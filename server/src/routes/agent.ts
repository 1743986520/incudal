/**
 * 宿主机 Agent 路由
 * 负责 Agent 凭据签发、HMAC 鉴权和心跳上报。
 */

import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { Prisma } from '@prisma/client'
import { createHash } from 'crypto'
import { readFileSync } from 'fs'
import { isIP } from 'net'
import { dirname, join } from 'path'
import { fileURLToPath } from 'url'
import { prisma } from '../db/prisma.js'
import * as db from '../db/index.js'
import { createLog, LogModule, LogResult } from '../db/logs.js'
import { decryptSensitiveData } from '../lib/security.js'
import {
  agentNonceTtlMs,
  createAgentBodyHash,
  isAgentTimestampFresh,
  isValidAgentSecret,
  readAgentAuthHeaders,
  validateAgentHeaders,
  verifyAgentSignature
} from '../lib/agent-auth.js'
import {
  consumeHostAgentInstallToken,
  issueHostAgentInstallToken,
  rotateHostAgentCredentials,
  type HostAgentRecord
} from '../lib/host-agent-credentials.js'
import { processAgentInstanceReport } from '../services/agent-instance-report.js'
import { sendSecurityIncidentNotification } from '../services/traffic-notifier.js'
import { buildHostAgentPolicyBundle } from '../services/host-network-policy.js'
import {
  BUILTIN_AUDIT_RULES, analyzeAuditData, parseConnections, parseProcesses, parseStartupItems,
  type AuditRuleDefinition, type AuditRuleMatchType, type AuditRuleTarget, type AuditSeverity
} from '../lib/instance-audit.js'
import { sendBanNotificationEmail } from '../lib/mailer.js'
import { clearAuthCache } from '../plugins/auth-decorators.js'
import { invalidateUserAccessTokens, revokeAllUserRefreshTokens } from '../lib/security.js'
import { closeUserSessions } from '../lib/terminal-proxy.js'

interface AgentCredentialsParams {
  hostId: string
}

interface AgentCredentialsBody {
  enabled?: boolean
}

interface AgentInstallCommandBody {
  enabled?: boolean
  baseUrl?: string
  binaryUrl?: string
}

interface AgentHeartbeatBody {
  version?: string
  capabilities?: string[]
  runtime?: Record<string, unknown>
  incus?: Record<string, unknown>
  instances?: Record<string, unknown>
  resources?: Record<string, unknown>
  metrics?: Record<string, unknown>
  securityEvents?: Array<Record<string, unknown>>
  auditSnapshots?: Array<Record<string, unknown>>
  networkPolicyStatus?: Record<string, unknown>
}

const securityIncidentDedupe = new Map<string, number>()

async function processAgentSecurityEvents(hostId: number, events: unknown, instancesReport: unknown): Promise<void> {
  if (!Array.isArray(events) || events.length === 0) return
  const host = await prisma.host.findUnique({ where: { id: hostId }, select: { name: true } })
  const now = Date.now()
  const instanceNameByMac = new Map<string, string>()
  if (instancesReport && typeof instancesReport === 'object') {
    const items = (instancesReport as { items?: unknown }).items
    if (Array.isArray(items)) {
      for (const rawItem of items) {
        if (!rawItem || typeof rawItem !== 'object') continue
        const item = rawItem as Record<string, unknown>
        const name = sanitizeShortString(item.name, 200)
        const network = item.network && typeof item.network === 'object' ? item.network as Record<string, unknown> : null
        const mac = sanitizeShortString(network?.mac, 32)?.toLowerCase()
        if (name && mac && /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(mac)) instanceNameByMac.set(mac, name)
      }
    }
  }
  for (const [key, expiresAt] of securityIncidentDedupe) {
    if (expiresAt <= now) securityIncidentDedupe.delete(key)
  }

  for (const raw of events.slice(0, 64)) {
    if (!raw || typeof raw !== 'object') continue
    const event = raw as Record<string, unknown>
    if (event.type !== 'single_target_pps_block') continue
    const sourceMac = sanitizeShortString(event.sourceMac, 32)
    const destinationIp = sanitizeShortString(event.destinationIp, 128)
    if (!sourceMac || !/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(sourceMac) || !destinationIp || isIP(destinationIp) === 0) continue
    const expiresInSeconds = Math.max(0, Math.min(86400, Number(event.expiresInSeconds) || 0))
    const dedupeKey = `${hostId}:${sourceMac.toLowerCase()}:${destinationIp}`
    if (securityIncidentDedupe.has(dedupeKey)) continue
    securityIncidentDedupe.set(dedupeKey, now + Math.max(60000, expiresInSeconds * 1000))

    const reportedName = instanceNameByMac.get(sourceMac.toLowerCase())
    const instance = reportedName ? await prisma.instance.findFirst({
      where: { hostId, incusId: reportedName, status: { not: 'deleted' } },
      include: { user: { select: { id: true, username: true, email: true, status: true, role: true } } }
    }) : null
    let suspensionResult = '未找到实例，未执行用户封禁'
    let emailResult = '未发送'

    if (instance) {
      const reason = `检测到实例 ${instance.name} 向 ${destinationIp} 的单目标发包超过 ${Math.max(1, Number(event.thresholdPps) || 10000).toLocaleString()} PPS，系统因滥用风险自动封禁账户。`
      if (instance.user.status !== 'banned' && instance.user.role !== 'admin') {
        await db.updateUserStatus(instance.userId, 'banned', reason)
        clearAuthCache(instance.userId)
        await revokeAllUserRefreshTokens(instance.userId)
        await invalidateUserAccessTokens(instance.userId)
        const closedSessions = closeUserSessions(instance.userId, 'User account automatically banned for PPS abuse')
        await createLog(instance.userId, LogModule.USER, 'user.security_auto_ban', `用户 ${instance.user.username} 因实例 ${instance.name} 的 PPS 安全事件被自动封禁；关闭 ${closedSessions} 个终端会话`, LogResult.SUCCESS)
        if (instance.user.email) {
          const mail = await sendBanNotificationEmail(instance.user.email, {
            username: instance.user.username,
            reason
          })
          emailResult = mail.success ? '邮件已发送' : `邮件发送失败：${mail.error || '未知错误'}`
        } else {
          emailResult = '用户未设置邮箱，未发送'
        }
        suspensionResult = `面板已封禁用户账户；已关闭 ${closedSessions} 个终端会话；实例流量规则已封锁异常目标`
      } else if (instance.user.role === 'admin') {
        suspensionResult = '目标属于管理员账户，安全规则拒绝自动封禁并已上报'
        emailResult = '未发送'
      } else {
        suspensionResult = '用户原本已被封禁，未重复处理'
        emailResult = '未重复发送'
      }
    }

    void sendSecurityIncidentNotification({
      hostName: host?.name || `Host ${hostId}`,
      hostId,
      sourceMac,
      destinationIp,
      family: event.family === 'ipv6' ? 'IPv6' : 'IPv4',
      thresholdPps: Math.max(1, Number(event.thresholdPps) || 10000),
      instanceLimitPps: Math.max(1, Number(event.instanceLimitPps) || 20000),
      expiresInSeconds,
      instanceName: instance?.name,
      username: instance?.user.username,
      userId: instance?.userId,
      suspensionResult,
      emailResult
    }).catch(error => console.error('[Agent] Failed to send PPS security notification:', error))
  }
}

interface AgentBinaryParams {
  name: string
}

interface AgentInstallTokenParams {
  token: string
}

interface AgentUpgradeManifestFile {
  name?: string
  sha256?: string
  size?: number
  gzip?: boolean
}

interface AgentUpgradeManifest {
  version?: string
  generatedAt?: string
  files?: Record<string, AgentUpgradeManifestFile>
}

interface GitHubReleaseAsset {
  name?: string
  size?: number
  url?: string
  browser_download_url?: string
}

interface GitHubRelease {
  tag_name?: string
  name?: string
  published_at?: string
  assets?: GitHubReleaseAsset[]
}

interface AgentUpgradeInstruction {
  available: boolean
  version?: string
  url?: string
  sha256?: string
  gzip?: boolean
  size?: number
}

const agentModel = prisma.hostAgent
const nonceModel = prisma.hostAgentNonce
const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)
const agentBinaryNamePattern = /^incudal-agent-linux-(amd64|arm64)(?:\.gz)?$/
const agentReleaseBinaryNamePattern = /^incudal-agent-(x86_64|aarch64)-v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/
const defaultAgentReleaseRepository = 'qwer-xyz/incudal_classic'
const githubApiBaseUrl = 'https://api.github.com'
const githubDownloadBaseUrl = 'https://github.com'
const agentReleaseCacheTtlMs = 5 * 60 * 1000
const agentBinaryDownloadLimitBytes = 64 * 1024 * 1024
const defaultAgentHeartbeatIntervalSeconds = 30
const minAgentHeartbeatIntervalSeconds = 5
const maxAgentHeartbeatIntervalSeconds = 3600
const minAgentOfflineThresholdSeconds = 120
let agentReleaseManifestCache: { expiresAt: number; manifest: AgentUpgradeManifest } | null = null
let agentReleaseAssetCache: { expiresAt: number; assets: Map<string, GitHubReleaseAsset> } | null = null
let agentReleaseBinaryCache: { expiresAt: number; binaries: Map<string, Buffer> } | null = null

function getLocalAgentDistPath(): string {
  return process.env.INCUDAL_AGENT_LOCAL_DIST?.trim() || join(__dirname, '../../../agent/dist')
}

function readLocalAgentManifest(): AgentUpgradeManifest | null {
  try {
    const distPath = getLocalAgentDistPath()
    const raw = JSON.parse(readFileSync(join(distPath, 'manifest.json'), 'utf8')) as AgentUpgradeManifest
    const version = sanitizeShortString(raw.version, 128)
    if (!version || !/^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/.test(version)) {
      return null
    }

    const manifest: AgentUpgradeManifest = {
      version,
      generatedAt: sanitizeShortString(raw.generatedAt, 80) ?? new Date().toISOString(),
      files: {}
    }
    const binaries = new Map<string, Buffer>()

    for (const platform of ['linux-amd64', 'linux-arm64'] as const) {
      const file = raw.files?.[platform]
      const name = sanitizeShortString(file?.name, 128)
      if (!name || !agentBinaryNamePattern.test(name) || !isSha256(file?.sha256)) {
        return null
      }
      const expectedName = `incudal-agent-${platform}`
      if (name !== expectedName && name !== `${expectedName}.gz`) {
        return null
      }

      const binary = readFileSync(join(distPath, name))
      if (binary.length === 0 || binary.length > agentBinaryDownloadLimitBytes) {
        return null
      }
      const actualSha256 = createHash('sha256').update(binary).digest('hex')
      if (actualSha256 !== file.sha256.toLowerCase()) {
        console.warn('[AgentRelease] Local Agent binary checksum mismatch', { name })
        return null
      }

      manifest.files![platform] = {
        name,
        sha256: actualSha256,
        size: binary.length,
        gzip: file?.gzip ?? name.endsWith('.gz')
      }
      binaries.set(`${version}:${name}:${actualSha256}`, binary)
    }

    agentReleaseBinaryCache = {
      expiresAt: Date.now() + agentReleaseCacheTtlMs,
      binaries
    }
    return manifest
  } catch (error) {
    console.warn('[AgentRelease] Local Agent release is unavailable', error)
    return null
  }
}

function parsePositiveId(value: string): number | null {
  const id = Number.parseInt(value, 10)
  return Number.isSafeInteger(id) && id > 0 ? id : null
}

function sanitizeShortString(value: unknown, maxLength: number): string | null {
  if (typeof value !== 'string') {
    return null
  }
  const trimmed = value.trim()
  return trimmed ? trimmed.slice(0, maxLength) : null
}

function normalizeCapabilities(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return []
  }

  const uniqueCapabilities = new Set<string>()
  for (const item of value) {
    const capability = sanitizeShortString(item, 80)
    if (capability) {
      uniqueCapabilities.add(capability)
    }
    if (uniqueCapabilities.size >= 64) {
      break
    }
  }
  return Array.from(uniqueCapabilities)
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function parseInteger(value: unknown): number | null {
  if (typeof value === 'number' && Number.isSafeInteger(value)) {
    return value
  }
  if (typeof value === 'string' && /^\d+$/.test(value.trim())) {
    const parsed = Number.parseInt(value.trim(), 10)
    return Number.isSafeInteger(parsed) ? parsed : null
  }
  return null
}

function clampAgentHeartbeatIntervalSeconds(value: unknown): number {
  const parsed = parseInteger(value)
  if (!parsed) {
    return defaultAgentHeartbeatIntervalSeconds
  }
  if (parsed < minAgentHeartbeatIntervalSeconds) {
    return minAgentHeartbeatIntervalSeconds
  }
  if (parsed > maxAgentHeartbeatIntervalSeconds) {
    return maxAgentHeartbeatIntervalSeconds
  }
  return parsed
}

function buildRequestPath(request: FastifyRequest): string {
  return request.url.split('?')[0] || request.url
}

function firstHeaderValue(value: string | string[] | undefined): string | null {
  if (Array.isArray(value)) {
    return value[0] ?? null
  }
  return value ?? null
}

function normalizeIpCandidate(value: unknown): string | null {
  if (typeof value !== 'string') {
    return null
  }

  let candidate = value.trim()
  if (!candidate) {
    return null
  }

  if (candidate.startsWith('[')) {
    const closingBracketIndex = candidate.indexOf(']')
    if (closingBracketIndex > 0) {
      candidate = candidate.slice(1, closingBracketIndex)
    }
  }

  const ipv4WithPort = candidate.match(/^(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?$/)
  if (ipv4WithPort) {
    candidate = ipv4WithPort[1]
  }

  if (candidate.startsWith('::ffff:')) {
    const mapped = candidate.slice(7)
    if (isIP(mapped)) {
      return mapped
    }
  }

  return isIP(candidate) ? candidate : null
}

function firstForwardedIp(request: FastifyRequest): string | null {
  const headerValues = [
    firstHeaderValue(request.headers['cf-connecting-ip']),
    firstHeaderValue(request.headers['true-client-ip']),
    firstHeaderValue(request.headers['x-real-ip']),
    firstHeaderValue(request.headers['x-forwarded-for'])
  ]

  for (const value of headerValues) {
    if (!value) {
      continue
    }
    for (const part of value.split(',')) {
      const ip = normalizeIpCandidate(part)
      if (ip) {
        return ip
      }
    }
  }

  return null
}

function isLocalOrPrivateIp(ip: string | null): boolean {
  if (!ip) {
    return false
  }

  if (ip === '::1' || ip === '127.0.0.1' || ip.startsWith('127.')) {
    return true
  }

  if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('169.254.')) {
    return true
  }

  const parts = ip.split('.').map((part) => Number.parseInt(part, 10))
  if (parts.length === 4 && parts.every((part) => Number.isInteger(part))) {
    return parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31
  }

  const lowerIp = ip.toLowerCase()
  return lowerIp.startsWith('fc') || lowerIp.startsWith('fd') || lowerIp.startsWith('fe80:')
}

function getAgentHeartbeatIp(request: FastifyRequest): string {
  const directIp = normalizeIpCandidate(request.ip) ?? request.ip
  const forwardedIp = firstForwardedIp(request)
  const trustForwardedIp = process.env.AGENT_TRUST_FORWARDED_IP === 'true' || isLocalOrPrivateIp(directIp)

  return forwardedIp && trustForwardedIp ? forwardedIp : directIp
}

function normalizeBaseUrl(value: string | null | undefined): string | null {
  const trimmed = value?.trim()
  if (!trimmed) {
    return null
  }

  try {
    const parsed = new URL(trimmed)
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return null
    }
    return `${parsed.protocol}//${parsed.host}`
  } catch {
    return null
  }
}

function derivePanelUrl(request: FastifyRequest, explicitBaseUrl?: string): string {
  const explicit = normalizeBaseUrl(explicitBaseUrl)
  if (explicit) {
    return explicit
  }

  const frontendUrl = normalizeBaseUrl(process.env.FRONTEND_URL?.split(',')[0])
  if (frontendUrl) {
    return frontendUrl
  }

  const refererBaseUrl = normalizeBaseUrl(firstHeaderValue(request.headers.origin) ?? firstHeaderValue(request.headers.referer))
  if (refererBaseUrl) {
    return refererBaseUrl
  }

  const forwardedProto = firstHeaderValue(request.headers['x-forwarded-proto'])?.split(',')[0]?.trim()
  const forwardedHost = firstHeaderValue(request.headers['x-forwarded-host'])?.split(',')[0]?.trim()
  const directHost = firstHeaderValue(request.headers.host)?.trim()
  const protocol = forwardedProto === 'https' || forwardedProto === 'http'
    ? forwardedProto
    : (request.protocol || 'http')
  const host = forwardedHost || directHost

  if (host) {
    return `${protocol}://${host}`
  }

  return 'https://incudal.com'
}

function shellEscape(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`
}

function buildAgentInstallCommand(input: {
  panelUrl: string
  installToken: string
  binaryUrl?: string | null
}): string {
  const envParts = [
    `INCUDAL_PANEL_URL=${shellEscape(input.panelUrl)}`,
    `INCUDAL_AGENT_INSTALL_TOKEN=${shellEscape(input.installToken)}`
  ]

  const binaryUrl = input.binaryUrl?.trim()
  if (binaryUrl) {
    envParts.push(`INCUDAL_AGENT_BINARY_URL=${shellEscape(binaryUrl)}`)
  }

  return `curl -fsSL ${shellEscape(`${input.panelUrl}/api/agent/install.sh`)} | sudo env ${envParts.join(' ')} bash`
}

function buildAgentInstallConfig(input: {
  agentId: string
  agentSecret: string
}): string {
  return [
    `INCUDAL_AGENT_ID=${shellEscape(input.agentId)}`,
    `INCUDAL_AGENT_SECRET=${shellEscape(input.agentSecret)}`
  ].join('\n') + '\n'
}

function getAgentReleaseRepository(): string {
  const configured = process.env.INCUDAL_AGENT_RELEASE_REPOSITORY?.trim() || process.env.GITHUB_REPOSITORY?.trim()
  const repository = configured || defaultAgentReleaseRepository
  return /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository) ? repository : defaultAgentReleaseRepository
}

function getAgentReleaseApiUrl(): string {
  return `${githubApiBaseUrl}/repos/${getAgentReleaseRepository()}/releases`
}

function getGitHubHeaders(accept: string): Record<string, string> {
  const headers: Record<string, string> = {
    Accept: accept,
    'User-Agent': 'incudal-panel'
  }
  const token = process.env.INCUDAL_AGENT_RELEASE_TOKEN?.trim()
  if (token) {
    headers.Authorization = `Bearer ${token}`
  }
  return headers
}

function getAgentReleaseAssetUrl(tag: string, assetName: string): string {
  const repository = getAgentReleaseRepository()
  return `${githubDownloadBaseUrl}/${repository}/releases/download/${encodeURIComponent(tag)}/${encodeURIComponent(assetName)}`
}

function normalizeAgentReleaseVersion(tagName: string | undefined): string | null {
  const tag = sanitizeShortString(tagName, 128)
  if (!tag?.startsWith('agent-')) {
    return null
  }
  const version = tag.slice('agent-'.length)
  return /^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/.test(version) ? version : null
}

function agentApiBinaryNameToReleaseAssetName(name: string, version: string): string | null {
  if (name === 'incudal-agent-linux-amd64') {
    return `incudal-agent-x86_64-${version}`
  }
  if (name === 'incudal-agent-linux-arm64') {
    return `incudal-agent-aarch64-${version}`
  }
  return null
}

function releaseAssetNameToAgentPlatform(name: string): 'linux-amd64' | 'linux-arm64' | null {
  if (name.startsWith('incudal-agent-x86_64-')) {
    return 'linux-amd64'
  }
  if (name.startsWith('incudal-agent-aarch64-')) {
    return 'linux-arm64'
  }
  return null
}

async function fetchJsonFromGitHub<T>(url: string): Promise<T> {
  const response = await fetch(url, {
    headers: getGitHubHeaders('application/vnd.github+json')
  })
  if (!response.ok) {
    throw new Error(`GitHub request failed: ${response.status} ${response.statusText}`)
  }
  return await response.json() as T
}

async function fetchLatestAgentRelease(): Promise<GitHubRelease | null> {
  const releases = await fetchJsonFromGitHub<unknown>(getAgentReleaseApiUrl())
  if (!Array.isArray(releases)) {
    return null
  }

  for (const release of releases) {
    if (!isRecord(release)) {
      continue
    }
    const version = normalizeAgentReleaseVersion(sanitizeShortString(release.tag_name, 128) ?? undefined)
    const assets = Array.isArray(release.assets) ? release.assets : []
    if (version && assets.length > 0) {
      return release as GitHubRelease
    }
  }
  return null
}

async function fetchAgentReleaseAssetSha256(asset: GitHubReleaseAsset): Promise<string | null> {
  const downloadUrl = sanitizeShortString(asset.url, 2048) ?? sanitizeShortString(asset.browser_download_url, 2048)
  if (!downloadUrl) {
    return null
  }

  const response = await fetch(downloadUrl, {
    headers: getGitHubHeaders('application/octet-stream')
  })
  if (!response.ok || !response.body) {
    throw new Error(`Agent release asset download failed: ${response.status} ${response.statusText}`)
  }

  const hash = createHash('sha256')
  let totalBytes = 0
  for await (const chunk of response.body) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
    totalBytes += buffer.length
    if (totalBytes > agentBinaryDownloadLimitBytes) {
      throw new Error('Agent release asset exceeds download limit')
    }
    hash.update(buffer)
  }
  return hash.digest('hex')
}

async function readAgentUpgradeManifest(): Promise<AgentUpgradeManifest | null> {
  if (agentReleaseManifestCache && agentReleaseManifestCache.expiresAt > Date.now()) {
    return agentReleaseManifestCache.manifest
  }

  const localManifest = readLocalAgentManifest()
  if (localManifest) {
    agentReleaseManifestCache = {
      expiresAt: Date.now() + agentReleaseCacheTtlMs,
      manifest: localManifest
    }
    return localManifest
  }

  let release: GitHubRelease | null = null
  try {
    release = await fetchLatestAgentRelease()
  } catch (error) {
    console.warn('[AgentRelease] Failed to fetch latest Agent release', error)
    return null
  }
  const version = normalizeAgentReleaseVersion(release?.tag_name)
  if (!release || !version || !Array.isArray(release.assets)) {
    return null
  }

  const manifest: AgentUpgradeManifest = {
    version,
    generatedAt: sanitizeShortString(release.published_at, 80) ?? new Date().toISOString(),
    files: {}
  }
  const assets = new Map<string, GitHubReleaseAsset>()

  for (const asset of release.assets) {
    if (!isRecord(asset)) {
      continue
    }
    const name = sanitizeShortString(asset.name, 256)
    const size = typeof asset.size === 'number' && Number.isFinite(asset.size) ? asset.size : undefined
    if (!name || !agentReleaseBinaryNamePattern.test(name) || !name.endsWith(`-${version}`)) {
      continue
    }
    const platform = releaseAssetNameToAgentPlatform(name)
    if (!platform) {
      continue
    }
    let sha256: string | null = null
    try {
      sha256 = await fetchAgentReleaseAssetSha256(asset as GitHubReleaseAsset)
    } catch (error) {
      console.warn('[AgentRelease] Failed to hash Agent release asset', { name, error })
      continue
    }
    if (!sha256) {
      continue
    }

    manifest.files![platform] = {
      name: platform === 'linux-amd64' ? 'incudal-agent-linux-amd64' : 'incudal-agent-linux-arm64',
      sha256,
      size,
      gzip: false
    }
    assets.set(name, asset as GitHubReleaseAsset)
  }

  if (!manifest.files?.['linux-amd64'] || !manifest.files?.['linux-arm64']) {
    return null
  }

  agentReleaseManifestCache = {
    expiresAt: Date.now() + agentReleaseCacheTtlMs,
    manifest
  }
  agentReleaseAssetCache = {
    expiresAt: Date.now() + agentReleaseCacheTtlMs,
    assets
  }

  return manifest
}

async function getAgentReleaseAsset(name: string, version: string): Promise<GitHubReleaseAsset | null> {
  const assetName = agentApiBinaryNameToReleaseAssetName(name, version)
  if (!assetName) {
    return null
  }

  if (!agentReleaseAssetCache || agentReleaseAssetCache.expiresAt <= Date.now() || !agentReleaseAssetCache.assets.has(assetName)) {
    await readAgentUpgradeManifest()
  }

  return agentReleaseAssetCache?.assets.get(assetName) ?? {
    name: assetName,
    browser_download_url: getAgentReleaseAssetUrl(`agent-${version}`, assetName)
  }
}

async function downloadAgentReleaseBinary(input: {
  name: string
  version: string
  expectedSha256: string
}): Promise<Buffer | null> {
  const cacheKey = `${input.version}:${input.name}:${input.expectedSha256.toLowerCase()}`
  const cachedBinary = agentReleaseBinaryCache?.expiresAt && agentReleaseBinaryCache.expiresAt > Date.now()
    ? agentReleaseBinaryCache.binaries.get(cacheKey)
    : null
  if (cachedBinary) {
    return cachedBinary
  }

  const asset = await getAgentReleaseAsset(input.name, input.version)
  const assetName = sanitizeShortString(asset?.name, 256)
  if (!assetName || !agentReleaseBinaryNamePattern.test(assetName)) {
    return null
  }

  const downloadUrl = sanitizeShortString(asset?.url, 2048) ?? getAgentReleaseAssetUrl(`agent-${input.version}`, assetName)
  const response = await fetch(downloadUrl, {
    headers: getGitHubHeaders('application/octet-stream')
  })
  if (!response.ok || !response.body) {
    throw new Error(`Agent release binary download failed: ${response.status} ${response.statusText}`)
  }

  const chunks: Buffer[] = []
  const hash = createHash('sha256')
  let totalBytes = 0
  for await (const chunk of response.body) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
    totalBytes += buffer.length
    if (totalBytes > agentBinaryDownloadLimitBytes) {
      throw new Error('Agent release binary exceeds download limit')
    }
    chunks.push(buffer)
    hash.update(buffer)
  }

  const actualSha256 = hash.digest('hex')
  if (!isSha256(input.expectedSha256) || actualSha256 !== input.expectedSha256.toLowerCase()) {
    throw new Error(`Agent release binary sha256 mismatch: expected=${input.expectedSha256} actual=${actualSha256}`)
  }

  const binary = Buffer.concat(chunks)
  if (!agentReleaseBinaryCache || agentReleaseBinaryCache.expiresAt <= Date.now()) {
    agentReleaseBinaryCache = {
      expiresAt: Date.now() + agentReleaseCacheTtlMs,
      binaries: new Map()
    }
  }
  agentReleaseBinaryCache.binaries.set(cacheKey, binary)
  return binary
}

async function getLatestAgentVersion(): Promise<string | null> {
  return sanitizeShortString((await readAgentUpgradeManifest())?.version, 128)
}

function getAgentVersionStatus(agentVersion: string | null, latestVersion: string | null): 'latest' | 'outdated' | 'unknown' {
  if (!agentVersion || !latestVersion) {
    return 'unknown'
  }
  return agentVersion === latestVersion ? 'latest' : 'outdated'
}

function isSha256(value: string | undefined): value is string {
  return typeof value === 'string' && /^[a-f0-9]{64}$/i.test(value)
}

async function buildAgentUpgradeInstruction(request: FastifyRequest, body: AgentHeartbeatBody, agent: HostAgentRecord): Promise<AgentUpgradeInstruction> {
  const manifest = await readAgentUpgradeManifest()
  const manifestVersion = sanitizeShortString(manifest?.version, 128)
  if (!manifest || !manifestVersion) {
    return { available: false }
  }

  const currentVersion = sanitizeShortString(body.version, 128)
  const requestedTarget = sanitizeShortString(agent.upgradeTargetVersion, 128)
  const hasPendingRequest = Boolean(agent.upgradeRequestedAt && requestedTarget === manifestVersion)
  const requestAlreadyDelivered = Boolean(
    hasPendingRequest && agent.lastSeenAt && agent.upgradeRequestedAt && agent.lastSeenAt >= agent.upgradeRequestedAt
  )
  if (requestAlreadyDelivered && currentVersion === manifestVersion) {
    await agentModel.update({
      where: { id: agent.id },
      data: { upgradeRequestedAt: null, upgradeTargetVersion: null, upgradeForce: false }
    })
    return { available: false, version: manifestVersion }
  }
  if (currentVersion === manifestVersion && !(hasPendingRequest && agent.upgradeForce)) {
    return { available: false, version: manifestVersion }
  }

  const runtimeInfo = body.runtime ?? {}
  const goos = sanitizeShortString(runtimeInfo.goos, 32)
  const goarch = sanitizeShortString(runtimeInfo.goarch, 32)
  if (goos !== 'linux' || (goarch !== 'amd64' && goarch !== 'arm64')) {
    return { available: false, version: manifestVersion }
  }

  const file = manifest.files?.[`${goos}-${goarch}`]
  const name = sanitizeShortString(file?.name, 128)
  if (!file || !name || !agentBinaryNamePattern.test(name) || !isSha256(file.sha256)) {
    return { available: false, version: manifestVersion }
  }

  const upgradeUrl = `${derivePanelUrl(request)}/api/agent/binary/${encodeURIComponent(name)}?v=${encodeURIComponent(manifestVersion)}&sha256=${encodeURIComponent(file.sha256)}`
  const instruction: AgentUpgradeInstruction = {
    available: true,
    version: manifestVersion,
    url: upgradeUrl,
    sha256: file.sha256,
    gzip: file.gzip ?? name.endsWith('.gz')
  }
  if (typeof file.size === 'number' && Number.isFinite(file.size) && file.size > 0) {
    instruction.size = file.size
  }
  return instruction
}

function normalizeAgentMetrics(metrics: Record<string, unknown> | undefined): Record<string, unknown> {
  return {
    ...(metrics ?? {}),
    heartbeatIntervalSeconds: clampAgentHeartbeatIntervalSeconds(metrics?.heartbeatIntervalSeconds)
  }
}

function getAgentHeartbeatIntervalSeconds(agent: HostAgentRecord): number {
  if (!isRecord(agent.lastReport)) {
    return defaultAgentHeartbeatIntervalSeconds
  }
  const metrics = agent.lastReport.metrics
  if (!isRecord(metrics)) {
    return defaultAgentHeartbeatIntervalSeconds
  }
  return clampAgentHeartbeatIntervalSeconds(metrics.heartbeatIntervalSeconds)
}

function deriveAgentStatus(agent: HostAgentRecord, now = new Date()): string {
  if (!agent.enabled || agent.status !== 'online') {
    return agent.status
  }
  if (!agent.lastSeenAt) {
    return 'offline'
  }

  const heartbeatIntervalSeconds = getAgentHeartbeatIntervalSeconds(agent)
  const offlineThresholdSeconds = Math.max(heartbeatIntervalSeconds * 3, minAgentOfflineThresholdSeconds)
  const lastSeenAgeMs = now.getTime() - agent.lastSeenAt.getTime()

  return lastSeenAgeMs > offlineThresholdSeconds * 1000 ? 'offline' : agent.status
}

async function serializeAgent(agent: HostAgentRecord) {
  const latestVersion = await getLatestAgentVersion()
  const versionStatus = getAgentVersionStatus(agent.version, latestVersion)

  return {
    id: agent.id,
    hostId: agent.hostId,
    agentId: agent.agentId,
    secretHash: agent.secretHash,
    enabled: agent.enabled,
    status: deriveAgentStatus(agent),
    version: agent.version,
    latestVersion,
    versionStatus,
    capabilities: agent.capabilities ?? [],
    lastReport: agent.lastReport ?? {},
    lastSeenAt: agent.lastSeenAt?.toISOString() ?? null,
    lastHeartbeatIp: agent.lastHeartbeatIp,
    createdAt: agent.createdAt.toISOString(),
    updatedAt: agent.updatedAt.toISOString()
  }
}

async function serializeAgentStatus(agent: HostAgentRecord) {
  const latestVersion = await getLatestAgentVersion()
  const versionStatus = getAgentVersionStatus(agent.version, latestVersion)

  return {
    id: agent.id,
    hostId: agent.hostId,
    agentId: agent.agentId,
    enabled: agent.enabled,
    status: deriveAgentStatus(agent),
    version: agent.version,
    latestVersion,
    versionStatus,
    capabilities: agent.capabilities ?? [],
    lastReport: agent.lastReport ?? {},
    lastSeenAt: agent.lastSeenAt?.toISOString() ?? null,
    lastHeartbeatIp: agent.lastHeartbeatIp,
    createdAt: agent.createdAt.toISOString(),
    updatedAt: agent.updatedAt.toISOString()
  }
}

function buildHeartbeatReport(body: AgentHeartbeatBody): Record<string, unknown> {
  return {
    runtime: body.runtime ?? {},
    incus: body.incus ?? {},
    resources: body.resources ?? {},
    metrics: normalizeAgentMetrics(body.metrics)
  }
}

async function authenticateAgentRequest(
  request: FastifyRequest<{ Body: AgentHeartbeatBody }>,
  reply: FastifyReply
): Promise<HostAgentRecord | null> {
  const headers = readAgentAuthHeaders(request.headers)
  if (!headers) {
    reply.code(401).send({ error: 'Agent authentication headers are required', code: 'AGENT_AUTH_REQUIRED' })
    return null
  }

  const headerError = validateAgentHeaders(headers)
  if (headerError) {
    reply.code(401).send({ error: 'Invalid Agent authentication headers', code: 'AGENT_AUTH_INVALID', details: headerError })
    return null
  }

  if (!isAgentTimestampFresh(headers.timestamp)) {
    reply.code(401).send({ error: 'Agent request timestamp is expired', code: 'AGENT_AUTH_EXPIRED' })
    return null
  }

  const bodyHash = createAgentBodyHash(request.body ?? {})
  if (bodyHash !== headers.bodyHash.toLowerCase()) {
    reply.code(401).send({ error: 'Agent body hash mismatch', code: 'AGENT_BODY_HASH_MISMATCH' })
    return null
  }

  const agent = await agentModel.findUnique({
    where: { agentId: headers.agentId }
  })

  if (!agent || !agent.enabled) {
    reply.code(401).send({ error: 'Agent is not enabled', code: 'AGENT_DISABLED' })
    return null
  }

  const secret = decryptSensitiveData(agent.secretEncrypted)
  if (!secret || !isValidAgentSecret(secret)) {
    reply.code(401).send({ error: 'Agent secret is not available', code: 'AGENT_SECRET_INVALID' })
    return null
  }

  const signatureOk = verifyAgentSignature(secret, {
    method: request.method,
    path: buildRequestPath(request),
    timestamp: headers.timestamp,
    nonce: headers.nonce,
    bodyHash
  }, headers.signature)

  if (!signatureOk) {
    reply.code(401).send({ error: 'Agent signature verification failed', code: 'AGENT_SIGNATURE_INVALID' })
    return null
  }

  try {
    await prisma.$transaction([
      nonceModel.deleteMany({
        where: {
          expiresAt: { lt: new Date() }
        }
      }),
      nonceModel.create({
        data: {
          agentId: agent.agentId,
          nonce: headers.nonce,
          expiresAt: new Date(Date.now() + agentNonceTtlMs)
        }
      })
    ])
  } catch (error) {
    if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
      reply.code(401).send({ error: 'Agent nonce was already used', code: 'AGENT_NONCE_REPLAY' })
      return null
    }
    throw error
  }

  return agent
}

export default async function agentRoutes(fastify: FastifyInstance) {
  fastify.get('/install.sh', async (_request: FastifyRequest, reply: FastifyReply) => {
    const scriptPath = join(__dirname, '../../templates/agent-install.sh')
    const script = readFileSync(scriptPath, 'utf8')
    return reply
      .header('Content-Type', 'text/x-shellscript; charset=utf-8')
      .header('Cache-Control', 'no-store')
      .send(script)
  })

  fastify.get('/manifest.json', async (_request: FastifyRequest, reply: FastifyReply) => {
    const manifest = await readAgentUpgradeManifest()
    if (!manifest) {
      return reply.code(404).send({ error: 'Agent manifest not found', code: 'AGENT_MANIFEST_NOT_FOUND' })
    }

    return reply
      .header('Content-Type', 'application/json; charset=utf-8')
      .header('Content-Disposition', 'attachment; filename="manifest.json"')
      .header('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate')
      .header('Pragma', 'no-cache')
      .header('Expires', '0')
      .send(manifest)
  })

  fastify.get<{ Params: AgentInstallTokenParams }>('/install-config/:token', async (
    request: FastifyRequest<{ Params: AgentInstallTokenParams }>,
    reply: FastifyReply
  ) => {
    const { token } = request.params
    try {
      const result = await consumeHostAgentInstallToken(token)
      request.log.info(
        { hostId: result.host.id, agentId: result.agent.agentId },
        'Host Agent install token consumed'
      )
      await createLog(
        null,
        LogModule.HOST,
        'host.agent_install_token_consume',
        `宿主机 Agent 一次性安装 token 已消费: ${result.host.name} (#${result.host.id})`,
        LogResult.SUCCESS
      )

      return reply
        .header('Content-Type', 'text/plain; charset=utf-8')
        .header('Cache-Control', 'no-store')
        .send(buildAgentInstallConfig({
          agentId: result.agent.agentId,
          agentSecret: result.agentSecret
        }))
    } catch (error) {
      if (error instanceof Error && error.message === 'AGENT_INSTALL_TOKEN_EXPIRED') {
        return reply.code(403).send('# Error: Agent install token has expired')
      }
      if (error instanceof Error && (
        error.message === 'AGENT_INSTALL_TOKEN_INVALID' ||
        error.message === 'AGENT_SECRET_INVALID'
      )) {
        return reply.code(403).send('# Error: Invalid Agent install token')
      }
      throw error
    }
  })

  fastify.get<{ Params: AgentBinaryParams }>('/binary/:name', async (
    request: FastifyRequest<{ Params: AgentBinaryParams }>,
    reply: FastifyReply
  ) => {
    const { name } = request.params
    if (!agentBinaryNamePattern.test(name)) {
      return reply.code(400).send({ error: 'Invalid Agent binary name', code: 'INVALID_AGENT_BINARY_NAME' })
    }

    const manifest = await readAgentUpgradeManifest()
    const version = sanitizeShortString(manifest?.version, 128)
    const platform = name.includes('amd64') ? 'linux-amd64' : 'linux-arm64'
    const file = manifest?.files?.[platform]
    if (!manifest || !version || !file || !isSha256(file.sha256)) {
      return reply.code(404).send({ error: 'Agent binary not found', code: 'AGENT_BINARY_NOT_FOUND' })
    }

    let binary: Buffer | null = null
    try {
      binary = await downloadAgentReleaseBinary({
        name,
        version,
        expectedSha256: file.sha256
      })
    } catch (error) {
      request.log.warn({ error, name, version }, 'Failed to download Agent release binary')
      return reply.code(502).send({ error: 'Agent binary download failed', code: 'AGENT_BINARY_DOWNLOAD_FAILED' })
    }

    if (!binary) {
      return reply.code(404).send({ error: 'Agent binary not found', code: 'AGENT_BINARY_NOT_FOUND' })
    }

    return reply
      .header('Content-Type', 'application/octet-stream')
      .header('Content-Disposition', `attachment; filename="${name}"`)
      .header('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate')
      .header('Pragma', 'no-cache')
      .header('Expires', '0')
      .send(binary)
  })

  fastify.get<{ Params: AgentCredentialsParams }>('/hosts/:hostId/status', {
    onRequest: [fastify.authenticate]
  }, async (request: FastifyRequest<{ Params: AgentCredentialsParams }>, reply: FastifyReply) => {
    const hostId = parsePositiveId(request.params.hostId)
    if (!hostId) {
      return reply.code(400).send({ error: 'Invalid host ID', code: 'INVALID_HOST_ID' })
    }

    const host = await prisma.host.findUnique({
      where: { id: hostId },
      select: { id: true, name: true, userId: true }
    })
    if (!host) {
      return reply.code(404).send({ error: 'Host not found', code: 'HOST_NOT_FOUND' })
    }

    if (host.userId !== request.user.id && request.user.role !== 'admin') {
      return reply.code(403).send({ error: 'Forbidden', code: 'FORBIDDEN' })
    }

    const agent = await agentModel.findUnique({
      where: { hostId }
    })

    return {
      host: {
        id: host.id,
        name: host.name
      },
      agent: agent ? await serializeAgentStatus(agent) : null
    }
  })

  fastify.post<{ Params: AgentCredentialsParams }>('/hosts/:hostId/upgrade', {
    onRequest: [fastify.authenticate]
  }, async (request: FastifyRequest<{ Params: AgentCredentialsParams }>, reply: FastifyReply) => {
    const hostId = parsePositiveId(request.params.hostId)
    if (!hostId) {
      return reply.code(400).send({ error: 'Invalid host ID', code: 'INVALID_HOST_ID' })
    }

    const host = await prisma.host.findUnique({
      where: { id: hostId },
      select: { id: true, name: true, userId: true }
    })
    if (!host) {
      return reply.code(404).send({ error: 'Host not found', code: 'HOST_NOT_FOUND' })
    }

    if (host.userId !== request.user.id && request.user.role !== 'admin') {
      return reply.code(403).send({ error: 'Forbidden', code: 'FORBIDDEN' })
    }

    const agent = await agentModel.findUnique({
      where: { hostId }
    })
    if (!agent) {
      return reply.code(404).send({ error: 'Agent not found', code: 'AGENT_NOT_FOUND' })
    }

    const latestVersion = await getLatestAgentVersion()
    const versionStatus = getAgentVersionStatus(agent.version, latestVersion)
    const derivedStatus = deriveAgentStatus(agent)

    if (!latestVersion) {
      return reply.code(503).send({ error: 'Agent latest version unavailable', code: 'AGENT_LATEST_VERSION_UNAVAILABLE' })
    }
    if (versionStatus === 'unknown') {
      return reply.code(409).send({ error: 'Agent version unknown', code: 'AGENT_VERSION_UNKNOWN' })
    }
    if (versionStatus === 'latest') {
      return {
        requested: false,
        currentVersion: agent.version,
        latestVersion,
        versionStatus,
        nextHeartbeatSeconds: getAgentHeartbeatIntervalSeconds(agent),
        message: 'Agent is already latest'
      }
    }
    if (!agent.enabled || derivedStatus !== 'online') {
      return reply.code(409).send({ error: 'Agent is not online', code: 'AGENT_NOT_ONLINE' })
    }

    const nextHeartbeatSeconds = getAgentHeartbeatIntervalSeconds(agent)
    await agentModel.update({
      where: { id: agent.id },
      data: { upgradeRequestedAt: new Date(), upgradeTargetVersion: latestVersion, upgradeForce: true }
    })
    await createLog(
      request.user.id,
      LogModule.HOST,
      'host.agent_upgrade_request',
      `请求宿主机 Agent 升级: ${host.name} (#${host.id}) ${agent.version || 'unknown'} -> ${latestVersion}`,
      LogResult.SUCCESS
    )

    return {
      requested: true,
      currentVersion: agent.version,
      latestVersion,
      versionStatus,
      nextHeartbeatSeconds,
      message: 'Agent upgrade request accepted; upgrade instruction will be delivered on next heartbeat'
    }
  })

  fastify.post('/upgrade-all', {
    onRequest: [fastify.authenticateAdmin]
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const latestVersion = await getLatestAgentVersion()
    if (!latestVersion) {
      return reply.code(503).send({ error: 'Agent latest version unavailable', code: 'AGENT_LATEST_VERSION_UNAVAILABLE' })
    }
    const agents = await agentModel.findMany({
      where: { enabled: true },
      select: { id: true, status: true, version: true }
    })
    const now = new Date()
    await agentModel.updateMany({
      where: { id: { in: agents.map(agent => agent.id) } },
      data: { upgradeRequestedAt: now, upgradeTargetVersion: latestVersion, upgradeForce: true }
    })
    const online = agents.filter(agent => agent.status === 'online').length
    const offline = agents.length - online
    const alreadyLatest = agents.filter(agent => agent.version === latestVersion).length
    await createLog(
      request.user.id,
      LogModule.HOST,
      'host.agent_force_upgrade_all',
      `强制更新全部 Agent 到 ${latestVersion}: 总计 ${agents.length}，在线 ${online}，离线待执行 ${offline}`,
      LogResult.SUCCESS
    )
    return { requested: agents.length, online, pendingOffline: offline, alreadyLatest, latestVersion }
  })

  fastify.post<{ Params: AgentCredentialsParams; Body: AgentCredentialsBody }>('/hosts/:hostId/install-command', {
    onRequest: [fastify.authenticate],
    schema: {
      body: {
        type: 'object',
        additionalProperties: false,
        properties: {
          enabled: { type: 'boolean' }
        }
      }
    }
  }, async (
    request: FastifyRequest<{ Params: AgentCredentialsParams; Body: AgentCredentialsBody }>,
    reply: FastifyReply
  ) => {
    const hostId = parsePositiveId(request.params.hostId)
    if (!hostId) {
      return reply.code(400).send({ error: 'Invalid host ID', code: 'INVALID_HOST_ID' })
    }

    const host = await prisma.host.findUnique({
      where: { id: hostId },
      select: { id: true, name: true, userId: true }
    })
    if (!host) {
      return reply.code(404).send({ error: 'Host not found', code: 'HOST_NOT_FOUND' })
    }

    if (host.userId !== request.user.id && request.user.role !== 'admin') {
      return reply.code(403).send({ error: 'Forbidden', code: 'FORBIDDEN' })
    }

    const panelUrl = derivePanelUrl(request)
    let result: Awaited<ReturnType<typeof issueHostAgentInstallToken>>
    try {
      result = await issueHostAgentInstallToken(hostId, request.body?.enabled ?? true)
    } catch (error) {
      if (error instanceof Error && error.message === 'HOST_NOT_FOUND') {
        return reply.code(404).send({ error: 'Host not found', code: 'HOST_NOT_FOUND' })
      }
      throw error
    }
    const installCommand = buildAgentInstallCommand({
      panelUrl,
      installToken: result.installToken
    })

    await createLog(
      request.user.id,
      LogModule.HOST,
      'host.agent_install_command_generate',
      `生成宿主机 Agent 安装命令: ${host.name} (#${host.id})`,
      LogResult.SUCCESS
    )

    return reply.code(201).send({
      host: result.host,
      agent: await serializeAgentStatus(result.agent),
      installToken: result.installToken,
      installTokenExpiresAt: result.installTokenExpiresAt.toISOString(),
      installScriptUrl: `${panelUrl}/api/agent/install.sh`,
      installCommand,
      warning: 'installCommand 内包含一次性 Agent 安装 token，30 分钟内有效且只能使用一次。'
    })
  })

  fastify.get<{ Params: AgentCredentialsParams }>('/admin/hosts/:hostId/status', {
    onRequest: [fastify.authenticateAdmin]
  }, async (request: FastifyRequest<{ Params: AgentCredentialsParams }>, reply: FastifyReply) => {
    const hostId = parsePositiveId(request.params.hostId)
    if (!hostId) {
      return reply.code(400).send({ error: 'Invalid host ID', code: 'INVALID_HOST_ID' })
    }

    const host = await prisma.host.findUnique({
      where: { id: hostId },
      select: { id: true, name: true }
    })
    if (!host) {
      return reply.code(404).send({ error: 'Host not found', code: 'HOST_NOT_FOUND' })
    }

    const agent = await agentModel.findUnique({
      where: { hostId }
    })

    return {
      host,
      agent: agent ? await serializeAgent(agent) : null
    }
  })

  fastify.post<{ Params: AgentCredentialsParams; Body: AgentCredentialsBody }>('/admin/hosts/:hostId/credentials', {
    onRequest: [fastify.authenticateAdmin],
    schema: {
      body: {
        type: 'object',
        additionalProperties: false,
        properties: {
          enabled: { type: 'boolean' }
        }
      }
    }
  }, async (
    request: FastifyRequest<{ Params: AgentCredentialsParams; Body: AgentCredentialsBody }>,
    reply: FastifyReply
  ) => {
    const hostId = parsePositiveId(request.params.hostId)
    if (!hostId) {
      return reply.code(400).send({ error: 'Invalid host ID', code: 'INVALID_HOST_ID' })
    }

    let result: Awaited<ReturnType<typeof rotateHostAgentCredentials>>
    try {
      result = await rotateHostAgentCredentials(hostId, request.body?.enabled ?? true)
    } catch (error) {
      if (error instanceof Error && error.message === 'HOST_NOT_FOUND') {
        return reply.code(404).send({ error: 'Host not found', code: 'HOST_NOT_FOUND' })
      }
      throw error
    }

    await createLog(
      request.user.id,
      LogModule.HOST,
      'host.agent_credentials_rotate',
      `重置宿主机 Agent 凭据: ${result.host.name} (#${result.host.id})`,
      LogResult.SUCCESS
    )

    return reply.code(201).send({
      host: result.host,
      agent: await serializeAgent(result.agent),
      credentials: {
        agentId: result.agentId,
        agentSecret: result.agentSecret
      },
      warning: 'agentSecret 只会在本次响应中返回，请写入宿主机 Agent 配置后妥善保存。'
    })
  })

  fastify.post<{ Params: AgentCredentialsParams; Body: AgentInstallCommandBody }>('/admin/hosts/:hostId/install-command', {
    onRequest: [fastify.authenticateAdmin],
    schema: {
      body: {
        type: 'object',
        additionalProperties: false,
        properties: {
          enabled: { type: 'boolean' },
          baseUrl: { type: 'string', minLength: 1 },
          binaryUrl: { type: 'string', minLength: 1 }
        }
      }
    }
  }, async (
    request: FastifyRequest<{ Params: AgentCredentialsParams; Body: AgentInstallCommandBody }>,
    reply: FastifyReply
  ) => {
    const hostId = parsePositiveId(request.params.hostId)
    if (!hostId) {
      return reply.code(400).send({ error: 'Invalid host ID', code: 'INVALID_HOST_ID' })
    }

    const panelUrl = derivePanelUrl(request, request.body?.baseUrl)
    let result: Awaited<ReturnType<typeof issueHostAgentInstallToken>>
    try {
      result = await issueHostAgentInstallToken(hostId, request.body?.enabled ?? true)
    } catch (error) {
      if (error instanceof Error && error.message === 'HOST_NOT_FOUND') {
        return reply.code(404).send({ error: 'Host not found', code: 'HOST_NOT_FOUND' })
      }
      throw error
    }

    const installCommand = buildAgentInstallCommand({
      panelUrl,
      installToken: result.installToken,
      binaryUrl: request.body?.binaryUrl
    })

    await createLog(
      request.user.id,
      LogModule.HOST,
      'host.agent_install_command_generate',
      `生成宿主机 Agent 安装命令: ${result.host.name} (#${result.host.id})`,
      LogResult.SUCCESS
    )

    return reply.code(201).send({
      host: result.host,
      agent: await serializeAgent(result.agent),
      installToken: result.installToken,
      installTokenExpiresAt: result.installTokenExpiresAt.toISOString(),
      installScriptUrl: `${panelUrl}/api/agent/install.sh`,
      installCommand,
      warning: 'installCommand 内包含一次性 Agent 安装 token，30 分钟内有效且只能使用一次。'
    })
  })

  fastify.post<{ Body: AgentHeartbeatBody }>('/heartbeat', {
    schema: {
      body: {
        type: 'object',
        additionalProperties: true,
        properties: {
          version: { type: 'string', maxLength: 128 },
          capabilities: {
            type: 'array',
            maxItems: 64,
            items: { type: 'string', maxLength: 80 }
          },
          runtime: { type: 'object', additionalProperties: true },
          incus: { type: 'object', additionalProperties: true },
          instances: { type: 'object', additionalProperties: true },
          resources: { type: 'object', additionalProperties: true },
          metrics: { type: 'object', additionalProperties: true }
          ,securityEvents: {
            type: 'array',
            maxItems: 64,
            items: { type: 'object', additionalProperties: true }
          }
        }
      }
    }
  }, async (request: FastifyRequest<{ Body: AgentHeartbeatBody }>, reply: FastifyReply) => {
    const agent = await authenticateAgentRequest(request, reply)
    if (!agent) {
      return
    }

    const now = new Date()
    let instanceReport: Awaited<ReturnType<typeof processAgentInstanceReport>> | null = null
    try {
      instanceReport = await processAgentInstanceReport(agent.hostId, request.body.instances)
    } catch (error) {
      request.log.warn(
        { agentId: agent.agentId, hostId: agent.hostId, error },
        'Failed to process Agent instance report'
      )
    }

    try {
      await processAgentSecurityEvents(agent.hostId, request.body.securityEvents, request.body.instances)
    } catch (error) {
      request.log.warn({ agentId: agent.agentId, hostId: agent.hostId, error }, 'Failed to process Agent security events')
    }

    if (request.body.networkPolicyStatus && typeof request.body.networkPolicyStatus === 'object') {
      const statusRevision = sanitizeShortString(request.body.networkPolicyStatus.revision, 128)
      const applied = request.body.networkPolicyStatus.applied === true
      const applyError = sanitizeShortString(request.body.networkPolicyStatus.error, 2000)
      const policyBundle = await buildHostAgentPolicyBundle(agent.hostId)
      if (statusRevision && statusRevision === policyBundle.revision) {
        await prisma.hostNetworkPolicy.updateMany({
          where: { hostId: agent.hostId, enabled: true },
          data: { applyStatus: applied ? 'applied' : 'failed', applyError: applied ? null : applyError, appliedAt: applied ? now : null }
        })
      }
    }

    if (Array.isArray(request.body.auditSnapshots)) {
      const hostOwner = await prisma.host.findUnique({ where: { id: agent.hostId }, select: { userId: true } })
      if (!hostOwner) throw new Error('Agent host not found')
      for (const rawSnapshot of request.body.auditSnapshots.slice(0, 32)) {
        const incusId = sanitizeShortString(rawSnapshot?.incusId, 200)
        if (!incusId) continue
        const instance = await prisma.instance.findFirst({ where: { hostId: agent.hostId, incusId }, select: { id: true } })
        if (!instance) continue
        const processes = parseProcesses(sanitizeShortString(rawSnapshot.processOutput, 131072) || '')
        const connections = parseConnections(sanitizeShortString(rawSnapshot.connectionOutput, 131072) || '')
        const startupItems = parseStartupItems(sanitizeShortString(rawSnapshot.startupOutput, 131072) || '')
        const [customRules, overrides, ignores] = await Promise.all([
          prisma.instanceAuditRule.findMany({ where: { enabled: true, OR: [{ hostId: null }, { hostId: agent.hostId }] } }),
          prisma.instanceAuditBuiltinRuleOverride.findMany({ where: { hostId: agent.hostId } }),
          prisma.instanceAuditIgnore.findMany({ where: { hostId: agent.hostId, enabled: true, OR: [{ instanceId: null }, { instanceId: instance.id }] } })
        ])
        const overrideMap = new Map(overrides.map(item => [item.builtinRuleId, item]))
        const normalizeSeverity = (value: string): AuditSeverity => ['info', 'low', 'medium', 'high'].includes(value) ? value as AuditSeverity : 'medium'
        const normalizeMatch = (value: string): AuditRuleMatchType => ['contains', 'regex', 'exact'].includes(value) ? value as AuditRuleMatchType : 'contains'
        const normalizeTargets = (value: unknown): AuditRuleTarget[] => Array.isArray(value) ? value.filter((item): item is AuditRuleTarget => ['process', 'network', 'startup'].includes(String(item))) : []
        const builtinRules: AuditRuleDefinition[] = BUILTIN_AUDIT_RULES.map(rule => {
          const override = overrideMap.get(rule.id)
          return override ? { ...rule, name: override.name, severity: normalizeSeverity(override.severity), category: override.category, targetTypes: normalizeTargets(override.targetTypes), matchType: normalizeMatch(override.matchType), patternText: override.pattern, caseSensitive: override.caseSensitive, enabled: override.enabled, recommendation: override.recommendation } : rule
        }).filter(rule => rule.enabled)
        const rules: AuditRuleDefinition[] = [...builtinRules, ...customRules.map(rule => ({
          id: `custom:${rule.id}`, name: rule.name, description: rule.description, severity: normalizeSeverity(rule.severity),
          category: rule.category, targetTypes: normalizeTargets(rule.targetTypes), matchType: normalizeMatch(rule.matchType),
          patternText: rule.pattern, caseSensitive: rule.caseSensitive, source: 'custom' as const, enabled: rule.enabled, recommendation: rule.recommendation
        }))]
        const analysis = analyzeAuditData({ processes, connections, startupItems, rules, ignores: ignores.map(ignore => ({ id: ignore.id, ruleId: ignore.ruleId, targetType: ignore.targetType as any, matchText: ignore.matchText, reason: ignore.reason, expiresAt: ignore.expiresAt })) })
        await prisma.instanceAuditScan.create({ data: {
          hostId: agent.hostId, instanceId: instance.id, userId: hostOwner.userId,
          status: rawSnapshot.success === false ? 'failed' : 'success', capability: sanitizeShortString(rawSnapshot.capability, 80) || 'agent',
          riskLevel: analysis.summary.riskLevel, findingCount: analysis.summary.findingCount,
          ignoredCount: analysis.findings.filter(item => item.ignored).length, processCount: analysis.summary.processCount,
          connectionCount: analysis.summary.connectionCount, listeningCount: analysis.summary.listeningCount,
          startupItemCount: analysis.summary.startupItemCount, findings: analysis.findings.slice(0, 80) as any,
          error: sanitizeShortString(rawSnapshot.error, 2000)
        } })
      }
    }

    await agentModel.update({
      where: { agentId: agent.agentId },
      data: {
        status: 'online',
        version: sanitizeShortString(request.body.version, 128),
        capabilities: normalizeCapabilities(request.body.capabilities) as Prisma.InputJsonValue,
        lastReport: buildHeartbeatReport(request.body) as Prisma.InputJsonObject,
        lastSeenAt: now,
        lastHeartbeatIp: sanitizeShortString(getAgentHeartbeatIp(request), 128)
      }
    })

    const auditConfig = await prisma.hostAgentAuditConfig.findUnique({ where: { hostId: agent.hostId } })
    return {
      ok: true,
      serverTime: now.toISOString(),
      taskPollIntervalSeconds: 15,
      instanceReport,
      upgrade: await buildAgentUpgradeInstruction(request, request.body, agent),
      monitoring: {
        enabled: auditConfig?.enabled === true,
        force: Boolean(auditConfig?.lastRequestedAt && (!agent.lastSeenAt || auditConfig.lastRequestedAt > agent.lastSeenAt)),
        intervalSeconds: auditConfig?.intervalSeconds || 300,
        batchSize: auditConfig?.batchSize || 8
      },
      networkPolicies: await buildHostAgentPolicyBundle(agent.hostId)
    }
  })
}
