/**
 * 管理员控制面板更新
 *
 * 更新不会在后台自动执行。管理员必须先检查来源，再在页面上明确确认并发起更新。
 */

import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { spawn, type ChildProcess } from 'child_process'
import { randomUUID } from 'crypto'
import { existsSync, readFileSync } from 'fs'
import { join } from 'path'
import { createLog } from '../db/logs.js'
import { logAdminAction } from '../lib/security.js'
import {
  DEFAULT_GITHUB_REPOSITORY,
  buildManualCommand,
  getAllowedRepositories,
  getPinnedUpdate,
  isAllowedRepository,
  normalizeGitHubRepository
} from '../lib/system-update-security.js'

type UpdateMode = 'auto' | 'docker' | 'release'
type UpdateExecutionStatus = 'idle' | 'running' | 'succeeded' | 'failed'

interface UpdateRequestBody {
  source?: string
  mode?: UpdateMode
  confirm?: boolean
}

interface UpdateQuery {
  source?: string
}

interface GitHubReleasePayload {
  tag_name?: unknown
  name?: unknown
  html_url?: unknown
  published_at?: unknown
  body?: unknown
}

interface UpdateRelease {
  version: string
  name: string
  url: string
  publishedAt: string | null
  notes: string
}

interface UpdateExecution {
  id: string
  status: UpdateExecutionStatus
  sourceRepository: string
  mode: UpdateMode
  startedAt: string
  finishedAt: string | null
  exitCode: number | null
  signal: string | null
  output: string
  error: string | null
}

const GITHUB_API_BASE_URL = 'https://api.github.com'
const MAX_OUTPUT_CHARS = 16000
let activeUpdateProcess: ChildProcess | null = null
let lastUpdate: UpdateExecution | null = null

function getDefaultRepository(): string {
  return getAllowedRepositories()[0] || DEFAULT_GITHUB_REPOSITORY
}

function getCurrentVersion(): string {
  const configured = process.env.INCUDAL_VERSION?.trim()
  if (configured) return configured.startsWith('v') ? configured : `v${configured}`

  try {
    const packagePath = join(process.cwd(), 'package.json')
    const packageJson = JSON.parse(readFileSync(packagePath, 'utf8')) as { version?: unknown }
    if (typeof packageJson.version === 'string' && packageJson.version.trim()) {
      return packageJson.version.trim().startsWith('v') ? packageJson.version.trim() : `v${packageJson.version.trim()}`
    }
  } catch {
    // 发行包或容器中无法读取 package.json 时返回 unknown，由页面显示人工确认。
  }
  return 'unknown'
}

function normalizeReleaseVersion(value: unknown): string | null {
  if (typeof value !== 'string') return null
  const version = value.trim()
  return /^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version) ? version : null
}

function compareVersions(left: string, right: string): number | null {
  const leftMatch = left.match(/^v(\d+)\.(\d+)\.(\d+)/)
  const rightMatch = right.match(/^v(\d+)\.(\d+)\.(\d+)/)
  if (!leftMatch || !rightMatch) return null
  for (let index = 1; index <= 3; index += 1) {
    const difference = Number(leftMatch[index]) - Number(rightMatch[index])
    if (difference !== 0) return difference
  }
  return 0
}

function getSourceUrls(repository: string): { repositoryUrl: string } {
  return { repositoryUrl: `https://github.com/${repository}` }
}

async function fetchLatestRelease(repository: string): Promise<UpdateRelease> {
  const token = process.env.INCUDAL_AGENT_RELEASE_TOKEN?.trim()
  const headers: Record<string, string> = {
    Accept: 'application/vnd.github+json',
    'User-Agent': 'Incudal-System-Update'
  }
  if (token) headers.Authorization = `Bearer ${token}`

  const response = await fetch(`${GITHUB_API_BASE_URL}/repos/${repository}/releases/latest`, {
    headers,
    signal: AbortSignal.timeout(15000)
  })
  if (!response.ok) {
    throw new Error(`GitHub Release 查询失败（HTTP ${response.status}）`)
  }

  const payload = await response.json() as GitHubReleasePayload
  const version = normalizeReleaseVersion(payload.tag_name)
  if (!version) throw new Error('GitHub Release 未返回有效版本号')

  const notes = typeof payload.body === 'string' ? payload.body.slice(0, 6000) : ''
  return {
    version,
    name: typeof payload.name === 'string' && payload.name.trim() ? payload.name.trim() : version,
    url: typeof payload.html_url === 'string' ? payload.html_url : `https://github.com/${repository}/releases/tag/${version}`,
    publishedAt: typeof payload.published_at === 'string' ? payload.published_at : null,
    notes
  }
}

function appendOutput(execution: UpdateExecution, chunk: Buffer | string): void {
  const value = String(chunk)
  execution.output = `${execution.output}${value}`.slice(-MAX_OUTPUT_CHARS)
}

function getInstallDirectory(): string {
  return process.env.INCUDAL_INSTALL_DIR?.trim() || '/opt/incudal'
}

function getUpdateExecutor(): { command: string; prefixArgs: string[]; label: string } | null {
  const uid = typeof process.getuid === 'function' ? process.getuid() : 0
  const configuredCommand = process.env.INCUDAL_WEB_UPDATE_COMMAND?.trim()
  if (configuredCommand) {
    if (!configuredCommand.startsWith('/') || /\s/.test(configuredCommand)) return null
    if (!existsSync(configuredCommand)) return null
    if (uid === 0) return { command: configuredCommand, prefixArgs: [], label: configuredCommand }
    if (existsSync('/usr/bin/sudo')) {
      return { command: '/usr/bin/sudo', prefixArgs: ['-n', configuredCommand], label: `sudo ${configuredCommand}` }
    }
    return null
  }

  const helperPath = '/usr/local/sbin/incudal-web-update'
  if (existsSync(helperPath)) {
    if (uid === 0) return { command: helperPath, prefixArgs: [], label: helperPath }
    if (existsSync('/usr/bin/sudo')) {
      return { command: '/usr/bin/sudo', prefixArgs: ['-n', helperPath], label: `sudo ${helperPath}` }
    }
  }

  return null
}

function currentExecution(): UpdateExecution | null {
  return lastUpdate ? { ...lastUpdate } : null
}

export default async function systemUpdateRoutes(fastify: FastifyInstance) {
  fastify.get<{ Querystring: UpdateQuery }>('/status', {
    onRequest: [fastify.authenticateAdmin]
  }, async (request: FastifyRequest<{ Querystring: UpdateQuery }>) => {
    const requestedSource = request.query.source?.trim()
    const sourceRepository = requestedSource ? normalizeGitHubRepository(requestedSource) : getDefaultRepository()
    return {
      currentVersion: getCurrentVersion(),
      sourceRepository: sourceRepository || getDefaultRepository(),
      sourceUrl: sourceRepository ? getSourceUrls(sourceRepository).repositoryUrl : getSourceUrls(getDefaultRepository()).repositoryUrl,
      execution: currentExecution(),
      executorAvailable: Boolean(getUpdateExecutor()),
      installDirectory: getInstallDirectory()
    }
  })

  fastify.post<{ Body: { source?: string } }>('/check', {
    onRequest: [fastify.authenticateAdmin],
    config: { rateLimit: { max: 20, timeWindow: '1 minute' } }
  }, async (request: FastifyRequest<{ Body: { source?: string } }>, reply: FastifyReply) => {
    const body = request.body || {}
    const sourceRepository = body.source ? normalizeGitHubRepository(body.source) : getDefaultRepository()
    if (!sourceRepository) {
      return reply.code(400).send({ error: '仅支持 HTTPS GitHub 仓库地址或 owner/repo', code: 'UPDATE_SOURCE_INVALID' })
    }
    if (!isAllowedRepository(sourceRepository)) {
      return reply.code(403).send({ error: '更新来源不在服务器配置的白名单中', code: 'UPDATE_SOURCE_NOT_ALLOWED' })
    }

    try {
      const latest = await fetchLatestRelease(sourceRepository)
      const currentVersion = getCurrentVersion()
      const comparison = compareVersions(latest.version, currentVersion)
      return {
        currentVersion,
        sourceRepository,
        sourceUrl: getSourceUrls(sourceRepository).repositoryUrl,
        latest,
        updateAvailable: comparison === null ? true : comparison > 0
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : '无法查询远程版本'
      return reply.code(502).send({ error: message, code: 'UPDATE_CHECK_FAILED' })
    }
  })

  fastify.post<{ Body: UpdateRequestBody }>('/apply', {
    onRequest: [fastify.authenticateAdmin],
    config: { rateLimit: { max: 2, timeWindow: '10 minutes' } }
  }, async (request: FastifyRequest<{ Body: UpdateRequestBody }>, reply: FastifyReply) => {
    const body = request.body || {}
    if (body.confirm !== true) {
      return reply.code(400).send({ error: '必须在页面明确确认后才能更新', code: 'UPDATE_CONFIRMATION_REQUIRED' })
    }
    if (activeUpdateProcess) {
      return reply.code(409).send({ error: '已有更新正在执行', code: 'UPDATE_IN_PROGRESS', execution: currentExecution() })
    }

    const sourceRepository = body.source ? normalizeGitHubRepository(body.source) : getDefaultRepository()
    if (!sourceRepository) {
      return reply.code(400).send({ error: '仅支持 HTTPS GitHub 仓库地址或 owner/repo', code: 'UPDATE_SOURCE_INVALID' })
    }
    if (!isAllowedRepository(sourceRepository)) {
      return reply.code(403).send({ error: '更新来源不在服务器配置的白名单中', code: 'UPDATE_SOURCE_NOT_ALLOWED' })
    }
    const mode: UpdateMode = body.mode || 'auto'
    if (!['auto', 'docker', 'release'].includes(mode)) {
      return reply.code(400).send({ error: '更新模式必须是 auto、docker 或 release', code: 'UPDATE_MODE_INVALID' })
    }
    const pinnedUpdate = getPinnedUpdate()
    if (!pinnedUpdate) {
      return reply.code(409).send({
        error: '站点更新未配置固定 commit 与脚本 SHA256，请按手工更新提示完成配置',
        code: 'UPDATE_TRUST_CONFIG_REQUIRED',
        command: buildManualCommand(sourceRepository, mode)
      })
    }

    const executor = getUpdateExecutor()
    if (!executor) {
      return reply.code(409).send({
        error: '当前服务没有可用的站点更新执行器，请复制命令到服务器终端执行',
        code: 'UPDATE_EXECUTOR_UNAVAILABLE',
        command: buildManualCommand(sourceRepository, mode)
      })
    }

    const execution: UpdateExecution = {
      id: randomUUID(),
      status: 'running',
      sourceRepository,
      mode,
      startedAt: new Date().toISOString(),
      finishedAt: null,
      exitCode: null,
      signal: null,
      output: '',
      error: null
    }
    lastUpdate = execution

    const args = [...executor.prefixArgs, '--source', `https://github.com/${sourceRepository}`, '--ref', pinnedUpdate.ref, '--script-sha256', pinnedUpdate.scriptSHA256, '--mode', mode]
    const child = spawn(executor.command, args, {
      cwd: process.cwd(),
      detached: true,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: {
        ...process.env,
        INCUDAL_GITHUB_REPO: sourceRepository,
        INCUDAL_UPDATE_SOURCE: `https://github.com/${sourceRepository}`,
        INCUDAL_UPDATE_REF: pinnedUpdate.ref,
        INCUDAL_UPDATE_SCRIPT_SHA256: pinnedUpdate.scriptSHA256,
        INCUDAL_INSTALL_DIR: getInstallDirectory()
      }
    })
    activeUpdateProcess = child
    child.stdout?.on('data', (chunk: Buffer) => appendOutput(execution, chunk))
    child.stderr?.on('data', (chunk: Buffer) => appendOutput(execution, chunk))
    child.once('error', (error) => {
      execution.status = 'failed'
      execution.error = error.message
      execution.finishedAt = new Date().toISOString()
      activeUpdateProcess = null
    })
    child.once('close', (code, signal) => {
      execution.exitCode = code
      execution.signal = signal
      execution.status = code === 0 ? 'succeeded' : 'failed'
      execution.finishedAt = new Date().toISOString()
      activeUpdateProcess = null
      if (code !== 0) execution.error = `更新脚本退出码：${code ?? 'unknown'}`
    })
    child.unref()

    await createLog(request.user.id, 'system', 'system.update_start', `Admin started panel update from ${sourceRepository}`, 'success')
    await logAdminAction(request.user.id, 'system.update_start', {
      ip: request.ip,
      userAgent: request.headers['user-agent'],
      resourceType: 'system_update',
      newValue: { sourceRepository, mode },
      metadata: { executionId: execution.id }
    })

    return reply.code(202).send({ accepted: true, execution: currentExecution() })
  })
}
