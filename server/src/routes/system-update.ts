/**
 * 管理员控制面板更新
 *
 * 更新不会在后台自动执行。管理员必须先检查来源，再在页面上明确确认并发起更新。
 */

import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { spawn, type ChildProcess } from 'child_process'
import { randomUUID } from 'crypto'
import { existsSync, readFileSync } from 'fs'
import { chmod, mkdtemp, rm, writeFile } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import { createLog } from '../db/logs.js'
import { logAdminAction } from '../lib/security.js'

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

const DEFAULT_GITHUB_REPOSITORY = '1743986520/incudal'
const GITHUB_API_BASE_URL = 'https://api.github.com'
const MAX_SCRIPT_BYTES = 1024 * 1024
const MAX_OUTPUT_CHARS = 16000
const updateScriptPath = 'scripts/remote-update.sh'
let activeUpdateProcess: ChildProcess | null = null
let lastUpdate: UpdateExecution | null = null

function normalizeGitHubRepository(value: string): string | null {
  let candidate = value.trim().replace(/\/+$/, '').replace(/\.git$/, '')
  if (/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(candidate)) {
    return candidate
  }

  try {
    const parsed = new URL(candidate)
    if (parsed.protocol !== 'https:' || parsed.hostname.toLowerCase() !== 'github.com') {
      return null
    }
    const parts = parsed.pathname.split('/').filter(Boolean)
    if (parts.length !== 2 || !parts.every((part) => /^[A-Za-z0-9_.-]+$/.test(part))) {
      return null
    }
    return `${parts[0]}/${parts[1]}`
  } catch {
    return null
  }
}

function getDefaultRepository(): string {
  const candidates = [
    process.env.INCUDAL_UPDATE_SOURCE,
    process.env.INCUDAL_GITHUB_REPO,
    process.env.GITHUB_REPOSITORY,
    process.env.INCUDAL_AGENT_RELEASE_URL,
    process.env.INCUDAL_AGENT_RELEASE_REPOSITORY,
    DEFAULT_GITHUB_REPOSITORY
  ]
  for (const candidate of candidates) {
    if (!candidate) continue
    const repository = normalizeGitHubRepository(candidate)
    if (repository) return repository
  }
  return DEFAULT_GITHUB_REPOSITORY
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

function getSourceUrls(repository: string): { repositoryUrl: string; scriptUrl: string } {
  return {
    repositoryUrl: `https://github.com/${repository}`,
    scriptUrl: `https://raw.githubusercontent.com/${repository}/main/${updateScriptPath}`
  }
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

function buildManualCommand(repository: string, mode: UpdateMode): string {
  const { scriptUrl } = getSourceUrls(repository)
  return `curl -fsSL ${scriptUrl} | sudo bash -s -- --source https://github.com/${repository} --mode ${mode}`
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

  if (uid === 0 && existsSync('/bin/bash')) {
    return { command: '/bin/bash', prefixArgs: [], label: '/bin/bash' }
  }
  return null
}

async function downloadUpdateScript(repository: string): Promise<string> {
  const { scriptUrl } = getSourceUrls(repository)
  const response = await fetch(scriptUrl, {
    headers: { 'User-Agent': 'Incudal-System-Update' },
    signal: AbortSignal.timeout(15000)
  })
  if (!response.ok) throw new Error(`更新脚本下载失败（HTTP ${response.status}）`)

  const contentLength = Number(response.headers.get('content-length') || 0)
  if (contentLength > MAX_SCRIPT_BYTES) throw new Error('更新脚本超过大小限制')

  const script = await response.text()
  if (!script.startsWith('#!') || script.length > MAX_SCRIPT_BYTES) {
    throw new Error('远程更新脚本格式无效或超过大小限制')
  }

  const directory = await mkdtemp(join(tmpdir(), 'incudal-web-update-'))
  const scriptPath = join(directory, 'remote-update.sh')
  await writeFile(scriptPath, script, { encoding: 'utf8', mode: 0o700 })
  await chmod(scriptPath, 0o700)
  return scriptPath
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
    const mode: UpdateMode = body.mode || 'auto'
    if (!['auto', 'docker', 'release'].includes(mode)) {
      return reply.code(400).send({ error: '更新模式必须是 auto、docker 或 release', code: 'UPDATE_MODE_INVALID' })
    }

    const executor = getUpdateExecutor()
    if (!executor) {
      return reply.code(409).send({
        error: '当前服务没有可用的站点更新执行器，请复制命令到服务器终端执行',
        code: 'UPDATE_EXECUTOR_UNAVAILABLE',
        command: buildManualCommand(sourceRepository, mode)
      })
    }

    let scriptPath = ''
    try {
      if (executor.label === '/bin/bash') {
        scriptPath = await downloadUpdateScript(sourceRepository)
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : '无法下载更新脚本'
      return reply.code(502).send({ error: message, code: 'UPDATE_SCRIPT_DOWNLOAD_FAILED' })
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

    const args = executor.label === '/bin/bash'
      ? [scriptPath, '--source', `https://github.com/${sourceRepository}`, '--mode', mode, '--install-dir', getInstallDirectory()]
      : [...executor.prefixArgs, '--source', `https://github.com/${sourceRepository}`, '--mode', mode]
    const child = spawn(executor.command, args, {
      cwd: process.cwd(),
      detached: true,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: {
        ...process.env,
        INCUDAL_GITHUB_REPO: sourceRepository,
        INCUDAL_UPDATE_SOURCE: `https://github.com/${sourceRepository}`,
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
      if (scriptPath) {
        void rm(join(scriptPath, '..'), { recursive: true, force: true }).catch(() => undefined)
      }
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
