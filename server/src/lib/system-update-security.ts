import { randomUUID } from 'crypto'

export const DEFAULT_GITHUB_REPOSITORY = '1743986520/incudal'

export interface PinnedUpdate {
  ref: string
  scriptSHA256: string
}

export function normalizeGitHubRepository(value: string): string | null {
  const candidate = value.trim().replace(/\/+$/, '').replace(/\.git$/, '')
  if (/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(candidate)) return candidate
  try {
    const parsed = new URL(candidate)
    if (parsed.protocol !== 'https:' || parsed.hostname.toLowerCase() !== 'github.com') return null
    const parts = parsed.pathname.split('/').filter(Boolean)
    if (parts.length !== 2 || !parts.every((part) => /^[A-Za-z0-9_.-]+$/.test(part))) return null
    return `${parts[0]}/${parts[1]}`
  } catch {
    return null
  }
}

export function getAllowedRepositories(): string[] {
  const configured = process.env.INCUDAL_UPDATE_ALLOWED_REPOSITORIES?.split(',') || []
  const repositories = configured.map(normalizeGitHubRepository).filter((value): value is string => Boolean(value))
  return repositories.length > 0 ? [...new Set(repositories)] : [DEFAULT_GITHUB_REPOSITORY]
}

export function isAllowedRepository(repository: string): boolean {
  return getAllowedRepositories().some((allowed) => allowed.toLowerCase() === repository.toLowerCase())
}

export function getPinnedUpdate(): PinnedUpdate | null {
  const ref = process.env.INCUDAL_UPDATE_REF?.trim() || ''
  const scriptSHA256 = process.env.INCUDAL_UPDATE_SCRIPT_SHA256?.trim() || ''
  if (!/^[0-9a-fA-F]{40}$/.test(ref) || !/^[0-9a-fA-F]{64}$/.test(scriptSHA256)) return null
  return { ref: ref.toLowerCase(), scriptSHA256: scriptSHA256.toLowerCase() }
}

export function buildManualCommand(repository: string, mode: string): string {
  const pinned = getPinnedUpdate()
  if (!pinned) return '请配置 INCUDAL_UPDATE_REF 和 INCUDAL_UPDATE_SCRIPT_SHA256 后执行受校验的手动更新'
  const scriptURL = `https://raw.githubusercontent.com/${repository}/${pinned.ref}/scripts/remote-update.sh`
  const tempPath = `/tmp/incudal-update-${randomUUID()}.sh`
  return `curl -fsSL '${scriptURL}' -o '${tempPath}' && printf '%s  %s\\n' '${pinned.scriptSHA256}' '${tempPath}' | sha256sum -c - && sudo /usr/bin/bash '${tempPath}' --source 'https://github.com/${repository}' --ref '${pinned.ref}' --mode '${mode}'; status=$?; rm -f '${tempPath}'; exit $status`
}
