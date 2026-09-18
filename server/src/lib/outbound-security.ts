import { lookup as dnsLookup } from 'dns/promises'
import { isIP } from 'net'
import { Agent, fetch as undiciFetch, type RequestInit, type Response } from 'undici'
// 统一复用 Incus TLS 模块的公网地址判断，确保 IPv4-mapped IPv6（点分与十六进制形式）、
// NAT64（64:ff9b::/96）、IPv4-compatible（::/96）等特殊范围不会被当作公网地址放行。
import { isPublicHostAddress } from './incus/incus-tls.js'

export class OutboundTargetValidationError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'OutboundTargetValidationError'
  }
}

type SupportedProtocol = 'http' | 'https' | 'ftp' | 'sftp'

function buildUrl(input: string, defaultProtocol: SupportedProtocol): URL {
  const trimmed = input.trim()
  if (!trimmed) {
    throw new OutboundTargetValidationError('Target cannot be empty')
  }

  try {
    if (trimmed.includes('://')) {
      return new URL(trimmed)
    }
    return new URL(`${defaultProtocol}://${trimmed}`)
  } catch {
    throw new OutboundTargetValidationError('Target format is invalid')
  }
}

export function isIpPrivateOrReserved(ip: string): boolean {
  // 无法解析的地址按保留地址处理（fail closed），避免异常输入被放行。
  try {
    return !isPublicHostAddress(ip)
  } catch {
    return true
  }
}

async function assertPublicHostname(hostname: string): Promise<void> {
  await resolvePublicAddresses(hostname)
}

async function resolvePublicAddresses(hostname: string): Promise<Array<{ address: string; family: 4 | 6 }>> {
  const normalizedHost = hostname.trim().toLowerCase().replace(/\.$/, '')
  if (!normalizedHost) {
    throw new OutboundTargetValidationError('Hostname cannot be empty')
  }

  if (
    normalizedHost === 'localhost' ||
    normalizedHost.endsWith('.localhost') ||
    normalizedHost.endsWith('.local') ||
    normalizedHost.endsWith('.internal')
  ) {
    throw new OutboundTargetValidationError('Private or local targets are not allowed')
  }

  const family = isIP(normalizedHost)
  if (family !== 0) {
    if (isIpPrivateOrReserved(normalizedHost)) {
      throw new OutboundTargetValidationError('Private or reserved IP targets are not allowed')
    }
    return [{ address: normalizedHost, family: family as 4 | 6 }]
  }

  if (!normalizedHost.includes('.')) {
    throw new OutboundTargetValidationError('Private or local hostnames are not allowed')
  }

  let records: Array<{ address: string }>
  try {
    records = await dnsLookup(normalizedHost, { all: true, verbatim: true })
  } catch (error: any) {
    const code = error?.code ? String(error.code) : 'UNKNOWN'
    throw new OutboundTargetValidationError(`Unable to resolve hostname (${code})`)
  }

  if (records.length === 0) {
    throw new OutboundTargetValidationError('Unable to resolve hostname')
  }

  for (const record of records) {
    if (isIpPrivateOrReserved(record.address)) {
      throw new OutboundTargetValidationError('Targets resolving to private or reserved IPs are not allowed')
    }
  }

  return records.map(record => ({
    address: record.address,
    family: isIP(record.address) as 4 | 6
  }))
}

/**
 * Execute an HTTP request while pinning DNS resolution to the public addresses
 * that were validated immediately beforehand. Redirects are deliberately
 * disabled so every destination must pass a fresh validation.
 */
export async function withSafePublicFetch<T>(
  input: string | URL,
  init: RequestInit,
  consume: (response: Response) => Promise<T>
): Promise<T> {
  const parsed = typeof input === 'string' ? new URL(input) : input
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new OutboundTargetValidationError('Outbound URL must use http or https')
  }

  const addresses = await resolvePublicAddresses(parsed.hostname)
  let nextAddress = 0
  const dispatcher = new Agent({
    connect: {
      lookup: (_hostname, options, callback) => {
        const requestedFamily = typeof options === 'number' ? options : options?.family
        const candidates = requestedFamily === 4 || requestedFamily === 6
          ? addresses.filter(item => item.family === requestedFamily)
          : addresses
        const selected = candidates[nextAddress++ % candidates.length] || addresses[0]
        callback(null, selected.address, selected.family)
      }
    }
  })

  try {
    const response = await undiciFetch(parsed, {
      ...init,
      redirect: 'manual',
      dispatcher
    })
    return await consume(response)
  } finally {
    await dispatcher.close()
  }
}

export async function assertSafeWebhookUrl(url: string): Promise<URL> {
  const parsed = buildUrl(url, 'https')
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new OutboundTargetValidationError('Webhook URL must use http or https')
  }

  await assertPublicHostname(parsed.hostname)
  return parsed
}

export async function assertSafeStorageTarget(
  type: 'WEBDAV' | 'FTP' | 'SFTP',
  host: string
): Promise<void> {
  const defaultProtocol: Record<'WEBDAV' | 'FTP' | 'SFTP', SupportedProtocol> = {
    WEBDAV: 'https',
    FTP: 'ftp',
    SFTP: 'sftp'
  }

  const parsed = buildUrl(host, defaultProtocol[type])
  await assertPublicHostname(parsed.hostname)
}
