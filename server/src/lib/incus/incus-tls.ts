import { lookup as dnsLookup } from 'node:dns/promises'
import { isIP } from 'node:net'
import { isAbsolute, join, normalize, resolve } from 'node:path'
import { X509Certificate } from 'node:crypto'
import { connect as tlsConnect } from 'node:tls'
import { fileURLToPath } from 'node:url'
import { Address4, Address6 } from 'ip-address'

export interface IncusTlsTrust {
  ca?: string | Buffer | Array<string | Buffer>
  fingerprint?: string | null
}

export interface IncusTlsConnectOptions {
  rejectUnauthorized: true
  ca?: string | Buffer | Array<string | Buffer>
}

export interface ResolvedIncusTarget {
  url: string
  servername?: string
  address: string
}

const moduleDir = fileURLToPath(new URL('.', import.meta.url))
const defaultCertDir = resolve(moduleDir, '../../../certs')

function configuredPath(value: string | undefined, fallbackName: string): string {
  return resolve(value || join(defaultCertDir, fallbackName))
}

export function panelCertificatePaths(): { certPath: string; keyPath: string } {
  return {
    certPath: configuredPath(process.env.PANEL_CRT_PATH, 'client.crt'),
    keyPath: configuredPath(process.env.PANEL_KEY_PATH, 'client.key')
  }
}

export function assertServerManagedCertificatePaths(certPath: string, keyPath: string): void {
  const managed = panelCertificatePaths()
  const normalizedCert = normalize(resolve(certPath))
  const normalizedKey = normalize(resolve(keyPath))
  if (!isAbsolute(certPath) || !isAbsolute(keyPath) || normalizedCert !== normalize(managed.certPath) || normalizedKey !== normalize(managed.keyPath)) {
    throw new Error('Incus certificate paths must use the server-managed panel certificate pair')
  }
}

export function normalizeCertificatePem(certificate: string | Buffer): string {
  const pem = certificate.toString().trim()
  const parsed = new X509Certificate(pem)
  return parsed.toString().trim() + '\n'
}

export function certificateFingerprint(certificate: string | Buffer): string {
  return new X509Certificate(certificate).fingerprint256.replaceAll(':', '').toLowerCase()
}

export function assertCertificateMatchesFingerprint(certificate: string | Buffer, fingerprint?: string | null): void {
  if (!fingerprint) return
  const expected = fingerprint.replaceAll(':', '').trim().toLowerCase()
  if (!/^[a-f0-9]{64}$/.test(expected) || certificateFingerprint(certificate) !== expected) {
    throw new Error('Incus server certificate does not match the stored host fingerprint')
  }
}

export function buildIncusTlsConnectOptions(trust: IncusTlsTrust = {}): IncusTlsConnectOptions {
  if (trust.ca) assertCertificateMatchesFingerprint(Array.isArray(trust.ca) ? trust.ca[0] : trust.ca, trust.fingerprint)
  return {
    rejectUnauthorized: true,
    ...(trust.ca ? { ca: trust.ca } : {})
  }
}

const blockedIpv4Cidrs = [
  '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
  '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.168.0.0/16',
  '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4'
].map(cidr => new Address4(cidr))

const blockedIpv6Cidrs = [
  '::/128', '::1/128', '100::/64', '2001::/23', 'fc00::/7', 'fe80::/10', 'ff00::/8'
].map(cidr => new Address6(cidr))

function normalizedMappedIpv4(address: string): string | null {
  const value = address.toLowerCase().split('%')[0]
  const dotted = value.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/)?.[1]
  if (dotted && isIP(dotted) === 4) return dotted
  if (!value.startsWith('::ffff:')) return null
  const tail = value.slice('::ffff:'.length).split(':')
  if (tail.length !== 2 || tail.some(part => !/^[a-f0-9]{1,4}$/.test(part))) return null
  const high = Number.parseInt(tail[0], 16)
  const low = Number.parseInt(tail[1], 16)
  return `${high >>> 8}.${high & 255}.${low >>> 8}.${low & 255}`
}

export function isPublicHostAddress(address: string): boolean {
  const value = address.toLowerCase().split('%')[0]
  const mapped = normalizedMappedIpv4(value)
  if (mapped) return isPublicHostAddress(mapped)
  if (isIP(value) === 4) {
    const parsed = new Address4(value)
    return !blockedIpv4Cidrs.some(cidr => parsed.isInSubnet(cidr))
  }
  if (isIP(value) === 6) {
    const parsed = new Address6(value)
    return !blockedIpv6Cidrs.some(cidr => parsed.isInSubnet(cidr))
  }
  return false
}

export async function resolveIncusTarget(
  input: string,
  allowPrivateNetwork: boolean,
  resolver: (hostname: string) => Promise<string[]> = async hostname => (await dnsLookup(hostname, { all: true, verbatim: true })).map(item => item.address)
): Promise<ResolvedIncusTarget> {
  let url: URL
  try {
    url = new URL(input)
  } catch {
    throw new Error('Host URL is invalid')
  }
  if (url.protocol !== 'https:' || url.username || url.password) {
    throw new Error('Incus host URL must use HTTPS without credentials')
  }

  const hostname = url.hostname.replace(/^\[|\]$/g, '')
  const addresses = isIP(hostname) ? [hostname] : Array.from(new Set(await resolver(hostname)))
  if (addresses.length === 0) throw new Error('Host URL did not resolve to an address')
  if (!allowPrivateNetwork && addresses.some(address => !isPublicHostAddress(address))) {
    throw new Error('Ordinary host creators must use a publicly routable host URL')
  }

  const address = addresses.find(candidate => isIP(candidate) === 4) || addresses[0]
  if (!isIP(address)) throw new Error('Host URL resolved to an invalid address')
  url.hostname = isIP(address) === 6 ? `[${address.split('%')[0]}]` : address
  return {
    url: url.toString().replace(/\/$/, ''),
    ...(isIP(hostname) ? {} : { servername: hostname }),
    address
  }
}

export async function assertAllowedHostUrl(
  input: string,
  isAdmin: boolean,
  resolver?: (hostname: string) => Promise<string[]>
): Promise<void> {
  await resolveIncusTarget(input, isAdmin, resolver)
}

export async function captureIncusServerCertificate(
  input: string,
  allowPrivateNetwork: boolean
): Promise<{ certificate: string; fingerprint: string; target: ResolvedIncusTarget }> {
  const target = await resolveIncusTarget(input, allowPrivateNetwork)
  const parsed = new URL(target.url)
  const port = Number(parsed.port || 8443)
  return new Promise((resolveCapture, rejectCapture) => {
    const socket = tlsConnect({
      host: target.address,
      port,
      ...(target.servername ? { servername: target.servername } : {}),
      rejectUnauthorized: false
    })
    const finish = (error?: Error) => {
      socket.destroy()
      if (error) rejectCapture(error)
    }
    socket.setTimeout(15_000, () => finish(new Error('Timed out while capturing the Incus server certificate')))
    socket.once('error', finish)
    socket.once('secureConnect', () => {
      const peer = socket.getPeerX509Certificate()
      if (!peer?.raw) return finish(new Error('Incus did not present a server certificate'))
      const parsedCertificate = new X509Certificate(peer.raw)
      const certificate = parsedCertificate.toString().trim() + '\n'
      const fingerprint = certificateFingerprint(certificate)
      socket.destroy()
      resolveCapture({ certificate, fingerprint, target })
    })
  })
}

export function trustFromEnvironment(): IncusTlsTrust {
  const caPath = process.env.INCUS_CA_PATH?.trim()
  if (caPath) {
    assertServerManagedTrustPath(caPath)
    return { ca: caPath }
  }
  return {}
}

function assertServerManagedTrustPath(path: string): void {
  if (!isAbsolute(path)) throw new Error('INCUS_CA_PATH must be an absolute server-managed path')
}
