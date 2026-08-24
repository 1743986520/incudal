import { createHash } from 'crypto'
import { isIP } from 'net'
import { prisma } from '../db/prisma.js'

export const HOST_NETWORK_POLICY_TYPES = ['ip_block', 'dns_lock', 'dns_override'] as const
export type HostNetworkPolicyType = (typeof HOST_NETWORK_POLICY_TYPES)[number]

function stringList(value: unknown, maxItems = 256): string[] {
  if (!Array.isArray(value)) return []
  return [...new Set(value.filter((item): item is string => typeof item === 'string').map(item => item.trim()).filter(Boolean))].slice(0, maxItems)
}

function validCidr(value: string): boolean {
  const [address, rawPrefix, extra] = value.split('/')
  if (extra !== undefined || isIP(address) === 0) return false
  if (rawPrefix === undefined) return true
  if (!/^\d+$/.test(rawPrefix)) return false
  const prefix = Number(rawPrefix)
  return prefix >= 0 && prefix <= (isIP(address) === 4 ? 32 : 128)
}

function validDomain(value: string): boolean {
  return value.length <= 253 && /^(?:\*\.)?(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(value)
}

export function normalizeNetworkPolicyInput(input: {
  policyType?: unknown
  targetMode?: unknown
  targetInstanceIds?: unknown
  config?: unknown
}): { policyType: HostNetworkPolicyType; targetMode: 'selected' | 'all_current' | 'all_dynamic'; targetInstanceIds: number[]; config: Record<string, unknown> } {
  if (!HOST_NETWORK_POLICY_TYPES.includes(input.policyType as HostNetworkPolicyType)) throw new Error('不支持的网络策略类型')
  const policyType = input.policyType as HostNetworkPolicyType
  const targetMode = ['selected', 'all_current', 'all_dynamic'].includes(String(input.targetMode)) ? input.targetMode as 'selected' | 'all_current' | 'all_dynamic' : 'selected'
  const targetInstanceIds = [...new Set((Array.isArray(input.targetInstanceIds) ? input.targetInstanceIds : []).map(Number).filter(id => Number.isInteger(id) && id > 0))].slice(0, 1000)
  if (targetMode === 'selected' && targetInstanceIds.length === 0) throw new Error('请至少选择一个实例')
  const raw = input.config && typeof input.config === 'object' ? input.config as Record<string, unknown> : {}
  let config: Record<string, unknown>
  if (policyType === 'ip_block') {
    const cidrs = stringList(raw.cidrs).filter(validCidr)
    if (cidrs.length === 0) throw new Error('请填写有效的 IPv4、IPv6 或 CIDR')
    config = { cidrs }
  } else if (policyType === 'dns_lock') {
    const upstreams = stringList(raw.upstreams, 8).filter(value => isIP(value) !== 0)
    if (upstreams.length === 0) throw new Error('请填写平台 DNS 上游 IP')
    config = { upstreams, blockDot: raw.blockDot === true }
  } else {
    const domains = stringList(raw.domains).map(value => value.toLowerCase()).filter(validDomain)
    const action = ['address', 'nxdomain', 'zero'].includes(String(raw.action)) ? String(raw.action) : 'address'
    const addresses = stringList(raw.addresses, 16).filter(value => isIP(value) !== 0)
    const upstreams = stringList(raw.upstreams, 8).filter(value => isIP(value) !== 0)
    if (domains.length === 0) throw new Error('请填写有效域名')
    if (action === 'address' && addresses.length === 0) throw new Error('DNS 劫持必须填写目标 IP')
    if (upstreams.length === 0) throw new Error('请填写平台 DNS 上游 IP')
    config = { domains, action, addresses: action === 'address' ? addresses : [], upstreams }
  }
  return { policyType, targetMode, targetInstanceIds, config }
}

function lastReportMacMap(lastReport: unknown): Map<string, string> {
  const map = new Map<string, string>()
  if (!lastReport || typeof lastReport !== 'object') return map
  const instances = (lastReport as any).instances
  for (const item of Array.isArray(instances?.items) ? instances.items : []) {
    const name = typeof item?.name === 'string' ? item.name : ''
    const mac = typeof item?.network?.mac === 'string' ? item.network.mac.toLowerCase() : ''
    if (name && /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(mac)) map.set(name, mac)
  }
  return map
}

export async function buildHostAgentPolicyBundle(hostId: number): Promise<Record<string, unknown>> {
  const [agent, policies, instances] = await Promise.all([
    prisma.hostAgent.findUnique({ where: { hostId }, select: { lastReport: true } }),
    prisma.hostNetworkPolicy.findMany({ where: { hostId, enabled: true }, orderBy: { id: 'asc' } }),
    prisma.instance.findMany({ where: { hostId, status: { not: 'deleted' } }, select: { id: true, incusId: true, name: true } })
  ])
  const macByIncusId = lastReportMacMap(agent?.lastReport)
  const compiled = policies.map(policy => {
    const selected = new Set(Array.isArray(policy.targetInstanceIds) ? (policy.targetInstanceIds as unknown[]).map(Number) : [])
    const targets = instances
      .filter(instance => policy.targetMode !== 'selected' || selected.has(instance.id))
      .map(instance => ({ instanceId: instance.id, instanceName: instance.name, incusId: instance.incusId, mac: macByIncusId.get(instance.incusId) || null }))
    return { id: policy.id, revision: policy.revision, type: policy.policyType, config: policy.config, targets }
  })
  const revision = createHash('sha256').update(JSON.stringify(compiled)).digest('hex')
  return { revision, policies: compiled }
}
