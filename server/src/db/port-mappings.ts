/**
 * 端口映射相关数据库操作
 * 使用 Prisma ORM
 */

import { prisma } from './prisma.js'
import { getHostById } from './hosts.js'
import type { PortMapping } from '../types/database.js'

/**
 * 获取实例的端口映射列表
 */
export async function getPortMappings(instanceId: number): Promise<PortMapping[]> {
  const mappings = await prisma.portMapping.findMany({
    where: { instanceId },
    orderBy: {
      createdAt: 'asc'
    }
  })

  return mappings.map(m => ({
    id: m.id,
    instance_id: m.instanceId,
    host_id: m.hostId,
    protocol: m.protocol,
    public_port: m.publicPort,
    private_port: m.privatePort,
    remark: m.remark,
    created_at: m.createdAt.toISOString()
  }))
}

/**
 * 根据 ID 获取端口映射
 */
export async function getPortMappingById(id: number): Promise<PortMapping | null> {
  const mapping = await prisma.portMapping.findUnique({
    where: { id }
  })

  if (!mapping) return null

  return {
    id: mapping.id,
    instance_id: mapping.instanceId,
    host_id: mapping.hostId,
    protocol: mapping.protocol,
    public_port: mapping.publicPort,
    private_port: mapping.privatePort,
    remark: mapping.remark,
    created_at: mapping.createdAt.toISOString()
  }
}

/**
 * 检查端口是否已被使用
 */
export async function checkPortInUse(
  hostId: number,
  port: number,
  protocol: 'tcp' | 'udp'
): Promise<PortMapping | null> {
  const mapping = await prisma.portMapping.findFirst({
    where: {
      hostId,
      publicPort: port,
      protocol
    }
  })

  if (!mapping) return null

  return {
    id: mapping.id,
    instance_id: mapping.instanceId,
    host_id: mapping.hostId,
    protocol: mapping.protocol,
    public_port: mapping.publicPort,
    private_port: mapping.privatePort,
    remark: mapping.remark,
    created_at: mapping.createdAt.toISOString()
  }
}

/**
 * 创建端口映射
 */
export async function createPortMapping(data: {
  instanceId: number
  hostId: number
  protocol: 'tcp' | 'udp'
  publicPort: number
  privatePort: number
  remark?: string
}): Promise<number> {
  const mapping = await prisma.portMapping.create({
    data: {
      instanceId: data.instanceId,
      hostId: data.hostId,
      protocol: data.protocol,
      publicPort: data.publicPort,
      privatePort: data.privatePort,
      remark: data.remark || null
    }
  })

  return mapping.id
}

/**
 * 从宿主机端口池自动分配一个可用端口
 */
export async function allocatePort(hostId: number, protocol: 'tcp' | 'udp' = 'tcp'): Promise<number | null> {
  // 获取宿主机的端口范围
  const host = await getHostById(hostId)
  if (!host || !host.nat_port_start || !host.nat_port_end) {
    return null
  }

  const portStart = host.nat_port_start
  const portEnd = host.nat_port_end

  // 获取该宿主机已使用的端口
  const usedMappings = await prisma.portMapping.findMany({
    where: {
      hostId,
      protocol
    },
    select: {
      publicPort: true
    }
  })
  const usedPorts = new Set(usedMappings.map(m => m.publicPort))

  // 收集所有可用端口
  const availablePorts: number[] = []
  for (let port = portStart; port <= portEnd; port++) {
    if (!usedPorts.has(port)) {
      availablePorts.push(port)
    }
  }

  // 如果没有可用端口，返回 null
  if (availablePorts.length === 0) {
    return null
  }

  // 随机选择一个可用端口
  const randomIndex = Math.floor(Math.random() * availablePorts.length)
  return availablePorts[randomIndex]
}

/**
 * 批量分配多个端口
 * @param checkBothProtocols 是否同时检查 TCP 和 UDP（Both 模式）
 */
export async function allocatePorts(
  hostId: number,
  count: number,
  protocol: 'tcp' | 'udp' = 'tcp',
  checkBothProtocols: boolean = false
): Promise<number[]> {
  const host = await getHostById(hostId)
  if (!host || !host.nat_port_start || !host.nat_port_end) {
    return []
  }

  const portStart = host.nat_port_start
  const portEnd = host.nat_port_end

  // 获取该宿主机已使用的端口
  const usedPorts = new Set<number>()
  
  if (checkBothProtocols) {
    // Both 模式：同时检查 TCP 和 UDP
    const [tcpMappings, udpMappings] = await Promise.all([
      prisma.portMapping.findMany({
        where: { hostId, protocol: 'tcp' },
        select: { publicPort: true }
      }),
      prisma.portMapping.findMany({
        where: { hostId, protocol: 'udp' },
        select: { publicPort: true }
      })
    ])
    tcpMappings.forEach(m => usedPorts.add(m.publicPort))
    udpMappings.forEach(m => usedPorts.add(m.publicPort))
  } else {
    const usedMappings = await prisma.portMapping.findMany({
      where: { hostId, protocol },
      select: { publicPort: true }
    })
    usedMappings.forEach(m => usedPorts.add(m.publicPort))
  }

  // 收集所有可用端口
  const availablePorts: number[] = []
  for (let port = portStart; port <= portEnd; port++) {
    if (!usedPorts.has(port)) {
      availablePorts.push(port)
    }
  }

  // 如果没有足够的可用端口，返回已收集的
  if (availablePorts.length < count) {
    // 随机打乱并返回
    for (let i = availablePorts.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [availablePorts[i], availablePorts[j]] = [availablePorts[j], availablePorts[i]];
    }
    return availablePorts
  }

  // 随机选择指定数量的端口
  const shuffled = [...availablePorts]
  for (let i = shuffled.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
  }
  return shuffled.slice(0, count)
}

/**
 * 获取宿主机端口池统计
 */
export async function getHostPortStats(hostId: number): Promise<{
  total: number
  used: number
  available: number
  rangeStart: number
  rangeEnd: number
} | null> {
  const host = await getHostById(hostId)
  if (!host || !host.nat_port_start || !host.nat_port_end) {
    return null
  }

  const totalPorts = host.nat_port_end - host.nat_port_start + 1

  const usedCount = await prisma.portMapping.groupBy({
    by: ['publicPort'],
    where: { hostId },
    _count: {
      id: true
    }
  })
  const usedPorts = usedCount.length

  return {
    total: totalPorts,
    used: usedPorts,
    available: totalPorts - usedPorts,
    rangeStart: host.nat_port_start,
    rangeEnd: host.nat_port_end
  }
}

/**
 * 删除端口映射
 */
export async function deletePortMapping(id: number): Promise<void> {
  await prisma.portMapping.delete({
    where: { id }
  })
}

/**
 * 批量检查端口占用情况
 * @returns 被占用的端口列表，包含端口号和占用该端口的实例ID
 */
export async function checkPortsInUse(
  hostId: number,
  ports: number[],
  protocol: 'tcp' | 'udp'
): Promise<{ port: number; instanceId: number }[]> {
  if (ports.length === 0) return []

  const mappings = await prisma.portMapping.findMany({
    where: {
      hostId,
      protocol,
      publicPort: { in: ports }
    },
    select: {
      publicPort: true,
      instanceId: true
    }
  })

  return mappings.map(m => ({
    port: m.publicPort,
    instanceId: m.instanceId
  }))
}

/**
 * 批量建议可用端口（替换被占用的端口）
 * @param excludePorts 需要排除的端口（用户已选择的未冲突端口）
 * @param checkBothProtocols 是否同时检查 TCP 和 UDP（Both 模式）
 */
export async function suggestAvailablePorts(
  hostId: number,
  count: number,
  protocol: 'tcp' | 'udp',
  excludePorts: number[] = [],
  checkBothProtocols: boolean = false
): Promise<number[]> {
  const host = await getHostById(hostId)
  if (!host || !host.nat_port_start || !host.nat_port_end) {
    return []
  }

  const portStart = host.nat_port_start
  const portEnd = host.nat_port_end

  // 获取该宿主机已使用的端口
  const usedPorts = new Set<number>()
  
  if (checkBothProtocols) {
    // Both 模式：同时检查 TCP 和 UDP
    const [tcpMappings, udpMappings] = await Promise.all([
      prisma.portMapping.findMany({
        where: { hostId, protocol: 'tcp' },
        select: { publicPort: true }
      }),
      prisma.portMapping.findMany({
        where: { hostId, protocol: 'udp' },
        select: { publicPort: true }
      })
    ])
    tcpMappings.forEach(m => usedPorts.add(m.publicPort))
    udpMappings.forEach(m => usedPorts.add(m.publicPort))
  } else {
    // 单协议模式
    const usedMappings = await prisma.portMapping.findMany({
      where: { hostId, protocol },
      select: { publicPort: true }
    })
    usedMappings.forEach(m => usedPorts.add(m.publicPort))
  }
  
  // 将排除端口也加入已使用集合
  excludePorts.forEach(p => usedPorts.add(p))

  // 收集所有可用端口
  const availablePorts: number[] = []
  for (let port = portStart; port <= portEnd; port++) {
    if (!usedPorts.has(port)) {
      availablePorts.push(port)
    }
  }

  // 如果可用端口不足，返回所有可用的
  if (availablePorts.length <= count) {
    return availablePorts
  }

  // 顺序返回指定数量的可用端口（不随机，方便用户理解）
  return availablePorts.slice(0, count)
}

/**
 * 批量创建端口映射
 */
export async function createPortMappingsBatch(data: Array<{
  instanceId: number
  hostId: number
  protocol: 'tcp' | 'udp'
  publicPort: number
  privatePort: number
  remark?: string
}>): Promise<number[]> {
  const results = await prisma.$transaction(
    data.map(item =>
      prisma.portMapping.create({
        data: {
          instanceId: item.instanceId,
          hostId: item.hostId,
          protocol: item.protocol,
          publicPort: item.publicPort,
          privatePort: item.privatePort,
          remark: item.remark || null
        }
      })
    )
  )

  return results.map(r => r.id)
}

// 端口预留 advisory lock 的命名空间，与其他业务的锁隔离
const PORT_RESERVATION_LOCK_NAMESPACE = 746523

/**
 * 端口预留冲突错误：advisory lock 内复查发现端口已被其他请求占用
 */
export class PortReservationConflictError extends Error {
  readonly conflicts: string[]
  constructor(conflicts: string[]) {
    super(`PORT_RESERVATION_CONFLICT: ${conflicts.join(', ')}`)
    this.name = 'PortReservationConflictError'
    this.conflicts = conflicts
  }
}

export interface ReservePortMappingInput {
  instanceId: number
  hostId: number
  protocol: 'tcp' | 'udp'
  publicPort: number
  privatePort: number
  remark?: string
}

export interface ReservedPortMapping {
  id: number
  protocol: string
  publicPort: number
  privatePort: number
}

/**
 * 在数据库事务中预留端口映射（审查项 P2-12）
 *
 * 端口映射原先采用"检查 → 加 Incus 设备 → 写库"的顺序，两个并发请求可同时
 * 通过检查；后写库的一方唯一约束失败触发回滚，且回滚按设备名删除 Incus 设备，
 * 可能删掉先成功请求创建的设备，造成数据库与 Incus 状态漂移。
 *
 * 现改为"先预留后落盘"：以宿主机为粒度取 advisory lock 串行化同一宿主机的
 * 并发请求，在锁内复查占用并写入全部映射记录；事务提交后端口即被预订，
 * 后续 Incus 操作失败时只释放本次预留的记录（releasePortMappings），
 * 不会误删其他请求的映射或设备。表上的 (hostId, protocol, publicPort)
 * 唯一约束作为最后防线。
 */
export async function reservePortMappings(items: ReservePortMappingInput[]): Promise<ReservedPortMapping[]> {
  if (items.length === 0) return []
  const hostId = items[0].hostId

  return prisma.$transaction(async (tx) => {
    // 两段式 advisory lock (namespace, hostId)：只串行化同一宿主机的请求
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(${PORT_RESERVATION_LOCK_NAMESPACE}::int, ${hostId}::int)`

    // 锁内复查冲突（TCP/UDP 各自维度）
    const ports = [...new Set(items.map(item => item.publicPort))]
    const protocols = [...new Set(items.map(item => item.protocol))]
    const conflicts = await tx.portMapping.findMany({
      where: { hostId, protocol: { in: protocols }, publicPort: { in: ports } },
      select: { publicPort: true, protocol: true }
    })
    if (conflicts.length > 0) {
      throw new PortReservationConflictError(
        conflicts.map(c => `${c.publicPort}(${c.protocol.toUpperCase()})`)
      )
    }

    const created: ReservedPortMapping[] = []
    for (const item of items) {
      const row = await tx.portMapping.create({
        data: {
          instanceId: item.instanceId,
          hostId: item.hostId,
          protocol: item.protocol,
          publicPort: item.publicPort,
          privatePort: item.privatePort,
          remark: item.remark || null
        }
      })
      created.push({
        id: row.id,
        protocol: row.protocol,
        publicPort: row.publicPort,
        privatePort: row.privatePort
      })
    }
    return created
  })
}

/**
 * 释放预留的端口映射（Incus 操作失败时回滚本次请求，只删除传入的记录）
 */
export async function releasePortMappings(ids: number[]): Promise<void> {
  if (ids.length === 0) return
  await prisma.portMapping.deleteMany({ where: { id: { in: ids } } })
}
