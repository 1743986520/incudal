/**
 * IP 地址数据库操作
 */
import { prisma } from './prisma.js'
import { Prisma, type IpType } from '@prisma/client'
import { generateRandomIPv4, generateRandomIPv6 } from '../lib/ip-calculator.js'

export interface CreateIpAddressData {
    address: string
    type: IpType
    isPrimary: boolean
    isCustom?: boolean
    device: string
    hostId?: number
    instanceId: number
}

export interface ReserveInstanceIpAddressesData {
    instanceId: number
    hostId: number
    allocateIpv4: boolean
    ipv6Subnet?: string | null
}

export interface ReservedInstanceIpAddresses {
    ipv4: string | null
    ipv6: string | null
}

/**
 * Atomically reserves provisioning addresses before they are handed to Incus.
 *
 * Availability checks alone are inherently racy: two provisioners can observe
 * the same free candidate. The host/address unique constraint is the final
 * arbiter, while this transaction keeps the reservation rows and the legacy
 * Instance.ipv4/ipv6 fields in sync. Candidates already tried in this call are
 * never selected again.
 */
export async function reserveInstanceIpAddresses(
    data: ReserveInstanceIpAddressesData
): Promise<ReservedInstanceIpAddresses> {
    const attemptedIpv4 = new Set<string>()
    const attemptedIpv6 = new Set<string>()
    const maxAttempts = 100

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
        const ipv4Candidate = data.allocateIpv4
            ? nextDistinctCandidate(() => generateRandomIPv4(), attemptedIpv4, maxAttempts)
            : null
        const ipv6Candidate = data.ipv6Subnet
            ? nextDistinctCandidate(() => generateRandomIPv6(data.ipv6Subnet!), attemptedIpv6, maxAttempts)
            : null

        try {
            return await prisma.$transaction(async tx => {
                const instance = await tx.instance.findUnique({
                    where: { id: data.instanceId },
                    select: { hostId: true, status: true }
                })
                if (!instance) throw new Error(`Instance ${data.instanceId} not found while reserving IP addresses`)
                if (instance.hostId !== data.hostId) throw new Error('Instance host changed while reserving IP addresses')
                if (instance.status === 'deleted') throw new Error('Cannot reserve IP addresses for a deleted instance')

                const existing = await tx.ipAddress.findMany({
                    where: { instanceId: data.instanceId, isPrimary: true },
                    select: { address: true, type: true }
                })
                // Only an IpAddress row is a reservation. Legacy Instance fields
                // without one are untrusted check-then-use leftovers and must be
                // replaced rather than retried forever with the same collision.
                const existingIpv4 = existing.find(ip => ip.type === 'inet4')?.address
                const existingIpv6 = existing.find(ip => ip.type === 'inet6')?.address
                const ipv4 = data.allocateIpv4 ? (existingIpv4 ?? ipv4Candidate) : null
                const ipv6 = data.ipv6Subnet ? (existingIpv6 ?? ipv6Candidate) : null

                if (data.allocateIpv4 && !ipv4) throw new Error('IPv4 address pool exhausted')
                if (data.ipv6Subnet && !ipv6) throw new Error('IPv6 address pool exhausted')

                if (ipv4 && !existing.some(ip => ip.type === 'inet4')) {
                    await tx.ipAddress.create({
                        data: { address: ipv4, type: 'inet4', isPrimary: true, device: 'eth0', hostId: data.hostId, instanceId: data.instanceId }
                    })
                }
                if (ipv6 && !existing.some(ip => ip.type === 'inet6')) {
                    await tx.ipAddress.create({
                        data: { address: ipv6, type: 'inet6', isPrimary: true, device: 'eth1', hostId: data.hostId, instanceId: data.instanceId }
                    })
                }

                await tx.instance.update({
                    where: { id: data.instanceId },
                    data: { ipv4, ipv6 }
                })
                return { ipv4, ipv6 }
            }, { isolationLevel: Prisma.TransactionIsolationLevel.Serializable, maxWait: 3000, timeout: 5000 })
        } catch (error) {
            if (error instanceof Prisma.PrismaClientKnownRequestError && (error.code === 'P2002' || error.code === 'P2034')) continue
            throw error
        }
    }

    throw new Error(`Unable to reserve a unique IP address after ${maxAttempts} attempts`)
}

function nextDistinctCandidate(factory: () => string, attempted: Set<string>, maxAttempts: number): string | null {
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
        const candidate = factory()
        if (!attempted.has(candidate)) {
            attempted.add(candidate)
            return candidate
        }
    }
    return null
}

async function resolveInstanceHostId(instanceId: number): Promise<number> {
    const instance = await prisma.instance.findUnique({
        where: { id: instanceId },
        select: { hostId: true }
    })

    if (!instance) {
        throw new Error(`Instance ${instanceId} not found while creating IP address record`)
    }

    return instance.hostId
}

/**
 * 创建 IP 地址记录
 */
export async function createIpAddress(data: CreateIpAddressData) {
    const hostId = data.hostId ?? await resolveInstanceHostId(data.instanceId)

    return prisma.ipAddress.create({
        data: {
            address: data.address,
            type: data.type,
            isPrimary: data.isPrimary,
            isCustom: data.isCustom ?? false,
            device: data.device,
            host: {
                connect: { id: hostId }
            },
            instance: {
                connect: { id: data.instanceId }
            }
        }
    })
}

/**
 * 获取实例的所有 IP 地址
 */
export async function getIpAddressesByInstanceId(instanceId: number) {
    return prisma.ipAddress.findMany({
        where: { instanceId },
        orderBy: [
            { isPrimary: 'desc' },
            { createdAt: 'asc' }
        ]
    })
}

/**
 * 获取实例的主 IP 地址
 */
export async function getPrimaryIpAddress(instanceId: number, type: IpType) {
    return prisma.ipAddress.findFirst({
        where: {
            instanceId,
            type,
            isPrimary: true
        }
    })
}

/**
 * 根据 ID 获取 IP 地址
 */
export async function getIpAddressById(id: number) {
    return prisma.ipAddress.findUnique({
        where: { id },
        include: {
            instance: {
                include: {
                    host: true
                }
            }
        }
    })
}

/**
 * 删除 IP 地址
 */
export async function deleteIpAddress(id: number) {
    return prisma.ipAddress.delete({
        where: { id }
    })
}

/**
 * 获取实例下一个可用的网卡设备名
 */
export async function getNextDeviceName(instanceId: number): Promise<string> {
    const existingIps = await prisma.ipAddress.findMany({
        where: { instanceId },
        select: { device: true }
    })

    // 提取已使用的设备编号
    const usedIndices = existingIps
        .map((ip: { device: string }) => {
            const match = ip.device.match(/^eth(\d+)$/)
            return match ? parseInt(match[1], 10) : -1
        })
        .filter((idx: number) => idx >= 0)

    // 找到下一个可用编号
    let nextIndex = 0
    while (usedIndices.includes(nextIndex)) {
        nextIndex++
    }

    return `eth${nextIndex}`
}

/**
 * 检查 IP 地址是否已存在（全局检查）
 * 用于 IPv6 等公网地址的全局唯一性检查
 * 
 * 检查两个来源：
 * 1. IpAddress 表中的记录
 * 2. Instance 表的 ipv6 字段（防止数据不一致导致的冲突）
 * 
 * 注意：排除已删除状态的实例
 */
export async function isIpAddressExists(address: string): Promise<boolean> {
    // 1. 检查 IpAddress 表（排除已删除的实例）
    const existingInIpTable = await prisma.ipAddress.findFirst({
        where: {
            address,
            type: 'inet6',
            instance: {
                status: { not: 'deleted' }
            }
        }
    })
    if (existingInIpTable) {
        return true
    }

    // 2. 检查 Instance 表的 ipv6 字段（防止数据不一致）
    // 有些实例可能 ipv6 字段有值，但 IpAddress 表没有对应记录
    const existingInInstanceTable = await prisma.instance.findFirst({
        where: {
            ipv6: address,
            status: { not: 'deleted' }
        }
    })
    
    return !!existingInInstanceTable
}

/**
 * 检查 IP 地址在指定宿主机范围内是否已存在
 * 用于内网 IPv4 地址的按宿主机唯一性检查
 * （不同宿主机的内网是隔离的，可以使用相同的内网 IP）
 * 
 * 检查两个来源：
 * 1. IpAddress 表中的记录
 * 2. Instance 表的 ipv4 字段（防止数据不一致导致的冲突）
 * 
 * 注意：排除已删除状态的实例
 * 
 * @param address IP 地址
 * @param hostId 宿主机 ID
 * @returns 是否已存在
 */
export async function isIpAddressExistsOnHost(address: string, hostId: number): Promise<boolean> {
    // 1. 检查 IpAddress 表（排除已删除的实例）
    const existingInIpTable = await prisma.ipAddress.findFirst({
        where: {
            address,
            type: 'inet4',
            host: {
                is: { id: hostId }
            },
            instance: {
                status: { not: 'deleted' }
            }
        }
    })
    if (existingInIpTable) {
        return true
    }

    // 2. 检查 Instance 表的 ipv4 字段（防止数据不一致）
    // 有些实例可能 ipv4 字段有值，但 IpAddress 表没有对应记录
    const existingInInstanceTable = await prisma.instance.findFirst({
        where: {
            hostId,
            ipv4: address,
            status: { not: 'deleted' }
        }
    })
    
    return !!existingInInstanceTable
}

/**
 * 统计实例的 IP 数量
 */
export async function countIpAddresses(instanceId: number): Promise<number> {
    return prisma.ipAddress.count({
        where: { instanceId }
    })
}
