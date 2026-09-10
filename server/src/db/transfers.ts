/**
 * 实例转移相关数据库操作
 */

import { prisma } from './prisma.js'
import { Prisma } from '@prisma/client'
import type { TransferStatus } from '@prisma/client'
import { INSTANCE_OPERATION_LOCK_NAMESPACE, advisoryTransactionLock } from './advisory-locks.js'
import { assertCurrentInstanceOwner, debitTransferFee, executeTransferTransaction } from './transfer-safety.js'

// 事务隔离级别配置
const TRANSFER_TRANSACTION_OPTIONS = {
    isolationLevel: Prisma.TransactionIsolationLevel.Serializable,
    timeout: 10000,
} as const

const TRANSFER_CREATE_LOCK_RETRY_LIMIT = 20
const TRANSFER_CREATE_LOCK_RETRY_DELAY_MS = 100

function sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms))
}

/**
 * 清理卡住的 processing 状态转移（服务启动时调用）
 * 将所有 processing 状态回滚为 pending，让用户可以重新操作
 */
export async function cleanupStaleTransfers(): Promise<number> {
    return 0
}

/**
 * 清理超时的 processing 状态转移（运行时定期检查）
 * 将超过 30 分钟仍在 processing 状态的转移回滚为 pending
 * 使用 updatedAt 字段跟踪状态变更时间，避免旧的转移请求刚开始处理就被错误清理
 */
export async function cleanupTimeoutTransfers(): Promise<number> {
    const result = await prisma.instanceTransfer.updateMany({
        where: {
            status: 'processing',
            claimExpiresAt: { lt: new Date() },
            claimToken: { not: null }
        },
        data: { status: 'pending', claimToken: null, claimExpiresAt: null, phase: null }
    })
    return result.count
}

// 转移快照信息类型
export interface TransferSnapshot {
    packageId: number | null
    packageName: string | null
    hostId: number
    hostName: string
    hostLocation: string | null
    hostCountryCode: string
    originalName: string
    cpu: number
    memory: number
    disk: number
    networkMode: string
    portMappingsCount: number
    snapshotsCount: number
    backupsCount: number
    ipv4: string | null
    ipv6: string | null
}

// 创建转移请求（带手续费扣除，事务安全）
export async function createTransferWithFee(data: {
    instanceId: number
    fromUserId: number
    toUserId: number
    snapshot: TransferSnapshot
    remark?: string
    fee: number
    instanceName: string
}): Promise<{ transferId: number; feeDeducted: boolean }> {
    for (let attempt = 0; attempt < TRANSFER_CREATE_LOCK_RETRY_LIMIT; attempt++) {
        const result = await prisma.$transaction(async (tx) => {
            await advisoryTransactionLock(tx, INSTANCE_OPERATION_LOCK_NAMESPACE, data.instanceId)

            await assertCurrentInstanceOwner(tx, data.instanceId, data.fromUserId)

            // 0. 在事务内检查是否已有 pending/processing 转移
            const existingTransfer = await tx.instanceTransfer.findFirst({
                where: {
                    instanceId: data.instanceId,
                    status: { in: ['pending', 'processing'] }
                }
            })
            if (existingTransfer) {
                throw new Error('TRANSFER_ALREADY_PENDING')
            }

            // Revalidate immediately before creating the charge-bearing transfer.
            await assertCurrentInstanceOwner(tx, data.instanceId, data.fromUserId)
            const transfer = await tx.instanceTransfer.create({
                data: {
                    instanceId: data.instanceId,
                    fromUserId: data.fromUserId,
                    toUserId: data.toUserId,
                    snapshot: data.snapshot as any,
                    remark: data.remark,
                    fee: data.fee > 0 ? data.fee : null,
                    status: 'pending'
                }
            })
            if (data.fee > 0) {
                await debitTransferFee(tx, {
                    transferId: transfer.id,
                    userId: data.fromUserId,
                    instanceId: data.instanceId,
                    instanceName: data.instanceName,
                    fee: new Prisma.Decimal(data.fee)
                })
            }
            return { transferId: transfer.id, feeDeducted: data.fee > 0 }
        }, TRANSFER_TRANSACTION_OPTIONS)

        if (result) {
            return result
        }

        await sleep(TRANSFER_CREATE_LOCK_RETRY_DELAY_MS * (attempt + 1))
    }

    throw new Error('TRANSFER_ALREADY_PENDING')
}

// 创建转移请求（不带手续费，保持向后兼容）
export async function createTransfer(data: {
    instanceId: number
    fromUserId: number
    toUserId: number
    snapshot: TransferSnapshot
    remark?: string
    fee?: number
}): Promise<number> {
    for (let attempt = 0; attempt < TRANSFER_CREATE_LOCK_RETRY_LIMIT; attempt++) {
        const transferId = await prisma.$transaction(async (tx) => {
            await advisoryTransactionLock(tx, INSTANCE_OPERATION_LOCK_NAMESPACE, data.instanceId)

            await assertCurrentInstanceOwner(tx, data.instanceId, data.fromUserId)

            const existingTransfer = await tx.instanceTransfer.findFirst({
                where: {
                    instanceId: data.instanceId,
                    status: { in: ['pending', 'processing'] }
                }
            })
            if (existingTransfer) {
                throw new Error('TRANSFER_ALREADY_PENDING')
            }

            const transfer = await tx.instanceTransfer.create({
                data: {
                    instanceId: data.instanceId,
                    fromUserId: data.fromUserId,
                    toUserId: data.toUserId,
                    snapshot: data.snapshot as any,
                    remark: data.remark,
                    fee: null,
                    status: 'pending'
                }
            })

            return transfer.id
        }, TRANSFER_TRANSACTION_OPTIONS)

        if (transferId !== null) {
            return transferId
        }

        await sleep(TRANSFER_CREATE_LOCK_RETRY_DELAY_MS * (attempt + 1))
    }

    throw new Error('TRANSFER_ALREADY_PENDING')
}

// 检查实例是否有待处理的转移（包括 pending 和 processing 状态）
export async function hasPendingTransfer(instanceId: number): Promise<boolean> {
    const count = await prisma.instanceTransfer.count({
        where: {
            instanceId,
            status: { in: ['pending', 'processing'] }
        }
    })
    return count > 0
}

// 获取实例的待处理转移（包括 pending 和 processing 状态）
export async function getPendingTransferByInstanceId(instanceId: number) {
    return prisma.instanceTransfer.findFirst({
        where: {
            instanceId,
            status: { in: ['pending', 'processing'] }
        },
        include: {
            fromUser: {
                select: { id: true, username: true, email: true, avatarStyle: true, avatarBadgeId: true }
            },
            toUser: {
                select: { id: true, username: true, email: true, avatarStyle: true, avatarBadgeId: true }
            }
        }
    })
}

// 获取转移详情
export async function getTransferById(id: number) {
    return prisma.instanceTransfer.findUnique({
        where: { id },
        include: {
            instance: {
                select: {
                    id: true,
                    name: true,
                    status: true,
                    image: true
                }
            },
            fromUser: {
                select: { id: true, username: true, email: true, avatarStyle: true, avatarBadgeId: true }
            },
            toUser: {
                select: { id: true, username: true, email: true, avatarStyle: true, avatarBadgeId: true }
            }
        }
    })
}

// 获取转移详情（包含手续费字段）
export async function getTransferByIdWithFee(id: number) {
    const transfer = await prisma.instanceTransfer.findUnique({
        where: { id },
        select: {
            id: true,
            instanceId: true,
            fromUserId: true,
            toUserId: true,
            status: true,
            snapshot: true,
            remark: true,
            rejectReason: true,
            fee: true,
            createdAt: true,
            updatedAt: true,
            acceptedAt: true,
            rejectedAt: true,
            cancelledAt: true,
            instance: {
                select: {
                    id: true,
                    name: true,
                    status: true,
                    image: true
                }
            },
            fromUser: {
                select: { id: true, username: true, email: true, avatarStyle: true, avatarBadgeId: true }
            },
            toUser: {
                select: { id: true, username: true, email: true, avatarStyle: true, avatarBadgeId: true }
            }
        }
    })
    return transfer
}

// 退还转移手续费（事务安全）
export async function refundTransferFee(data: {
    transferId: number
    fromUserId: number
    fee: number
    instanceId: number
    instanceName: string
    reason: 'rejected' | 'cancelled'
}): Promise<{ success: boolean; error?: string }> {
    try {
        await prisma.$transaction(async (tx) => {
            // 1. 获取当前余额
            const user = await tx.user.findUnique({
                where: { id: data.fromUserId },
                select: { balance: true }
            })
            
            if (!user) {
                throw new Error('USER_NOT_FOUND')
            }
            
            const balanceBefore = Number(user.balance)
            const balanceAfter = balanceBefore + data.fee
            
            // 2. 更新余额
            await tx.user.update({
                where: { id: data.fromUserId },
                data: { balance: balanceAfter }
            })
            
            // 3. 创建退款日志
            const remarkMap = {
                rejected: `转移实例 "${data.instanceName}" 被拒绝，退还手续费`,
                cancelled: `取消转移实例 "${data.instanceName}"，退还手续费`
            }
            
            await tx.balanceLog.create({
                data: {
                    userId: data.fromUserId,
                    type: 'transfer_refund',
                    amount: data.fee,
                    balanceBefore,
                    balanceAfter,
                    instanceId: data.instanceId,
                    remark: remarkMap[data.reason]
                }
            })
        })
        
        return { success: true }
    } catch (error) {
        return {
            success: false,
            error: error instanceof Error ? error.message : '退款失败'
        }
    }
}

// 获取用户发起的转移列表
export async function getTransfersSent(userId: number, options: {
    page: number
    pageSize: number
    status?: TransferStatus
    search?: string
}) {
    const where: any = { fromUserId: userId }
    if (options.status) {
        where.status = options.status
    }

    // 搜索条件
    if (options.search && options.search.trim()) {
        const searchTerm = options.search.trim()
        where.OR = [
            { instance: { name: { contains: searchTerm, mode: 'insensitive' } } },
            { toUser: { username: { contains: searchTerm, mode: 'insensitive' } } },
            { remark: { contains: searchTerm, mode: 'insensitive' } }
        ]
    }

    const [items, total] = await Promise.all([
        prisma.instanceTransfer.findMany({
            where,
            include: {
                instance: {
                    select: { id: true, name: true, status: true, image: true }
                },
                toUser: {
                    select: { id: true, username: true, email: true, avatarStyle: true, avatarBadgeId: true }
                }
            },
            orderBy: { createdAt: 'desc' },
            skip: (options.page - 1) * options.pageSize,
            take: options.pageSize
        }),
        prisma.instanceTransfer.count({ where })
    ])

    return {
        items,
        total,
        page: options.page,
        pageSize: options.pageSize,
        totalPages: Math.ceil(total / options.pageSize)
    }
}

// 获取用户收到的转移列表
export async function getTransfersReceived(userId: number, options: {
    page: number
    pageSize: number
    status?: TransferStatus
    search?: string
}) {
    const where: any = { toUserId: userId }
    if (options.status) {
        where.status = options.status
    }

    // 搜索条件
    if (options.search && options.search.trim()) {
        const searchTerm = options.search.trim()
        where.OR = [
            { instance: { name: { contains: searchTerm, mode: 'insensitive' } } },
            { fromUser: { username: { contains: searchTerm, mode: 'insensitive' } } },
            { remark: { contains: searchTerm, mode: 'insensitive' } }
        ]
    }

    const [items, total] = await Promise.all([
        prisma.instanceTransfer.findMany({
            where,
            include: {
                instance: {
                    select: { id: true, name: true, status: true, image: true }
                },
                fromUser: {
                    select: { id: true, username: true, email: true, avatarStyle: true, avatarBadgeId: true }
                }
            },
            orderBy: { createdAt: 'desc' },
            skip: (options.page - 1) * options.pageSize,
            take: options.pageSize
        }),
        prisma.instanceTransfer.count({ where })
    ])

    return {
        items,
        total,
        page: options.page,
        pageSize: options.pageSize,
        totalPages: Math.ceil(total / options.pageSize)
    }
}

// 获取用户待处理的接收数量（仅 pending 状态，processing 不显示为待接收）
export async function getPendingReceivedCount(userId: number): Promise<number> {
    return prisma.instanceTransfer.count({
        where: {
            toUserId: userId,
            status: 'pending'  // 仅计算 pending，processing 表示正在处理中
        }
    })
}

// 更新转移状态为已接受
export async function acceptTransfer(id: number): Promise<void> {
    await prisma.instanceTransfer.update({
        where: { id },
        data: {
            status: 'accepted',
            acceptedAt: new Date()
        }
    })
}

// 更新转移状态为已拒绝
export async function rejectTransfer(id: number, reason?: string): Promise<void> {
    await prisma.instanceTransfer.update({
        where: { id },
        data: {
            status: 'rejected',
            rejectedAt: new Date(),
            rejectReason: reason
        }
    })
}

// 更新转移状态为已取消
export async function cancelTransfer(id: number): Promise<void> {
    await prisma.instanceTransfer.update({
        where: { id },
        data: {
            status: 'cancelled',
            cancelledAt: new Date()
        }
    })
}

// 执行转移（事务操作）
// 注意：不再更新实例配额，因为不再限制用户的实例配额
// 安全改进：显式指定 Serializable 隔离级别，确保操作一致性
export async function executeTransfer(
    transferId: number,
    instanceId: number,
    fromUserId: number,
    toUserId: number,
    newInstanceName: string,
    newIncusId: string,
    claimToken: string,
    oldIncusId: string,
    instanceVersion: number
): Promise<void> {
    await prisma.$transaction(async (tx) => {
        await executeTransferTransaction(tx, {
            transferId,
            instanceId,
            fromUserId,
            toUserId,
            newInstanceName,
            newIncusId,
            claimToken,
            oldIncusId,
            instanceVersion
        })
    }, TRANSFER_TRANSACTION_OPTIONS)
}
