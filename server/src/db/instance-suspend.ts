/**
 * 实例封停/解封相关数据库操作
 * 使用 Prisma ORM
 */

import { prisma } from './prisma.js'
import type { Instance } from '@prisma/client'
import {
  INSTANCE_OPERATION_LOCK_NAMESPACE,
  advisoryTransactionLock
} from './advisory-locks.js'

// ==================== 封停操作 ====================

/**
 * 封停实例（系统自动封停 - 到期）
 */
export async function suspendInstanceByExpiry(
  instanceId: number,
  onSuspended?: () => Promise<void>
): Promise<boolean> {
  return prisma.$transaction(async tx => {
    await advisoryTransactionLock(tx, INSTANCE_OPERATION_LOCK_NAMESPACE, instanceId)

    const now = new Date()
    const result = await tx.instance.updateMany({
      where: {
        id: instanceId,
        packagePlanId: { not: null },
        status: { in: ['running', 'stopped'] },
        expiresAt: { not: null, lt: now }
      },
      data: {
        status: 'suspended',
        suspendedAt: now,
        suspendedBy: null, // null 表示系统自动
        suspendReason: 'expired',
        version: { increment: 1 }
      }
    })

    if (result.count !== 1) return false

    // 外部 stop 在同一实例锁保护下执行，避免续费在标记后抢先解封，
    // 随后又被本次过期任务停止。
    if (onSuspended) await onSuspended()
    return true
  })
}

/**
 * 封停实例（管理员或宿主机所有者手动封停）
 */
export async function suspendInstanceManually(
  instanceId: number,
  operatorId: number,
  reason: string
): Promise<Instance> {
  return prisma.$transaction(async tx => {
    await advisoryTransactionLock(tx, INSTANCE_OPERATION_LOCK_NAMESPACE, instanceId)
    const current = await tx.instance.findUnique({
      where: { id: instanceId },
      select: { status: true, suspendReason: true }
    })
    if (current?.status === 'deleted' && current.suspendReason === 'expired') {
      throw new Error('实例正在删除，无法封停')
    }
    return tx.instance.update({
      where: { id: instanceId },
      data: {
        status: 'suspended',
        suspendedAt: new Date(),
        suspendedBy: operatorId,
        suspendReason: reason,
        version: { increment: 1 }
      }
    })
  })
}

/**
 * 解封实例
 */
export async function unsuspendInstance(
  instanceId: number
): Promise<Instance> {
  return prisma.$transaction(async tx => {
    await advisoryTransactionLock(tx, INSTANCE_OPERATION_LOCK_NAMESPACE, instanceId)
    const current = await tx.instance.findUnique({
      where: { id: instanceId },
      select: { status: true }
    })
    if (!current || current.status !== 'suspended') {
      throw new Error('实例未被封停或正在删除')
    }
    return tx.instance.update({
      where: { id: instanceId },
      data: {
        status: 'stopped', // 解封后设为停止状态
        suspendedAt: null,
        suspendedBy: null,
        suspendReason: null,
        version: { increment: 1 }
      }
    })
  })
}

// ==================== 查询操作 ====================

/**
 * 检查实例是否已封停
 */
export async function isInstanceSuspended(instanceId: number): Promise<boolean> {
  const instance = await prisma.instance.findUnique({
    where: { id: instanceId },
    select: { status: true }
  })
  return instance?.status === 'suspended'
}

/**
 * 检查实例是否到期封停（可续费解封）
 */
export async function isExpiredSuspension(instanceId: number): Promise<boolean> {
  const instance = await prisma.instance.findUnique({
    where: { id: instanceId },
    select: { status: true, suspendReason: true }
  })
  return instance?.status === 'suspended' && instance?.suspendReason === 'expired'
}

/**
 * 检查实例是否手动封停（不可续费解封）
 */
export async function isManualSuspension(instanceId: number): Promise<boolean> {
  const instance = await prisma.instance.findUnique({
    where: { id: instanceId },
    select: { status: true, suspendReason: true, suspendedBy: true }
  })
  return instance?.status === 'suspended' && instance?.suspendedBy !== null
}

/**
 * 获取实例的封停信息
 */
export async function getSuspendInfo(instanceId: number): Promise<{
  isSuspended: boolean
  suspendedAt: Date | null
  suspendedBy: number | null
  suspendReason: string | null
  isExpiredSuspension: boolean
  isManualSuspension: boolean
} | null> {
  const instance = await prisma.instance.findUnique({
    where: { id: instanceId },
    select: {
      status: true,
      suspendedAt: true,
      suspendedBy: true,
      suspendReason: true
    }
  })

  if (!instance) return null

  const isSuspended = instance.status === 'suspended'
  return {
    isSuspended,
    suspendedAt: instance.suspendedAt,
    suspendedBy: instance.suspendedBy,
    suspendReason: instance.suspendReason,
    isExpiredSuspension: isSuspended && instance.suspendReason === 'expired',
    isManualSuspension: isSuspended && instance.suspendedBy !== null
  }
}

/**
 * 获取即将到期的实例（用于发送提醒）
 * @param hoursBeforeExpiry 到期前多少小时
 * @param notifiedWithin 在多少小时内已通知过的不再返回
 */
export async function getExpiringInstances(
  hoursBeforeExpiry: number,
  notifiedWithin?: number
): Promise<Instance[]> {
  const now = new Date()
  const expiryThreshold = new Date(now.getTime() + hoursBeforeExpiry * 60 * 60 * 1000)

  const whereCondition: any = {
    expiresAt: {
      not: null,
      lte: expiryThreshold,
      gt: now // 还未到期
    },
    status: { notIn: ['suspended', 'deleted'] } // 未封停且未删除
  }

  // 如果指定了 notifiedWithin，排除最近已通知的
  if (notifiedWithin) {
    const notifiedThreshold = new Date(now.getTime() - notifiedWithin * 60 * 60 * 1000)
    whereCondition.OR = [
      { expiryNotifiedAt: null },
      { expiryNotifiedAt: { lt: notifiedThreshold } }
    ]
  }

  return prisma.instance.findMany({
    where: whereCondition
  })
}

/**
 * 获取已到期但未封停的实例
 * 注意：只查询付费实例（packagePlanId 不为 null）
 * 排除已删除和已封停的实例
 */
export async function getExpiredUnsuspendedInstances(): Promise<Instance[]> {
  return prisma.instance.findMany({
    where: {
      packagePlanId: { not: null },  // 明确排除免费实例
      expiresAt: {
        not: null,
        lt: new Date()
      },
      // 只有已经完成开通的实例才允许进入到期封停流程。
      // creating/error 实例可能没有完整的 Incus 资源，不能被误标记为已封停。
      status: { in: ['running', 'stopped'] }
    }
  })
}

/**
 * 更新到期通知时间
 */
export async function updateExpiryNotifiedAt(instanceId: number): Promise<void> {
  await prisma.instance.update({
    where: { id: instanceId },
    data: { expiryNotifiedAt: new Date() }
  })
}

/**
 * 获取需要自动续费的实例
 * @param hoursBeforeExpiry 到期前多少小时
 */
export async function getAutoRenewInstances(
  hoursBeforeExpiry: number
): Promise<Instance[]> {
  const now = new Date()
  const expiryThreshold = new Date(now.getTime() + hoursBeforeExpiry * 60 * 60 * 1000)

  return prisma.instance.findMany({
    where: {
      autoRenew: true,
      expiresAt: {
        not: null,
        lte: expiryThreshold,
        gt: now // 还未到期
      },
      status: { in: ['running', 'stopped'] } // 只处理已完成开通的实例
    }
  })
}

/**
 * 更新自动续费尝试记录
 */
export async function updateAutoRenewAttempt(
  instanceId: number,
  attempt: number,
  disableAutoRenew: boolean = false
): Promise<void> {
  await prisma.instance.update({
    where: { id: instanceId },
    data: {
      autoRenewAttempts: attempt,
      lastAutoRenewAttemptAt: new Date(),
      ...(disableAutoRenew ? { autoRenew: false } : {})
    }
  })
}

/**
 * 重置自动续费尝试记录（续费成功后）
 */
export async function resetAutoRenewAttempts(instanceId: number): Promise<void> {
  await prisma.instance.update({
    where: { id: instanceId },
    data: {
      autoRenewAttempts: 0,
      lastAutoRenewAttemptAt: null
    }
  })
}

/**
 * 获取封停超过指定天数的实例（用于自动删除）
 */
export async function getSuspendedInstancesOlderThan(days: number): Promise<Instance[]> {
  const threshold = new Date()
  threshold.setDate(threshold.getDate() - days)

  return prisma.instance.findMany({
    where: {
      // deleted + expired 表示删除任务已认领但尚未完成数据库清理；
      // 纳入查询可以恢复进程崩溃或外部删除失败后的清理。
      status: { in: ['suspended', 'deleted'] },
      suspendReason: 'expired',
      suspendedAt: {
        not: null,
        lt: threshold
      }
    }
  })
}

/**
 * 认领一个到期删除候选。schema 没有 deleting 状态，因此复用
 * `deleted + expired` 作为短暂的删除中标记，并用 version 绑定认领代次。
 */
export async function claimExpiredInstanceForDeletion(
  instanceId: number,
  expectedVersion: number,
  expectedSuspendedAt: Date
): Promise<Instance | null> {
  return prisma.$transaction(async tx => {
    await advisoryTransactionLock(tx, INSTANCE_OPERATION_LOCK_NAMESPACE, instanceId)

    const current = await tx.instance.findUnique({ where: { id: instanceId } })
    if (!current || current.suspendedAt?.getTime() !== expectedSuspendedAt.getTime()) {
      return null
    }

    // 进程在外部删除或数据库清理之间崩溃时，允许下一轮继续处理同一认领。
    if (
      current.status === 'deleted' &&
      current.suspendReason === 'expired' &&
      current.version === expectedVersion
    ) {
      return current
    }

    if (
      current.status !== 'suspended' ||
      current.suspendReason !== 'expired' ||
      current.version !== expectedVersion
    ) {
      return null
    }

    const claimed = await tx.instance.updateMany({
      where: {
        id: instanceId,
        status: 'suspended',
        suspendReason: 'expired',
        version: expectedVersion,
        suspendedAt: expectedSuspendedAt
      },
      data: {
        status: 'deleted',
        version: { increment: 1 }
      }
    })

    if (claimed.count !== 1) return null
    return tx.instance.findUnique({ where: { id: instanceId } })
  })
}

/** 恢复外部删除失败的到期删除认领，使下一轮调度可以重试。 */
export async function restoreExpiredInstanceDeletionClaim(
  instanceId: number,
  claimVersion: number
): Promise<boolean> {
  return prisma.$transaction(async tx => {
    await advisoryTransactionLock(tx, INSTANCE_OPERATION_LOCK_NAMESPACE, instanceId)
    const result = await tx.instance.updateMany({
      where: {
        id: instanceId,
        status: 'deleted',
        suspendReason: 'expired',
        version: claimVersion
      },
      data: {
        status: 'suspended',
        version: { increment: 1 }
      }
    })
    return result.count === 1
  })
}
