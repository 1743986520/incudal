/**
 * 实例销毁相关路由
 * 处理用户端实例销毁功能（带退款）
 */

import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify'
import type { InstanceStatus } from '@prisma/client'
import * as db from '../db/index.js'
import { prisma } from '../db/prisma.js'
import { createLog } from '../db/logs.js'
import { apiError, ErrorCode } from '../lib/errors.js'
import { closeInstanceSessions } from '../lib/terminal-proxy.js'
import { claimInstanceForDelete } from './instances/helpers.js'
import { processPendingInstanceDeletion } from '../services/pending-instance-deletion.js'
import { withInstanceRemoteOperationLock } from '../services/instance-remote-operation-lock.js'
import {
  INSTANCE_OPERATION_LOCK_NAMESPACE,
  tryAdvisoryTransactionLock
} from '../db/advisory-locks.js'

// 销毁业务规则常量
const DESTROY_RULES = {
  FEE_RATE: 0.10,                // 手续费率 10%（首次免手续费）
  DEFAULT_MAX_PAID_DESTROY_MONTHLY_TRAFFIC: 5n * 1024n * 1024n * 1024n // 5 GiB
}

const DESTROY_DISABLED_REASON = '此套餐不支持用户自行删除及退款'

interface BatchDestroyPreviewItem {
  id: number
  name: string
  canDestroy: boolean
  cannotDestroyReason: string
  isFreeInstance: boolean
  isFirstTime: boolean
  feeWaiverEligible: boolean
  countsTowardsDestroyFee?: boolean
  refund: {
    remainingDays: number
    remainingValue: number
    feeRate: number
    feeAmount: number
    refundAmount: number
    destroyCount: number
    maxRefundable: number
  }
  instance: {
    id: number
    name: string
    hostName: string
    planName: string | null
  }
}

interface BatchDestroyResultItem {
  id: number
  name: string
  success: boolean
  skipped?: boolean
  pending?: boolean
  status?: 'deleting'
  reason?: string
  refundAmount?: number
  feeAmount?: number
  isFirstTime?: boolean
  isFreeInstance?: boolean
}

const BATCH_HIDDEN_REASON = '实例不存在或无权操作'

function isExpiredAt(expiresAt: Date | null | undefined): boolean {
  return !!expiresAt && expiresAt.getTime() <= Date.now()
}

function canUserDestroyExpiredSuspendedPaidInstance(instance: {
  status: string
  suspendReason?: string | null
  packagePlanId?: number | null
  expiresAt?: Date | null
  billingMode?: string | null
}): boolean {
  if (instance.status === 'suspended' && instance.billingMode === 'hourly' && instance.suspendReason === 'hourly_billing_insufficient_balance') {
    return true
  }
  return instance.status === 'suspended'
    && instance.suspendReason === 'expired'
    && !!instance.packagePlanId
    && isExpiredAt(instance.expiresAt)
}

/**
 * 计算手续费率
 * 第1次：0%（首次免手续费）
 * 第2次及以后：10%
 */
function calculateFeeRate(destroyCount: number): number {
  if (destroyCount === 0) return 0 // 首次免手续费
  return DESTROY_RULES.FEE_RATE
}

function getDestroyTrafficLimit(instance: { package?: { destroyTrafficLimit: bigint } | null }): bigint {
  return instance.package?.destroyTrafficLimit ?? DESTROY_RULES.DEFAULT_MAX_PAID_DESTROY_MONTHLY_TRAFFIC
}

function isInstanceDeletionAllowed(instance: { package?: { allowInstanceDeletion: boolean } | null }): boolean {
  return instance.package?.allowInstanceDeletion ?? true
}

function exceedsPaidDestroyTrafficLimit(monthlyTrafficUsed: bigint, limit: bigint): boolean {
  return monthlyTrafficUsed >= limit
}

function getDestroyTrafficUsage(instance: {
  trafficBillingMode: 'package' | 'usage'
  monthlyTrafficUsed: bigint
  monthlyTrafficLimit: bigint | null
  trafficSettledBytes: bigint
}, currentMonthlyTrafficUsed = instance.monthlyTrafficUsed): bigint {
  if (instance.trafficBillingMode !== 'usage') return currentMonthlyTrafficUsed
  const included = instance.monthlyTrafficLimit ?? 0n
  const overage = currentMonthlyTrafficUsed > included ? currentMonthlyTrafficUsed - included : 0n
  return overage > instance.trafficSettledBytes ? overage - instance.trafficSettledBytes : 0n
}

function formatTrafficLimit(limit: bigint): string {
  const gib = Number(limit) / (1024 ** 3)
  return `${Number.isInteger(gib) ? gib.toFixed(0) : gib.toFixed(2)} GiB`
}

function getDestroyTrafficLimitReason(limit: bigint): string {
  return `当前月流量周期无法销毁，已用流量达到或超过 ${formatTrafficLimit(limit)}`
}

async function getDestroyBlockingTask(instanceId: number, client: any = prisma): Promise<{
  code: 'RESTORE_IN_PROGRESS' | 'UPLOAD_IN_PROGRESS' | 'TASK_IN_PROGRESS'
  reason: string
} | null> {
  const [activeRestoreTask, activeUploadTask, activeInstanceTask] = await Promise.all([
    client.restoreTask.findFirst({
      where: {
        instanceId,
        status: { in: ['PENDING', 'PROCESSING'] }
      },
      select: { id: true }
    }),
    client.backupUploadTask.findFirst({
      where: {
        instanceId,
        status: { in: ['PENDING', 'PROCESSING'] }
      },
      select: { id: true }
    }),
    client.instanceTask.findFirst({
      where: {
        instanceId,
        status: { in: ['PENDING', 'PROCESSING'] }
      },
      select: { id: true }
    })
  ])

  if (activeRestoreTask) {
    return { code: 'RESTORE_IN_PROGRESS', reason: '该实例有正在进行的恢复任务，请等待完成或取消' }
  }
  if (activeUploadTask) {
    return { code: 'UPLOAD_IN_PROGRESS', reason: '该实例有正在进行的备份上传任务，请等待完成或取消' }
  }
  if (activeInstanceTask) {
    return { code: 'TASK_IN_PROGRESS', reason: '该实例有正在进行的操作任务，请等待完成' }
  }
  return null
}

function roundMoney(value: number): number {
  return Number(value.toFixed(2))
}

/** Free, package-traffic instances have no refund, destroy fee or final
 * usage settlement. Use the same durable deletion as ordinary DELETE. */
async function destroyFreeInstanceDurably(
  user: { id: number; role: 'admin' | 'user' },
  instance: {
    id: number; userId: number; hostId: number; incusId: string; version: number
    status: InstanceStatus; packageId: number | null; packagePlanId: number | null
    billingMode: 'package' | 'hourly'; trafficBillingMode: 'package' | 'usage'; suspendReason: string | null
    host: { userId: number }
  },
  logger: { warn: (...args: any[]) => void }
): Promise<'completed' | 'pending' | 'conflict'> {
  const claimed = await claimInstanceForDelete(instance.id, instance.status, {
    authorization: {
      actorUserId: user.id, actorRole: user.role, scope: 'instance-or-host',
      expectedUserId: instance.userId, expectedHostId: instance.hostId,
      expectedHostUserId: instance.host.userId, expectedIncusId: instance.incusId,
      expectedVersion: instance.version, expectedPackagePlanId: instance.packagePlanId,
      expectedPackageId: instance.packageId, expectedSuspendReason: instance.suspendReason,
      expectedBillingMode: instance.billingMode, expectedTrafficBillingMode: instance.trafficBillingMode
    },
    pending: { requestedById: user.id }
  })
  if (!claimed) return 'conflict'

  closeInstanceSessions(instance.id, 'Instance is being deleted')
  try {
    if (await processPendingInstanceDeletion(instance.id)) return 'completed'
  } catch (error) {
    logger.warn({ instanceId: instance.id, error }, 'Free instance destruction remains pending')
  }
  return 'pending'
}

export async function claimInstanceForUserDestroy(
  expected: {
    id: number; userId: number; hostId: number; incusId: string; version: number
    status: InstanceStatus; packageId: number | null; packagePlanId: number | null
    billingMode: 'package' | 'hourly'; suspendReason: string | null; expiresAt: Date | null
    trafficBillingMode: 'package' | 'usage'; monthlyTrafficUsed: bigint; monthlyTrafficLimit: bigint | null; trafficSettledBytes: bigint
    package: { allowInstanceDeletion: boolean; destroyTrafficLimit: bigint } | null
  },
  actor: { id: number; role: 'admin' | 'user' },
  currentMonthlyTrafficUsed: bigint,
  deletionBillingMode: 'user_destroy' | 'hourly_close' | null,
  feeWaiver: boolean
): Promise<boolean> {
  const instanceId = expected.id
  const currentStatus = expected.status
  if (expected.userId !== actor.id) return false
  if (currentStatus === 'deleted' || currentStatus === 'deleting') return false
  return prisma.$transaction(async (tx) => {
    const locked = await tryAdvisoryTransactionLock(tx, INSTANCE_OPERATION_LOCK_NAMESPACE, instanceId)
    if (!locked) return false

    const actors = await tx.$queryRaw<Array<{ role: string; status: string }>>`
      SELECT "role", "status" FROM "users" WHERE "id" = ${actor.id} FOR UPDATE
    `
    if (actors[0]?.status !== 'active' || actors[0]?.role !== actor.role) return false

    if (expected.packageId !== null) {
      const policies = await tx.$queryRaw<Array<{ allowed: boolean; trafficLimit: bigint }>>`
        SELECT "allow_instance_deletion" AS "allowed", "destroy_traffic_limit" AS "trafficLimit"
        FROM "packages" WHERE "id" = ${expected.packageId} FOR UPDATE
      `
      if (!expected.package || !policies[0]?.allowed || policies[0].allowed !== expected.package.allowInstanceDeletion
        || policies[0].trafficLimit !== expected.package.destroyTrafficLimit) return false
    }

    const blockingTask = await getDestroyBlockingTask(instanceId, tx)
    if (blockingTask) return false
    const activeTransfer = await tx.instanceTransfer.findFirst({
      where: { instanceId, status: { in: ['pending', 'processing'] } }, select: { id: true }
    })
    if (activeTransfer) return false

    const requestedAt = new Date()
    const result = await tx.instance.updateMany({
      where: {
        id: instanceId,
        userId: expected.userId,
        hostId: expected.hostId,
        incusId: expected.incusId,
        version: expected.version,
        status: currentStatus,
        packageId: expected.packageId,
        packagePlanId: expected.packagePlanId,
        billingMode: expected.billingMode,
        suspendReason: expected.suspendReason,
        expiresAt: expected.expiresAt,
        trafficBillingMode: expected.trafficBillingMode,
        monthlyTrafficUsed: currentMonthlyTrafficUsed,
        monthlyTrafficLimit: expected.monthlyTrafficLimit,
        trafficSettledBytes: expected.trafficSettledBytes,
        provisioningCleanupPending: false
      },
      data: {
        status: 'deleting',
        version: { increment: 1 },
        deletionBillingPending: deletionBillingMode !== null,
        deletionRemoteDeleted: false,
        deletionBillingMode,
        deletionRefundableValue: null,
        deletionFeeWaiver: deletionBillingMode !== null ? feeWaiver : false,
        deletionOriginalStatus: currentStatus,
        deletionRequestedAt: requestedAt,
        deletionRequestedById: actor.id,
        deletionReason: null
      }
    })

    if (result.count === 1 && deletionBillingMode === 'user_destroy') {
      // Persist the request-time quote in the same transaction as the claim;
      // it is a ceiling only, never evidence of eligibility or final usage.
      const current = await tx.instance.findUniqueOrThrow({
        where: { id: instanceId },
        select: { id: true, billingPrice: true, billingCycle: true, expiresAt: true, packagePlanId: true }
      })
      const quote = await db.calculateInstanceRemainingRefundQuote(current, tx, requestedAt)
      await tx.instance.update({ where: { id: instanceId }, data: { deletionRefundableValue: quote.isPaid ? quote.refundableValue : 0 } })
    }
    return result.count === 1
  })
}

/** Paid destruction is durable, but must not pretend stale traffic
 * proves eligibility. It remains pending for a final-usage reconciliation. */
async function queueOfflinePaidDestroy(
  instance: Parameters<typeof claimInstanceForUserDestroy>[0],
  actor: Parameters<typeof claimInstanceForUserDestroy>[1],
  feeWaiver: boolean
): Promise<boolean> {
  const mode = db.isHourlyInstance(instance) ? 'hourly_close' : 'user_destroy'
  const locked = await withInstanceRemoteOperationLock(instance.id, () =>
    claimInstanceForUserDestroy(instance, actor, instance.monthlyTrafficUsed, mode, feeWaiver)
  )
  if (!locked.acquired || !locked.value) return false
  closeInstanceSessions(instance.id, 'Instance destruction pending reconciliation')
  return true
}

async function buildBatchDestroyPreviewItem(userId: number, instanceId: number): Promise<BatchDestroyPreviewItem> {
  const instance = await prisma.instance.findUnique({
    where: { id: instanceId },
    include: {
      host: { select: { id: true, name: true, userId: true } },
      package: { select: { allowInstanceDeletion: true, destroyTrafficLimit: true } },
      packagePlan: { select: { id: true, name: true } }
    }
  })

  if (!instance) {
    return {
      id: instanceId,
      name: `#${instanceId}`,
      canDestroy: false,
      cannotDestroyReason: BATCH_HIDDEN_REASON,
      isFreeInstance: true,
      isFirstTime: false,
      feeWaiverEligible: false,
      refund: {
        remainingDays: 0,
        remainingValue: 0,
        feeRate: 0,
        feeAmount: 0,
        refundAmount: 0,
        destroyCount: 0,
        maxRefundable: 0
      },
      instance: {
        id: instanceId,
        name: `#${instanceId}`,
        hostName: '-',
        planName: null
      }
    }
  }

  if (instance.userId !== userId) {
    return {
      id: instanceId,
      name: `#${instanceId}`,
      canDestroy: false,
      cannotDestroyReason: BATCH_HIDDEN_REASON,
      isFreeInstance: true,
      isFirstTime: false,
      feeWaiverEligible: false,
      refund: {
        remainingDays: 0,
        remainingValue: 0,
        feeRate: 0,
        feeAmount: 0,
        refundAmount: 0,
        destroyCount: 0,
        maxRefundable: 0
      },
      instance: {
        id: instanceId,
        name: `#${instanceId}`,
        hostName: '-',
        planName: null
      }
    }
  }

  if (instance.status === 'deleted' || instance.status === 'deleting') {
    return {
      id: instance.id,
      name: instance.name,
      canDestroy: false,
      cannotDestroyReason: instance.status === 'deleting' ? '实例正在销毁' : '实例已删除',
      isFreeInstance: db.isFreeInstance(instance),
      isFirstTime: false,
      feeWaiverEligible: false,
      refund: {
        remainingDays: 0,
        remainingValue: 0,
        feeRate: 0,
        feeAmount: 0,
        refundAmount: 0,
        destroyCount: 0,
        maxRefundable: 0
      },
      instance: {
        id: instance.id,
        name: instance.name,
        hostName: instance.host.name,
        planName: instance.packagePlan?.name || null
      }
    }
  }

  if (instance.status === 'creating') {
    return {
      id: instance.id,
      name: instance.name,
      canDestroy: false,
      cannotDestroyReason: '实例正在创建中，无法销毁',
      isFreeInstance: db.isFreeInstance(instance),
      isFirstTime: false,
      feeWaiverEligible: false,
      refund: {
        remainingDays: 0,
        remainingValue: 0,
        feeRate: 0,
        feeAmount: 0,
        refundAmount: 0,
        destroyCount: 0,
        maxRefundable: 0
      },
      instance: {
        id: instance.id,
        name: instance.name,
        hostName: instance.host.name,
        planName: instance.packagePlan?.name || null
      }
    }
  }

  if (instance.status === 'suspended' && !canUserDestroyExpiredSuspendedPaidInstance(instance)) {
    return {
      id: instance.id,
      name: instance.name,
      canDestroy: false,
      cannotDestroyReason: '实例已被封停，无法销毁，请先联系管理员解封',
      isFreeInstance: db.isFreeInstance(instance),
      isFirstTime: false,
      feeWaiverEligible: false,
      refund: {
        remainingDays: 0,
        remainingValue: 0,
        feeRate: 0,
        feeAmount: 0,
        refundAmount: 0,
        destroyCount: 0,
        maxRefundable: 0
      },
      instance: {
        id: instance.id,
        name: instance.name,
        hostName: instance.host.name,
        planName: instance.packagePlan?.name || null
      }
    }
  }

  const isErrorState = instance.status === 'error'
  const feeWaiver = isErrorState
  const isFreeInstance = db.isFreeInstance(instance)
  const destroyRecords = await prisma.userDestroyRecord.findMany({
    where: { userId },
    orderBy: { destroyedAt: 'desc' }
  })
  let isFirstTime = destroyRecords.length === 0

  let remainingValue = 0
  let feeAmount = 0
  let refundAmount = 0
  let remainingDays = 0
  let maxRefundable = 0
  let refundableValue = 0
  let currentFeeRate = feeWaiver ? 0 : calculateFeeRate(destroyRecords.length)
  let canDestroy = true
  let cannotDestroyReason = ''

  if (!isInstanceDeletionAllowed(instance)) {
    canDestroy = false
    cannotDestroyReason = DESTROY_DISABLED_REASON
  }

  if (canDestroy) {
    const blockingTask = await getDestroyBlockingTask(instanceId)
    if (blockingTask) {
      canDestroy = false
      cannotDestroyReason = blockingTask.reason
    }
  }

  if (!isFreeInstance && instance.expiresAt && instance.billingPrice && instance.billingCycle) {
    const refundQuote = await db.calculateInstanceRemainingRefundQuote({
      id: instance.id,
      billingPrice: instance.billingPrice,
      billingCycle: instance.billingCycle,
      expiresAt: instance.expiresAt,
      packagePlanId: instance.packagePlanId
    })

    if (refundQuote.isPaid) {
      remainingDays = refundQuote.remainingDays
      remainingValue = refundQuote.remainingValue
      refundableValue = refundQuote.refundableValue
      maxRefundable = refundQuote.maxRefundable
      currentFeeRate = feeWaiver ? 0 : calculateFeeRate(destroyRecords.length)
      if (!isFirstTime && !feeWaiver) {
        feeAmount = Number((refundableValue * currentFeeRate).toFixed(2))
      }
      refundAmount = Number((refundableValue - feeAmount).toFixed(2))
    }

  }

  if (
    canDestroy
    && !isFreeInstance
    && !canUserDestroyExpiredSuspendedPaidInstance(instance)
    && exceedsPaidDestroyTrafficLimit(getDestroyTrafficUsage(instance), getDestroyTrafficLimit(instance))
  ) {
    canDestroy = false
    cannotDestroyReason = getDestroyTrafficLimitReason(getDestroyTrafficLimit(instance))
  }

  return {
    id: instance.id,
    name: instance.name,
    canDestroy,
    cannotDestroyReason,
    isFreeInstance,
    isFirstTime: !db.isHourlyInstance(instance) && isFirstTime,
    feeWaiverEligible: isErrorState,
    countsTowardsDestroyFee: !isFreeInstance && !db.isHourlyInstance(instance),
    refund: {
      remainingDays,
      remainingValue,
      feeRate: currentFeeRate,
      feeAmount,
      refundAmount,
      destroyCount: destroyRecords.length,
      maxRefundable
    },
    instance: {
      id: instance.id,
      name: instance.name,
      hostName: instance.host.name,
      planName: instance.packagePlan?.name || null
    }
  }
}

async function executeDestroyForUser(
  user: { id: number; username: string; role: 'admin' | 'user' },
  instanceId: number,
  logger: { warn: (...args: any[]) => void; error: (...args: any[]) => void }
): Promise<BatchDestroyResultItem> {
  const instance = await prisma.instance.findUnique({
    where: { id: instanceId },
    include: {
      user: { select: { id: true, username: true, balance: true, email: true } },
      host: { select: { id: true, name: true, userId: true, status: true } },
      package: { select: { allowInstanceDeletion: true, destroyTrafficLimit: true } }
    }
  })

  if (!instance) {
    return { id: instanceId, name: `#${instanceId}`, success: false, reason: BATCH_HIDDEN_REASON }
  }

  if (instance.userId !== user.id) {
    return { id: instanceId, name: `#${instanceId}`, success: false, reason: BATCH_HIDDEN_REASON }
  }

  if (!isInstanceDeletionAllowed(instance)) {
    return { id: instance.id, name: instance.name, success: false, skipped: true, reason: DESTROY_DISABLED_REASON }
  }

  if (instance.status === 'deleted') {
    return { id: instance.id, name: instance.name, success: false, skipped: true, reason: '实例已删除' }
  }
  if (instance.status === 'deleting') {
    return { id: instance.id, name: instance.name, success: false, skipped: true, reason: '实例正在销毁' }
  }

  if (instance.status === 'creating') {
    return { id: instance.id, name: instance.name, success: false, skipped: true, reason: '实例正在创建中，无法销毁' }
  }

  if (instance.status === 'suspended' && !canUserDestroyExpiredSuspendedPaidInstance(instance)) {
    return { id: instance.id, name: instance.name, success: false, skipped: true, reason: '实例已被封停，无法销毁，请先联系管理员解封' }
  }

  const blockingTask = await getDestroyBlockingTask(instanceId)
  if (blockingTask) {
    return { id: instance.id, name: instance.name, success: false, skipped: true, reason: blockingTask.reason }
  }

  const isFreeInstance = db.isFreeInstance(instance)
  if (isFreeInstance) {
    const result = await destroyFreeInstanceDurably(user, instance, logger)
    if (result === 'conflict') return { id: instance.id, name: instance.name, success: false, skipped: true, reason: '实例正在销毁或已删除' }
    if (result === 'pending') return { id: instance.id, name: instance.name, success: false, pending: true, status: 'deleting', isFreeInstance: true }
    return { id: instance.id, name: instance.name, success: true, refundAmount: 0, feeAmount: 0, isFreeInstance: true }
  }
  // Final traffic since the last sample is not provable while the guest may
  // still be running. Preserve the claim and its quote for manual review.
  if (!canUserDestroyExpiredSuspendedPaidInstance(instance)
    && exceedsPaidDestroyTrafficLimit(getDestroyTrafficUsage(instance), getDestroyTrafficLimit(instance))) {
    return { id: instance.id, name: instance.name, success: false, skipped: true, reason: getDestroyTrafficLimitReason(getDestroyTrafficLimit(instance)) }
  }
  if (!await queueOfflinePaidDestroy(instance, user, instance.status === 'error')) {
    return { id: instance.id, name: instance.name, success: false, skipped: true, reason: '实例正在操作、销毁或创建清理中' }
  }
  return { id: instance.id, name: instance.name, success: false, pending: true, status: 'deleting', isFreeInstance: false }

}

export default async function instanceDestroyRoutes(fastify: FastifyInstance) {

  fastify.post<{
    Body: { instanceIds: number[] }
  }>('/batch/destroy-info', {
    onRequest: [fastify.authenticateUser],
    config: { rateLimit: { max: 10, timeWindow: '1 minute' } },
    schema: {
      body: {
        type: 'object',
        required: ['instanceIds'],
        properties: {
          instanceIds: {
            type: 'array',
            items: { type: 'integer' },
            minItems: 1,
            maxItems: 100
          }
        },
        additionalProperties: false
      }
    }
  }, async (request, reply) => {
    const uniqueIds = Array.from(new Set(request.body.instanceIds)).filter(id => Number.isInteger(id))
    if (uniqueIds.length === 0) {
      return reply.code(400).send({ error: '请选择至少一个实例' })
    }

    const items = await Promise.all(uniqueIds.map(id => buildBatchDestroyPreviewItem(request.user.id, id)))
    // Execute uses the submitted order. Only monthly paid instances create a
    // destroy record, so only the first eligible one can use the free deletion.
    let priorDestroyCount = items.find(item => item.countsTowardsDestroyFee)?.refund.destroyCount ?? 0
    for (const item of items) {
      if (!item.canDestroy || !item.countsTowardsDestroyFee) continue
      const isFirstTime = priorDestroyCount === 0
      const refundableValue = item.refund.refundAmount + item.refund.feeAmount
      const feeRate = item.feeWaiverEligible || isFirstTime ? 0 : DESTROY_RULES.FEE_RATE
      const feeAmount = roundMoney(refundableValue * feeRate)
      item.isFirstTime = isFirstTime
      item.refund.feeRate = feeRate
      item.refund.feeAmount = feeAmount
      item.refund.refundAmount = roundMoney(Math.max(0, refundableValue - feeAmount))
      item.refund.destroyCount = priorDestroyCount
      priorDestroyCount++
    }
    return { items }
  })

  fastify.post<{
    Body: { instanceIds: number[] }
  }>('/batch/destroy', {
    onRequest: [fastify.authenticateUser],
    config: { rateLimit: { max: 3, timeWindow: '1 minute' } },
    schema: {
      body: {
        type: 'object',
        required: ['instanceIds'],
        properties: {
          instanceIds: {
            type: 'array',
            items: { type: 'integer' },
            minItems: 1,
            maxItems: 100
          }
        },
        additionalProperties: false
      }
    }
  }, async (request, reply) => {
    const uniqueIds = Array.from(new Set(request.body.instanceIds)).filter(id => Number.isInteger(id))
    if (uniqueIds.length === 0) {
      return reply.code(400).send({ error: '请选择至少一个实例' })
    }

    const userMeta = {
      id: request.user.id,
      username: request.user.username,
      role: request.user.role
    }

    const results: BatchDestroyResultItem[] = []
    for (const instanceId of uniqueIds) {
      const result = await executeDestroyForUser(userMeta, instanceId, request.log)
      results.push(result)
    }

    const successCount = results.filter(item => item.success).length
    const skippedCount = results.filter(item => item.skipped).length
    const pendingCount = results.filter(item => item.pending).length
    const failedCount = results.length - successCount - skippedCount - pendingCount

    await createLog(
      request.user.id,
      'billing',
      'instance.batch_destroy',
      `Batch destroy processed ${results.length} instance(s): success=${successCount}, pending=${pendingCount}, skipped=${skippedCount}, failed=${failedCount}`,
      failedCount > 0 ? 'warning' : 'success'
    )

    return {
      message: successCount > 0 || pendingCount > 0 ? '批量销毁已处理' : '没有实例完成销毁',
      successCount,
      pendingCount,
      skippedCount,
      failedCount,
      results
    }
  })

  // ==================== 获取销毁预览信息 ====================
  // GET /api/instances/:id/destroy-info
  fastify.get<{ Params: { id: string }; Querystring: { feeWaiver?: string } }>('/:id/destroy-info', {
    onRequest: [fastify.authenticate],
    config: { rateLimit: { max: 30, timeWindow: '1 minute' } }
  }, async (request: FastifyRequest<{ Params: { id: string }; Querystring: { feeWaiver?: string } }>, reply: FastifyReply) => {
    const { user } = request
    const instanceId = Number(request.params.id)

    if (isNaN(instanceId)) {
      return reply.code(400).send(apiError(ErrorCode.INVALID_ID))
    }

    const instance = await prisma.instance.findUnique({
      where: { id: instanceId },
      include: {
        host: { select: { id: true, name: true, userId: true } },
        package: { select: { allowInstanceDeletion: true, destroyTrafficLimit: true } },
        packagePlan: { select: { id: true, name: true } }
      }
    })

    if (!instance) {
      return reply.code(404).send(apiError(ErrorCode.INSTANCE_NOT_FOUND))
    }

    // 只有实例所有者可以销毁
    if (instance.userId !== user.id) {
      return reply.code(403).send(apiError(ErrorCode.FORBIDDEN))
    }

    // 检查实例状态
    if (instance.status === 'deleted') {
      return reply.code(400).send({ error: '实例已删除', canDestroy: false })
    }
    if (instance.status === 'deleting') {
      return reply.code(409).send({ error: '实例正在销毁', code: 'INSTANCE_DESTROY_IN_PROGRESS', canDestroy: false })
    }

    if (instance.status === 'creating') {
      return reply.code(400).send({ error: '实例正在创建中，无法销毁', canDestroy: false })
    }

    if (instance.status === 'suspended' && !canUserDestroyExpiredSuspendedPaidInstance(instance)) {
      return reply.code(400).send({ error: '实例已被封停，无法销毁，请先联系管理员解封', canDestroy: false })
    }

    // 异常实例免手续费
    const isErrorState = instance.status === 'error'
    const feeWaiver = request.query.feeWaiver === 'error' && isErrorState

    // 免费实例检查
    const isFreeInstance = db.isFreeInstance(instance)

    // 查询用户销毁记录（仅付费实例销毁计入）
    const destroyRecords = await prisma.userDestroyRecord.findMany({
      where: { userId: user.id },
      orderBy: { destroyedAt: 'desc' }
    })

    // 检查是否首次销毁
    let isFirstTime = destroyRecords.length === 0

    // 计算剩余价值和退款金额
    let remainingValue = 0
    let feeAmount = 0
    let refundAmount = 0
    let remainingDays = 0
    let maxRefundable = 0
    let refundableValue = 0
    let currentFeeRate = feeWaiver ? 0 : calculateFeeRate(destroyRecords.length)

    if (!isFreeInstance && instance.expiresAt && instance.billingPrice && instance.billingCycle) {
      const refundQuote = await db.calculateInstanceRemainingRefundQuote({
        id: instanceId,
        billingPrice: instance.billingPrice,
        billingCycle: instance.billingCycle,
        expiresAt: instance.expiresAt,
        packagePlanId: instance.packagePlanId
      })

      if (refundQuote.isPaid) {
        remainingDays = refundQuote.remainingDays
        remainingValue = refundQuote.remainingValue
        refundableValue = refundQuote.refundableValue
        maxRefundable = refundQuote.maxRefundable

        // 计算手续费（首次免手续费，后续固定 10%；异常实例免手续费）
        currentFeeRate = feeWaiver ? 0 : calculateFeeRate(destroyRecords.length)
        if (!isFirstTime && !feeWaiver) {
          feeAmount = Number((refundableValue * currentFeeRate).toFixed(2))
        }

        // 实际退款金额
        refundAmount = Number((refundableValue - feeAmount).toFixed(2))
      }
    }

    // 判断是否可以销毁（已移除冷却期限制，付费实例随时可销毁）
    let canDestroy = isInstanceDeletionAllowed(instance)
    let cannotDestroyReason = canDestroy ? '' : DESTROY_DISABLED_REASON

    if (canDestroy) {
      const blockingTask = await getDestroyBlockingTask(instanceId)
      if (blockingTask) {
        canDestroy = false
        cannotDestroyReason = blockingTask.reason
      }
    }

    if (
      canDestroy
      && !isFreeInstance
      && !canUserDestroyExpiredSuspendedPaidInstance(instance)
      && exceedsPaidDestroyTrafficLimit(getDestroyTrafficUsage(instance), getDestroyTrafficLimit(instance))
    ) {
      canDestroy = false
      cannotDestroyReason = getDestroyTrafficLimitReason(getDestroyTrafficLimit(instance))
    }

    return {
      canDestroy,
      cannotDestroyReason,
      isFreeInstance,
      isFirstTime,
      isErrorState,
      feeWaiverEligible: isErrorState,
      // 销毁规则
      rules: {
        feeRate: feeWaiver ? 0 : DESTROY_RULES.FEE_RATE,
        trafficLimitBytes: getDestroyTrafficLimit(instance).toString(),
        trafficLimitLabel: formatTrafficLimit(getDestroyTrafficLimit(instance))
      },
      // 退款预览
      refund: {
        remainingDays,
        remainingValue,
        feeRate: currentFeeRate,
        feeAmount,
        refundAmount,
        destroyCount: destroyRecords.length,  // 已销毁次数
        maxRefundable  // 退款上限（基于历史账单）
      },
      // 实例信息
      instance: {
        id: instance.id,
        name: instance.name,
        hostName: instance.host.name,
        planName: instance.packagePlan?.name || null
      }
    }
  })

  // ==================== 执行销毁 ====================
  // POST /api/instances/:id/destroy
  fastify.post<{ Params: { id: string }; Querystring: { feeWaiver?: string } }>('/:id/destroy', {
    onRequest: [fastify.authenticate],
    config: { rateLimit: { max: 5, timeWindow: '1 minute' } }
  }, async (request: FastifyRequest<{ Params: { id: string }; Querystring: { feeWaiver?: string } }>, reply: FastifyReply) => {
    const { user } = request
    const instanceId = Number(request.params.id)

    if (isNaN(instanceId)) {
      return reply.code(400).send(apiError(ErrorCode.INVALID_ID))
    }

    // 获取实例信息
    const instance = await prisma.instance.findUnique({
      where: { id: instanceId },
      include: {
        user: { select: { id: true, username: true, balance: true, email: true } },
        host: { select: { id: true, name: true, userId: true, status: true } },
        package: { select: { allowInstanceDeletion: true, destroyTrafficLimit: true } }
      }
    })

    if (!instance) {
      return reply.code(404).send(apiError(ErrorCode.INSTANCE_NOT_FOUND))
    }

    // 只有实例所有者可以销毁
    if (instance.userId !== user.id) {
      return reply.code(403).send(apiError(ErrorCode.FORBIDDEN))
    }

    if (!isInstanceDeletionAllowed(instance)) {
      return reply.code(403).send(apiError(ErrorCode.INSTANCE_DELETION_NOT_ALLOWED, DESTROY_DISABLED_REASON))
    }

    // 检查实例状态
    if (instance.status === 'deleted') {
      return reply.code(400).send({ error: '实例已删除' })
    }
    if (instance.status === 'deleting') {
      return reply.code(409).send({ error: '实例正在销毁', code: 'INSTANCE_DESTROY_IN_PROGRESS' })
    }

    if (instance.status === 'creating') {
      return reply.code(400).send({ error: '实例正在创建中，无法销毁' })
    }

    if (instance.status === 'suspended' && !canUserDestroyExpiredSuspendedPaidInstance(instance)) {
      return reply.code(400).send({ error: '实例已被封停，无法销毁，请先联系管理员解封' })
    }

    const blockingTask = await getDestroyBlockingTask(instanceId)
    if (blockingTask) {
      return reply.code(409).send({
        error: blockingTask.reason,
        code: blockingTask.code
      })
    }

    // 免费实例检查
    const isFreeInstance = db.isFreeInstance(instance)

    if (isFreeInstance) {
      const result = await destroyFreeInstanceDurably(user, instance, request.log)
      if (result === 'conflict') return reply.code(409).send({ error: '实例正在销毁或已删除', code: 'INSTANCE_DESTROY_IN_PROGRESS' })
      if (result === 'pending') return reply.code(202).send({ success: false, pending: true, status: 'deleting', message: 'Instance destruction pending', isFreeInstance: true })
      const previousDestroyCount = await prisma.userDestroyRecord.count({ where: { userId: user.id } })
      return { success: true, message: '实例已销毁', refundAmount: 0, feeAmount: 0, isFirstTime: previousDestroyCount === 0, isFreeInstance: true }
    }

    // Preserve the request without deleting or refunding until final traffic
    // is established from trustworthy evidence, even when the host is online.
    if (!canUserDestroyExpiredSuspendedPaidInstance(instance)
      && exceedsPaidDestroyTrafficLimit(getDestroyTrafficUsage(instance), getDestroyTrafficLimit(instance))) {
      return reply.code(400).send(apiError(ErrorCode.INSTANCE_DESTROY_TRAFFIC_LIMIT_EXCEEDED, getDestroyTrafficLimitReason(getDestroyTrafficLimit(instance))))
    }
    const feeWaiver = request.query.feeWaiver === 'error' && instance.status === 'error'
    if (!await queueOfflinePaidDestroy(instance, user, feeWaiver)) {
      return reply.code(409).send({ error: '实例正在操作、销毁或创建清理中', code: 'INSTANCE_DESTROY_IN_PROGRESS' })
    }
    return reply.code(202).send({ success: false, pending: true, status: 'deleting', message: 'Instance destruction pending reconciliation', isFreeInstance: false })

  })
}
