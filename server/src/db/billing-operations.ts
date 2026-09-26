/**
 * 计费业务逻辑操作
 * 处理付费实例开通、续费、升降级等核心计费业务
 */

import { prisma } from './prisma.js'
import { Prisma, type Instance, type PackagePlan } from '@prisma/client'
import { getInstanceAffBinding, isAffRebateEnabled, processAffCommission, reverseAffCommissionForInstance } from './aff.js'
import {
  countDiscountedMonthsForInstance,
  getInstancePurchaseCoupon,
  releaseOfficialCouponUsageByInstance,
  reserveOfficialCouponUsage,
  validateOfficialCoupon
} from './official-coupons.js'
import {
  calculateDiscountAmountForMonths,
  getRemainingDiscountedMonths,
  getDiscountedMonthsForRenewal
} from '../lib/official-coupon-rules.js'
import { getInstanceBillingLineageIds } from './billing-records.js'
import { matchCouponUsagesToBillingRecords } from '../lib/billing-coupon-match.js'
import {
  calculateDiscountAmount,
  calculateDiscountedPrice,
  calculateRemainingDays,
  calculateRemainingDaysPrecise,
  calculatePriceDiff,
  calculateRemainingValue,
  calculatePlanChangeDetails,
  addMonths as calcAddMonths
} from '../lib/billing-calc.js'
import { shouldSyncInstanceSwapSizeWithPlan } from '../lib/instance-swap.js'
import { resolveInstanceTrafficLimitForHost } from '../lib/traffic-multiplier.js'
import { calculateInstanceTrafficStatus, calculatePlanChangeSettledBytes } from '../services/traffic-utils.js'
import { normalizePlanTrafficLimitSpeed } from '../services/traffic-bandwidth.js'
import {
  HOSTING_BALANCE_LOG_LOCK_NAMESPACE,
  INSTANCE_OPERATION_LOCK_NAMESPACE,
  USER_BALANCE_LOCK_NAMESPACE,
  USER_DESTROY_BILLING_LOCK_NAMESPACE,
  advisoryTransactionLock,
  tryAdvisoryTransactionLock
} from './advisory-locks.js'
import { decrementHostResourceCounters } from './quota-operations.js'

// ==================== 类型定义 ====================

export interface CreateBillingResult {
  plan: PackagePlan
  price: number
  billingCycle: number
  setupFee: number
  totalPrice: number
  expiresAt: Date
}

export interface RenewBillingResult {
  monthlyPrice: number
  months: number
  amount: number
  newExpiresAt: Date
}

export interface InstanceRefundResult {
  remainingDays: number
  remainingValue: number
  refundableValue: number
  refundAmount: number
  maxRefundable: number
  discountRate: number
  isPaid: boolean
}

export interface InstanceRemainingRefundQuote {
  remainingDays: number
  remainingValue: number
  refundableValue: number
  maxRefundable: number
  isPaid: boolean
}

export interface HostingBalanceDeductionResult {
  hostOwnerId: number
  deductedAmount: number
  fromFrozen: number
  fromAvailable: number
  fromBalance: number
}

export interface ChangePlanPreviewResult {
  oldPlan: PackagePlan
  newPlan: PackagePlan
  remainingDays: number
  // 计算详情（供前端展示）
  oldDailyPrice: number        // 原方案日价（元）
  newDailyPrice: number        // 新方案日价（元）
  remainingValue: number       // 剩余价值（元）
  newPlanCost: number          // 新方案费用（元）
  // 折扣信息
  discountRate: number         // 折扣率（0-1）
  discountAmount: number       // 折扣金额（元）
  // 最终费用
  priceDiff: number            // 差价（元，正数=补交，负数=退款）
  isUpgrade: boolean           // 是否升级（按日价判断）
  newExpiresAt: Date           // 新到期时间（保持不变）
  newConfig: { cpu: number; memory: number; disk: number }
  // 冷却期信息
  canChange: boolean           // 是否可以变更
  cannotChangeReason?: string  // 不能变更的原因
}

export interface PlanChangeOptions {
  preciseRemainingDays?: boolean
  minRemainingDays?: number | null
}

export interface InstancePriceAdjustmentQuote {
  oldPrice: number
  newPrice: number
  billingCycle: number
  remainingDays: number
  discountRate: number
  priceDiff: number
}

// ==================== 费用计算函数 ====================

/**
 * 计算开通费用
 * 注意：数据库中 price 存储的是分（cents），需要除以100转成元
 * 开通费已废弃，固定为0
 */
export function calculateCreateBilling(plan: PackagePlan): CreateBillingResult {
  const price = Number(plan.price) / 100  // 分转元
  const totalPrice = price  // 不再计算开通费

  // 计算到期时间（根据计费周期）
  const expiresAt = addMonths(new Date(), plan.billingCycle)

  return {
    plan,
    price,
    billingCycle: plan.billingCycle,
    setupFee: 0,  // 开通费已废弃
    totalPrice,
    expiresAt
  }
}

/**
 * 计算月价（将方案价格折算为月价）
 */
export function calculateMonthlyPrice(instance: { billingPrice: any; billingCycle: number | null }): number {
  const price = Number(instance.billingPrice) || 0
  const cycle = Math.max(instance.billingCycle || 1, 1) // 防止除零
  return price / cycle
}

/**
 * 查询实例的最大可退款金额（基于历史账单）
 * maxRefundable = 历史总消费 - 历史已退
 * lastPaymentAmount = 最近一次付款金额（用于按时间比例退款）
 *
 * @param instanceId 实例 ID
 * @returns { maxRefundable, lastPaymentAmount }
 */
type BillingDbClient = Prisma.TransactionClient | typeof prisma

async function getMaxRefundableForClient(
  client: BillingDbClient,
  instanceId: number
): Promise<{ maxRefundable: number; lastPaymentAmount: number }> {
  const billingLineageInstanceIds = await getInstanceBillingLineageIds(instanceId, client)
  const instanceIds = billingLineageInstanceIds.length > 0 ? billingLineageInstanceIds : [instanceId]

  const [totalConsumed, refundRecords, lastPayment] = await Promise.all([
    client.instanceBillingRecord.aggregate({
      where: {
        instanceId: { in: instanceIds },
        type: { in: ['newPurchase', 'renew', 'upgrade'] },
        amount: { gt: 0 }
      },
      _sum: { amount: true }
    }),
    client.instanceBillingRecord.findMany({
      where: {
        instanceId: { in: instanceIds },
        type: 'refund'
      },
      select: { amount: true }
    }),
    client.instanceBillingRecord.findFirst({
      where: {
        instanceId: { in: instanceIds },
        // 仅查询 newPurchase/renew（upgrade 记录的 amount 是差价，不是完整周期金额）
        type: { in: ['newPurchase', 'renew'] },
        amount: { gt: 0 }
      },
      orderBy: { createdAt: 'desc' },
      select: { amount: true }
    })
  ])

  const consumedAmount = totalConsumed._sum?.amount !== null && totalConsumed._sum?.amount !== undefined
    ? parseFloat(String(totalConsumed._sum.amount))
    : 0
  const refundedAmount = refundRecords.reduce((sum, record) => sum + Math.abs(Number(record.amount)), 0)
  const lastPaymentAmount = lastPayment?.amount !== null && lastPayment?.amount !== undefined
    ? parseFloat(String(lastPayment.amount))
    : 0

  return {
    maxRefundable: roundCurrency(Math.max(0, consumedAmount - refundedAmount)),
    lastPaymentAmount
  }
}

export async function getMaxRefundable(instanceId: number): Promise<{ maxRefundable: number; lastPaymentAmount: number }> {
  return getMaxRefundableForClient(prisma, instanceId)
}

export async function getMaxRefundableInTransaction(
  tx: Prisma.TransactionClient,
  instanceId: number
): Promise<number> {
  const result = await getMaxRefundableForClient(tx, instanceId)
  return result.maxRefundable
}

function roundCurrency(value: number): number {
  return Number(value.toFixed(2))
}

export interface UserDestroyBillingSettlementParams {
  requestUserId: number
  instance: {
    id: number
    userId: number
    hostId: number
    name: string
  }
  refundableValue: number
  feeWaiver: boolean
}

export interface PrivilegedDeletionBillingSettlementParams {
  instance: {
    id: number
    userId: number
    hostId: number
    name: string
  }
  requestedRefundAmount: number
  remark: string
}

function clearDeletionBillingStateData() {
  return {
    deletionBillingPending: false,
    deletionRemoteDeleted: true,
    deletionBillingMode: null,
    deletionRefundableValue: null,
    deletionFeeWaiver: false
  }
}

interface BillingValueBreakdown {
  hasPositiveBillingRecords: boolean
  totalUserValue: number
  totalHostedValue: number
  remainingUserValue: number
  remainingHostedValue: number
}

/**
 * 计算计费血缘的净价值。
 *
 * 官方优惠券的用户账单是折后价，但托管收入按原价入账；退款时不能
 * 直接拿用户退款金额扣托管余额，否则优惠差额会永久留在托管主账户。
 * 先把历史 refund 按账单时间顺序冲销，再计算剩余服务价值，也能避免
 * 降级/管理员部分退款后再次销毁实例时重复退款。
 */
async function getBillingValueBreakdownForClient(
  client: BillingDbClient,
  instanceId: number
): Promise<BillingValueBreakdown> {
  const lineageInstanceIds = await getInstanceBillingLineageIds(instanceId, client)
  const instanceIds = lineageInstanceIds.length > 0 ? lineageInstanceIds : [instanceId]
  const [billingRecords, refundRecords, couponUsages] = await Promise.all([
    client.instanceBillingRecord.findMany({
      where: {
        instanceId: { in: instanceIds },
        type: { in: ['newPurchase', 'renew', 'upgrade'] },
        amount: { gt: 0 }
      },
      select: {
        type: true,
        amount: true,
        periodStart: true,
        periodEnd: true,
        createdAt: true
      },
      orderBy: [{ periodStart: 'asc' }, { createdAt: 'asc' }]
    }),
    client.instanceBillingRecord.findMany({
      where: {
        instanceId: { in: instanceIds },
        type: 'refund',
        amount: { lt: 0 }
      },
      select: { amount: true },
      orderBy: { createdAt: 'asc' }
    }),
    client.officialCouponUsage.findMany({
      where: { instanceId: { in: instanceIds } },
      select: {
        id: true,
        type: true,
        originalPrice: true,
        discountAmount: true,
        createdAt: true
      },
      orderBy: [{ createdAt: 'asc' }, { id: 'asc' }]
    })
  ])

  // 续费可在券停用期间按原价支付；仅按顺序配对会把之后的优惠误配给原价账单。
  const usageMatches = matchCouponUsagesToBillingRecords(
    billingRecords.map(record => ({
      type: record.type,
      amount: Number(record.amount),
      createdAt: record.createdAt
    })),
    couponUsages.map(usage => ({
      type: usage.type,
      originalPrice: Number(usage.originalPrice),
      discountAmount: Number(usage.discountAmount),
      createdAt: usage.createdAt
    }))
  )

  const values = billingRecords.map((record, recordIndex) => {
    const rawUserAmount = Number(record.amount)
    const userAmount = Number.isFinite(rawUserAmount) ? Math.max(0, rawUserAmount) : 0
    const usageIndex = usageMatches.get(recordIndex)
    const couponUsage = usageIndex === undefined ? undefined : couponUsages[usageIndex]
    const originalPrice = couponUsage ? Number(couponUsage.originalPrice) : userAmount
    const hostedAmount = Number.isFinite(originalPrice) && originalPrice > 0 ? originalPrice : userAmount

    return {
      userAmount,
      hostedAmount,
      netUserAmount: userAmount,
      netHostedAmount: hostedAmount,
      periodStart: new Date(record.periodStart),
      periodEnd: new Date(record.periodEnd)
    }
  })

  // Refund records do not carry a source billing-record id. FIFO allocation is
  // deterministic and matches the existing billing model's chronological
  // purchase/renewal periods; hosted value is reduced in the same ratio as
  // the user's paid value, including official-coupon original-price subsidy.
  let remainingRefund = refundRecords.reduce((sum, record) => {
    const amount = Math.abs(Number(record.amount))
    return Number.isFinite(amount) ? sum + amount : sum
  }, 0)
  for (const value of values) {
    if (remainingRefund <= 0) break
    const refundedUserAmount = Math.min(value.netUserAmount, remainingRefund)
    value.netUserAmount = Math.max(0, value.netUserAmount - refundedUserAmount)
    value.netHostedAmount = value.userAmount > 0
      ? value.hostedAmount * (value.netUserAmount / value.userAmount)
      : 0
    remainingRefund -= refundedUserAmount
  }

  let totalUserValue = 0
  let totalHostedValue = 0
  let remainingUserValue = 0
  let remainingHostedValue = 0
  const now = new Date()

  for (const value of values) {
    totalUserValue += value.netUserAmount
    totalHostedValue += value.netHostedAmount

    const totalMs = value.periodEnd.getTime() - value.periodStart.getTime()
    if (totalMs <= 0 || value.periodEnd <= now) continue

    const remainingRatio = Math.min(
      Math.max(value.periodEnd.getTime() - now.getTime(), 0) / totalMs,
      1
    )
    remainingUserValue += value.netUserAmount * remainingRatio
    remainingHostedValue += value.netHostedAmount * remainingRatio
  }

  return {
    hasPositiveBillingRecords: values.length > 0,
    totalUserValue: roundCurrency(totalUserValue),
    totalHostedValue: roundCurrency(totalHostedValue),
    remainingUserValue: roundCurrency(remainingUserValue),
    remainingHostedValue: roundCurrency(remainingHostedValue)
  }
}

/**
 * 计算托管节点应该回收的退款收入。
 * `allowHistorical` 用于管理员全额退款：即使服务期已过，也要按
 * 历史托管实收价回收；用户自助销毁只允许按当前未使用价值回收。
 */
async function calculateHostedRefundAmountForClient(
  client: BillingDbClient,
  instanceId: number,
  requestedUserRefund: number,
  options: { allowHistorical?: boolean } = {}
): Promise<number> {
  const requestedAmount = Number(requestedUserRefund)
  if (!Number.isFinite(requestedAmount) || requestedAmount <= 0) return 0

  const breakdown = await getBillingValueBreakdownForClient(client, instanceId)
  if (!breakdown.hasPositiveBillingRecords) return roundCurrency(requestedAmount)

  const allowHistorical = options.allowHistorical !== false
  const useHistoricalValue = allowHistorical
    && (breakdown.remainingUserValue <= 0 || requestedAmount > breakdown.remainingUserValue)
  const baseUserValue = useHistoricalValue ? breakdown.totalUserValue : breakdown.remainingUserValue
  const baseHostedValue = useHistoricalValue ? breakdown.totalHostedValue : breakdown.remainingHostedValue
  if (baseUserValue <= 0 || baseHostedValue <= 0) return 0

  const refundRatio = Math.min(Math.max(requestedAmount / baseUserValue, 0), 1)
  return roundCurrency(baseHostedValue * refundRatio)
}

export async function getHostedRefundAmountInTransaction(
  tx: Prisma.TransactionClient,
  instanceId: number,
  requestedUserRefund: number,
  options: { allowHistorical?: boolean } = {}
): Promise<number> {
  return calculateHostedRefundAmountForClient(tx, instanceId, requestedUserRefund, options)
}

/**
 * Settles a user-initiated deletion refund after Incus has been confirmed
 * absent. The unique UserDestroyRecord and refund billing record make this
 * operation safe to retry after a process/database failure.
 */
export async function settleUserDestroyBilling(
  params: UserDestroyBillingSettlementParams
): Promise<{ refundAmount: number; feeAmount: number; isFirstTime: boolean }> {
  const { requestUserId, instance, feeWaiver } = params

  return prisma.$transaction(async tx => {
    await advisoryTransactionLock(tx, INSTANCE_OPERATION_LOCK_NAMESPACE, instance.id)
    await advisoryTransactionLock(tx, USER_DESTROY_BILLING_LOCK_NAMESPACE, requestUserId)
    await advisoryTransactionLock(tx, USER_BALANCE_LOCK_NAMESPACE, instance.userId)

    const deletionState = await tx.instance.findUnique({
      where: { id: instance.id },
      select: { deletionRemoteDeleted: true }
    })
    if (!deletionState?.deletionRemoteDeleted) {
      throw new Error('REMOTE_DELETION_NOT_CONFIRMED')
    }

    const existingDestroy = await tx.userDestroyRecord.findUnique({
      where: { instanceId: instance.id }
    })
    if (existingDestroy) {
      await tx.instance.update({
        where: { id: instance.id },
        data: clearDeletionBillingStateData()
      })
      return {
        refundAmount: Number(existingDestroy.refundAmount),
        feeAmount: Number(existingDestroy.feeAmount),
        isFirstTime: existingDestroy.isFirstTime
      }
    }

    const destroyCount = await tx.userDestroyRecord.count({
      where: { userId: requestUserId }
    })
    const isFirstTime = destroyCount === 0
    const maxRefundable = await getMaxRefundableInTransaction(tx, instance.id)
    const refundableValue = roundCurrency(Math.min(Math.max(0, params.refundableValue), maxRefundable))
    const feeAmount = !feeWaiver && !isFirstTime
      ? roundCurrency(refundableValue * 0.10)
      : 0
    const refundAmount = roundCurrency(Math.max(0, refundableValue - feeAmount))
    const hostedRefundAmount = refundAmount > 0
      // The destruction fee is retained by the platform, so only the amount
      // actually returned to the user may be recovered from the host owner.
      ? await calculateHostedRefundAmountForClient(tx, instance.id, refundAmount, { allowHistorical: false })
      : 0

    if (refundAmount > 0) {
      const currentUser = await tx.user.findUnique({
        where: { id: instance.userId },
        select: { balance: true }
      })
      if (!currentUser) throw new Error(`User ${instance.userId} not found during instance destroy refund`)

      const oldBalance = Number(currentUser.balance)
      const newBalance = roundCurrency(oldBalance + refundAmount)
      await tx.user.update({
        where: { id: instance.userId },
        data: { balance: { increment: refundAmount } }
      })

      const balanceLog = await tx.balanceLog.create({
        data: {
          userId: instance.userId,
          type: 'refund',
          amount: refundAmount,
          balanceBefore: oldBalance,
          balanceAfter: newBalance,
          instanceId: instance.id,
          remark: `用户销毁实例退款：${instance.name}${feeWaiver ? '（异常实例免手续费）' : feeAmount > 0 ? `（手续费 ¥${feeAmount.toFixed(2)}）` : '（首次销毁免手续费）'}`
        }
      })

      await tx.instanceBillingRecord.create({
        data: {
          instanceId: instance.id,
          userId: instance.userId,
          type: 'refund',
          amount: -refundAmount,
          months: 0,
          periodStart: new Date(),
          periodEnd: new Date(),
          balanceLogId: balanceLog.id,
          remark: `用户销毁实例退款${feeWaiver ? '（异常实例免手续费）' : feeAmount > 0 ? `（手续费 ¥${feeAmount.toFixed(2)}）` : '（首次销毁免手续费）'}`
        }
      })

      await deductHostingBalance(
        instance.hostId,
        hostedRefundAmount,
        instance.id,
        `用户销毁托管实例退款扣除：${instance.name}`,
        tx
      )
    }

    await tx.userDestroyRecord.create({
      data: {
        userId: requestUserId,
        hostId: instance.hostId,
        instanceId: instance.id,
        instanceName: instance.name,
        refundAmount,
        feeAmount,
        isFirstTime
      }
    })

    await tx.instance.update({
      where: { id: instance.id },
      data: clearDeletionBillingStateData()
    })

    return { refundAmount, feeAmount, isFirstTime }
  })
}

/**
 * Settles a host/admin deletion refund. The amount is capped again inside
 * the instance lock so a manual refund cannot race this operation into a
 * double refund. It is also idempotent because the refund record consumes
 * the remaining refundable amount.
 */
export async function settlePrivilegedDeletionBilling(
  params: PrivilegedDeletionBillingSettlementParams
): Promise<number> {
  const { instance } = params

  return prisma.$transaction(async tx => {
    await advisoryTransactionLock(tx, INSTANCE_OPERATION_LOCK_NAMESPACE, instance.id)
    await advisoryTransactionLock(tx, USER_BALANCE_LOCK_NAMESPACE, instance.userId)

    const deletionState = await tx.instance.findUnique({
      where: { id: instance.id },
      select: { deletionRemoteDeleted: true }
    })
    if (!deletionState?.deletionRemoteDeleted) {
      throw new Error('REMOTE_DELETION_NOT_CONFIRMED')
    }

    const maxRefundable = await getMaxRefundableInTransaction(tx, instance.id)
    const refundAmount = roundCurrency(Math.min(Math.max(0, params.requestedRefundAmount), maxRefundable))
    const hostedRefundAmount = refundAmount > 0
      ? await calculateHostedRefundAmountForClient(tx, instance.id, refundAmount)
      : 0

    if (refundAmount > 0) {
      const currentUser = await tx.user.findUnique({
        where: { id: instance.userId },
        select: { balance: true }
      })
      if (!currentUser) throw new Error(`User ${instance.userId} not found during privileged deletion refund`)

      const oldBalance = Number(currentUser.balance)
      const newBalance = roundCurrency(oldBalance + refundAmount)
      await tx.user.update({
        where: { id: instance.userId },
        data: { balance: { increment: refundAmount } }
      })

      const balanceLog = await tx.balanceLog.create({
        data: {
          userId: instance.userId,
          type: 'refund',
          amount: refundAmount,
          balanceBefore: oldBalance,
          balanceAfter: newBalance,
          instanceId: instance.id,
          remark: params.remark
        }
      })

      await tx.instanceBillingRecord.create({
        data: {
          instanceId: instance.id,
          userId: instance.userId,
          type: 'refund',
          amount: -refundAmount,
          months: 0,
          periodStart: new Date(),
          periodEnd: new Date(),
          balanceLogId: balanceLog.id,
          remark: params.remark
        }
      })

      await deductHostingBalance(
        instance.hostId,
        hostedRefundAmount,
        instance.id,
        `删除托管实例退款扣除：${instance.name}`,
        tx
      )
    }

    await tx.instance.update({
      where: { id: instance.id },
      data: clearDeletionBillingStateData()
    })

    return refundAmount
  })
}

/**
 * Completes the non-refund billing leg of an hourly-instance deletion.
 *
 * Hourly billing closes its account and releases prepaid balance in its own
 * serializable transaction. The deletion marker is finalized separately so a
 * crash between those two commits can be retried safely by the recovery job.
 */
export async function completeHourlyDeletionBilling(instanceId: number): Promise<void> {
  await prisma.$transaction(async tx => {
    await advisoryTransactionLock(tx, INSTANCE_OPERATION_LOCK_NAMESPACE, instanceId)

    const instance = await tx.instance.findUnique({
      where: { id: instanceId },
      select: {
        deletionBillingPending: true,
        deletionRemoteDeleted: true,
        deletionBillingMode: true
      }
    })

    if (!instance || !instance.deletionBillingPending) return
    if (!instance.deletionRemoteDeleted) {
      throw new Error('REMOTE_DELETION_NOT_CONFIRMED')
    }
    if (instance.deletionBillingMode !== 'hourly_close') {
      throw new Error('INVALID_HOURLY_DELETION_BILLING_MODE')
    }

    await tx.instance.update({
      where: { id: instanceId },
      data: clearDeletionBillingStateData()
    })
  })
}

export interface FailedProvisionSettlementResult {
  claimed: boolean
  refundAmount: number
}

export interface FailedProvisionResourceRollback {
  hostId: number
  cpu: number
  memory: number
  disk: number
  portCount?: number
}

/**
 * Claims a failed provision before any external cleanup is attempted.
 *
 * The row remains `creating` while Incus is being cleaned up. That makes the
 * instance non-retryable and prevents the success path from resurrecting it,
 * while still ensuring that a cleanup failure cannot trigger a refund.
 */
export async function claimCreatingInstanceForCleanup(
  instanceId: number,
  options: { reclaimPendingBefore?: Date } = {}
): Promise<boolean> {
  return prisma.$transaction(async tx => {
    await advisoryTransactionLock(tx, INSTANCE_OPERATION_LOCK_NAMESPACE, instanceId)

    const cleanupState: Prisma.InstanceWhereInput = options.reclaimPendingBefore
      ? {
          OR: [
            { provisioningCleanupPending: false },
            {
              provisioningCleanupPending: true,
              updatedAt: { lt: options.reclaimPendingBefore }
            }
          ]
        }
      : { provisioningCleanupPending: false }

    const claimed = await tx.instance.updateMany({
      where: {
        id: instanceId,
        status: 'creating',
        ...cleanupState
      },
      data: {
        provisioningCleanupPending: true,
        version: { increment: 1 },
        updatedAt: new Date()
      }
    })

    return claimed.count === 1
  })
}

/**
 * Reconcile a timed-out provision that did in fact finish on Incus. This
 * clears the cleanup claim without touching the charge, coupon usage, or
 * host reservations. The same instance lock as the failure path prevents a
 * timeout worker and the success path from settling the row in opposite ways.
 */
export async function markCreatingInstanceProvisioned(
  instanceId: number,
  status: 'running' | 'stopped'
): Promise<boolean> {
  return prisma.$transaction(async tx => {
    await advisoryTransactionLock(tx, INSTANCE_OPERATION_LOCK_NAMESPACE, instanceId)

    const instance = await tx.instance.findUnique({
      where: { id: instanceId },
      select: { status: true }
    })

    if (!instance) return false
    if (instance.status === 'running' || instance.status === 'stopped') return true
    if (instance.status !== 'creating') return false

    await tx.instance.update({
      where: { id: instanceId },
      data: {
        status,
        provisioningCleanupPending: false,
        version: { increment: 1 }
      }
    })

    return true
  })
}

/**
 * Atomically marks a retrying provision as failed and releases its reservation.
 *
 * Retry failures do not create a new charge, so they must not reuse the refund
 * path above. Keeping the status claim and resource release in one transaction
 * also prevents the timeout worker from releasing the same reservation twice.
 */
export async function failCreatingInstanceAndRollbackResources(
  instanceId: number,
  resourceRollback?: FailedProvisionResourceRollback
): Promise<boolean> {
  return prisma.$transaction(async (tx) => {
    await advisoryTransactionLock(tx, INSTANCE_OPERATION_LOCK_NAMESPACE, instanceId)

    const claimed = await tx.instance.updateMany({
      where: { id: instanceId, status: 'creating' },
      data: { status: 'error' }
    })

    if (claimed.count === 0) return false

    if (resourceRollback) {
      await decrementHostResourceCounters(tx, resourceRollback)
    }

    return claimed.count === 1
  })
}

/**
 * Atomically settles a creating instance after its external resource has been
 * confirmed absent, marking it failed and fully reversing its charge.
 *
 * Callers must claim the instance with claimCreatingInstanceForCleanup() and
 * complete the Incus cleanup before calling this function. Requiring the
 * persistent cleanup flag means a network/API failure cannot accidentally
 * turn into a refund, and the state claim remains idempotent when the
 * provisioner and timeout scheduler race each other. Existing refund records
 * are subtracted so retries cannot refund the same purchase twice.
 */
export async function failCreatingInstanceAndRefund(
  instanceId: number,
  reason: string,
  resourceRollback?: FailedProvisionResourceRollback
): Promise<FailedProvisionSettlementResult> {
  return prisma.$transaction(async (tx) => {
    await advisoryTransactionLock(tx, INSTANCE_OPERATION_LOCK_NAMESPACE, instanceId)

    const claimed = await tx.instance.updateMany({
      where: {
        id: instanceId,
        status: 'creating',
        provisioningCleanupPending: true
      },
      data: {
        status: 'error',
        provisioningCleanupPending: false,
        version: { increment: 1 }
      }
    })

    if (claimed.count === 0) {
      return { claimed: false, refundAmount: 0 }
    }

    const instance = await tx.instance.findUnique({
      where: { id: instanceId },
      select: {
        id: true,
        name: true,
        userId: true,
        hostId: true,
        billingMode: true
      }
    })

    if (!instance) {
      throw new Error(`Instance ${instanceId} disappeared during failed provision settlement`)
    }

    if (resourceRollback) {
      await decrementHostResourceCounters(tx, resourceRollback)
    }

    if (instance.billingMode === 'hourly') {
      const account = await tx.hourlyBillingAccount.findUnique({ where: { instanceId } })
      const prepaid = new Prisma.Decimal(account?.prepaidBalance ?? 0)
      if (account && prepaid.gt(0)) {
        const user = await tx.user.findUnique({ where: { id: instance.userId }, select: { balance: true } })
        if (!user) throw new Error(`User ${instance.userId} not found during hourly provision refund`)
        const balanceBefore = new Prisma.Decimal(user.balance)
        const balanceAfter = balanceBefore.add(prepaid)
        await tx.user.update({
          where: { id: instance.userId },
          data: {
            balance: { increment: prepaid },
            hourlyReservedBalance: { decrement: prepaid }
          }
        })
        await tx.balanceLog.create({
          data: {
            userId: instance.userId,
            instanceId,
            type: 'hourly_release',
            amount: prepaid,
            balanceBefore,
            balanceAfter,
            remark: `按小时计费实例开通失败，退回冻结预付款：${instance.name}（${reason}）`
          }
        })
        await tx.hourlyBillingAccount.update({
          where: { id: account.id },
          data: { status: 'closed', prepaidBalance: 0, totalReleased: { increment: prepaid }, nextSettlementAt: null, version: { increment: 1 } }
        })
        return { claimed: true, refundAmount: prepaid.toNumber() }
      }
      if (account) {
        await tx.hourlyBillingAccount.update({ where: { id: account.id }, data: { status: 'closed', nextSettlementAt: null, version: { increment: 1 } } })
      }
      return { claimed: true, refundAmount: 0 }
    }

    const billingRecords = await tx.instanceBillingRecord.findMany({
      where: {
        instanceId,
        type: { in: ['newPurchase', 'refund'] }
      },
      select: { type: true, amount: true }
    })

    const chargedAmount = billingRecords
      .filter(record => record.type === 'newPurchase')
      .reduce((sum, record) => sum + Math.max(0, Number(record.amount)), 0)
    const refundedAmount = billingRecords
      .filter(record => record.type === 'refund')
      .reduce((sum, record) => sum + Math.abs(Number(record.amount)), 0)
    const refundAmount = roundCurrency(Math.max(0, chargedAmount - refundedAmount))

    // 开通失败即未成交：释放官方优惠券使用次数，使用户可以重新下单
    const releasedCoupon = await releaseOfficialCouponUsageByInstance(instanceId, tx)

    // 新购已经发放的 AFF 返利也必须随失败开通一起回滚，避免平台在
    // 用户收到全额退款后仍永久承担一笔推荐佣金。
    await reverseAffCommissionForInstance(instanceId, tx)

    if (refundAmount <= 0) {
      return { claimed: true, refundAmount: 0 }
    }

    const user = await tx.user.findUnique({
      where: { id: instance.userId },
      select: { balance: true }
    })
    if (!user) {
      throw new Error(`User ${instance.userId} not found during failed provision refund`)
    }

    const balanceBefore = Number(user.balance)
    const balanceAfter = roundCurrency(balanceBefore + refundAmount)
    await tx.user.update({
      where: { id: instance.userId },
      data: { balance: { increment: refundAmount } }
    })

    const balanceLog = await tx.balanceLog.create({
      data: {
        userId: instance.userId,
        type: 'refund',
        amount: refundAmount,
        balanceBefore,
        balanceAfter,
        instanceId,
        remark: `实例开通失败自动全额退款：${instance.name}（${reason}）`
      }
    })

    const now = new Date()
    await tx.instanceBillingRecord.create({
      data: {
        instanceId,
        userId: instance.userId,
        type: 'refund',
        amount: -refundAmount,
        months: 0,
        periodStart: now,
        periodEnd: now,
        balanceLogId: balanceLog.id,
        remark: `实例开通失败自动全额退款：${reason}`
      }
    })

    await deductHostingBalance(
      instance.hostId,
      // 官方优惠券的托管收入按原价记账，回退时同样按原价扣除，
      // 否则托管主会留下平台本应承担的折扣差额
      roundCurrency(refundAmount + (releasedCoupon?.discountAmount || 0)),
      instance.id,
      `实例开通失败退款扣除托管收入：${instance.name}`,
      tx
    )

    return { claimed: true, refundAmount }
  })
}

/**
 * 按账单记录计算实例的剩余价值退款报价
 *
 * 正向计费记录（newPurchase / renew / upgrade）各自对应独立的服务期区间，
 * 退款时应按这些区间的未消耗比例逐条计算，而不是仅依赖实例当前 billingPrice。
 * 这样升级补差价、后续续费、管理员延期等场景都能正确纳入剩余价值。
 */
export async function calculateInstanceRemainingRefundQuote(instance: {
  id: number
  billingPrice: any
  billingCycle: number | null
  expiresAt: Date | null
  packagePlanId: number | null
}, client: BillingDbClient = prisma): Promise<InstanceRemainingRefundQuote> {
  const isPaid = !!(instance.packagePlanId && instance.expiresAt && instance.billingPrice)

  if (!isPaid) {
    return {
      remainingDays: 0,
      remainingValue: 0,
      refundableValue: 0,
      maxRefundable: 0,
      isPaid: false
    }
  }

  const now = new Date()
  const expiresAt = new Date(instance.expiresAt!)

  if (expiresAt <= now) {
    return {
      remainingDays: 0,
      remainingValue: 0,
      refundableValue: 0,
      maxRefundable: 0,
      isPaid: true
    }
  }

  const remainingDays = calculateRemainingDays(expiresAt, now)
  const [maxRefundableInfo, billingValueBreakdown] = await Promise.all([
    getMaxRefundableForClient(client, instance.id),
    getBillingValueBreakdownForClient(client, instance.id)
  ])
  const { maxRefundable } = maxRefundableInfo

  let remainingValue = billingValueBreakdown.remainingUserValue

  // 兼容历史/异常数据：如果缺少正向计费记录，则回退到旧逻辑，
  // 避免老实例直接变成 0 退款。
  if (!billingValueBreakdown.hasPositiveBillingRecords && instance.billingPrice && instance.billingCycle) {
    let discountRate = 0
    const affBinding = await getInstanceAffBinding(instance.id, client)
    if (affBinding?.affCode?.enabled) {
      discountRate = Number(affBinding.affCode.discountRate) || 0
    }

    remainingValue = calculateRemainingValue(
      Number(instance.billingPrice),
      instance.billingCycle,
      remainingDays,
      discountRate
    )
  }

  const refundableValue = roundCurrency(Math.min(remainingValue, maxRefundable))

  return {
    remainingDays,
    remainingValue,
    refundableValue,
    maxRefundable,
    isPaid: true
  }
}

/**
 * 计算实例退款金额（用于节点所有者删除实例时）
 * 节点所有者删除时不收取手续费
 * 
 * @param instance 实例信息（需包含计费相关字段）
 * @returns 退款计算结果
 */
export async function calculateInstanceRefund(instance: {
  id: number
  billingPrice: any
  billingCycle: number | null
  expiresAt: Date | null
  packagePlanId: number | null
}): Promise<InstanceRefundResult> {
  const quote = await calculateInstanceRemainingRefundQuote(instance)

  return {
    remainingDays: quote.remainingDays,
    remainingValue: quote.remainingValue,
    refundableValue: quote.refundableValue,
    refundAmount: quote.refundableValue, // 节点所有者删除不收手续费
    maxRefundable: quote.maxRefundable,
    discountRate: 0,
    isPaid: quote.isPaid
  }
}

/**
 * 续费费用计算（支持任意月数）
 */
export function calculateRenewBilling(
  instance: { billingPrice: any; billingCycle: number | null; expiresAt: Date | null },
  months: number = 1
): RenewBillingResult {
  // 验证续费月数范围
  if (months < 1 || months > 24) {
    throw new Error('续费月数必须在 1-24 之间')
  }

  const monthlyPrice = calculateMonthlyPrice(instance)
  const amount = Number((monthlyPrice * months).toFixed(2)) // 保留两位小数

  // 从当前到期时间续期（如已过期则从现在开始）
  const now = new Date()
  const baseDate = instance.expiresAt && instance.expiresAt > now
    ? instance.expiresAt
    : now

  const newExpiresAt = addMonths(baseDate, months)

  return { monthlyPrice, months, amount, newExpiresAt }
}

// 周期天数常量和 getCycleDays 函数已移至公共模块 billing-calc.ts
// 从 ../lib/billing-calc.js 导入使用

/**
 * 计算升降级差价（带优惠码折扣和冷却期检查）
 * 使用公共模块 billing-calc.ts 的计算方法确保一致性
 * 
 * 计算公式：
 * 1. 原方案日价 = 原方案周期价格 / 原方案周期天数
 * 2. 新方案日价 = 新方案周期价格 / 新方案周期天数
 * 3. 剩余价值 = 原方案日价 × 剩余天数 × (1 - 折扣率)
 * 4. 新方案费用 = 新方案日价 × 剩余天数 × (1 - 折扣率)
 * 5. 差价 = 新方案费用 - 剩余价值
 */
export async function calculatePlanChange(
  instance: Instance,
  newPlan: PackagePlan,
  options: PlanChangeOptions = {}
): Promise<ChangePlanPreviewResult> {
  const oldPlanId = instance.packagePlanId
  if (!oldPlanId) {
    throw new Error('免费实例不支持升降级')
  }

  const oldPlan = await prisma.packagePlan.findUnique({
    where: { id: oldPlanId }
  })

  if (!oldPlan) {
    throw new Error('原方案不存在')
  }

  const expiresAt = instance.expiresAt!
  const preciseRemainingDays = options.preciseRemainingDays ?? true
  const minRemainingDays = options.minRemainingDays === undefined ? 15 : options.minRemainingDays

  // ========== 检查剩余天数 ==========
  let canChange = true
  let cannotChangeReason: string | undefined

  // 使用统一方法计算剩余时间；金额口径默认使用精确剩余天数
  const remainingDays = preciseRemainingDays
    ? calculateRemainingDaysPrecise(expiresAt)
    : calculateRemainingDays(expiresAt)

  if (minRemainingDays !== null && remainingDays < minRemainingDays) {
    canChange = false
    cannotChangeReason = 'remaining_days_insufficient' // 剩余天数不足
  }

  // ========== 获取 AFF 折扣率 ==========
  let discountRate = 0
  const affEnabled = await isAffRebateEnabled()
  const affBinding = affEnabled ? await getInstanceAffBinding(instance.id) : null
  if (affBinding) {
    discountRate = Number(affBinding.affCode.discountRate) || 0
  }

  // ========== 使用公共方法计算差价 ==========
  const oldCyclePrice = Number(instance.billingPrice) || 0 // 已是元
  const newCyclePrice = Number(newPlan.price) / 100 // 分转元

  // 使用公共方法计算详情
  const calcResult = calculatePlanChangeDetails(
    oldCyclePrice,
    instance.billingCycle || 1,
    newCyclePrice,
    newPlan.billingCycle,
    remainingDays,
    discountRate
  )
  const priceDiff = calcResult.priceDiff < 0
    ? -Math.min(
        Math.abs(calcResult.priceDiff),
        (await getMaxRefundable(instance.id)).maxRefundable
      )
    : calcResult.priceDiff

  return {
    oldPlan,
    newPlan,
    remainingDays,
    oldDailyPrice: calcResult.oldDailyPrice,
    newDailyPrice: calcResult.newDailyPrice,
    remainingValue: calcResult.remainingValue,
    newPlanCost: calcResult.newPlanCost,
    discountRate,
    discountAmount: calcResult.discountAmount,
    priceDiff,
    isUpgrade: calcResult.isUpgrade,
    newExpiresAt: expiresAt, // 到期时间保持不变
    newConfig: {
      cpu: newPlan.cpu,
      memory: newPlan.memory,
      disk: newPlan.disk
    },
    canChange,
    cannotChangeReason
  }
}

/**
 * 计算管理员调整实例续费价格时的差价结算报价
 * 统一使用精确剩余天数，避免与升级报价口径分叉。
 */
export async function calculateInstancePriceAdjustmentQuote(
  instance: {
    id: number
    billingPrice: any
    billingCycle: number | null
    expiresAt: Date | null
  },
  newPrice: number,
  settleBalance: boolean,
  tx?: Prisma.TransactionClient
): Promise<InstancePriceAdjustmentQuote> {
  const oldPrice = Number(instance.billingPrice) || 0
  const roundedNewPrice = roundCurrency(newPrice)
  const billingCycle = instance.billingCycle || 1

  let discountRate = 0
  const affEnabled = await isAffRebateEnabled()
  const affBinding = affEnabled ? await getInstanceAffBinding(instance.id, tx) : null
  if (affBinding?.affCode?.enabled) {
    discountRate = Number(affBinding.affCode.discountRate) || 0
  }

  let remainingDays = 0
  let priceDiff = 0

  if (settleBalance && instance.expiresAt) {
    remainingDays = calculateRemainingDaysPrecise(new Date(instance.expiresAt))
    if (remainingDays > 0) {
      priceDiff = calculatePriceDiff(
        oldPrice,
        billingCycle,
        roundedNewPrice,
        billingCycle,
        remainingDays,
        discountRate
      )
    }
  }

  return {
    oldPrice,
    newPrice: roundedNewPrice,
    billingCycle,
    remainingDays,
    discountRate,
    priceDiff
  }
}

/**
 * 续费价格预览（前端调用）
 */
export function previewRenewPrices(
  instance: { billingPrice: any; billingCycle: number | null; expiresAt: Date | null }
): Array<{ months: number; amount: number; expiresAt: Date }> {
  const options = [1, 3, 6, 12] // 常用续费选项
  return options.map(months => {
    const result = calculateRenewBilling(instance, months)
    return {
      months,
      amount: result.amount,
      expiresAt: result.newExpiresAt
    }
  })
}

// ==================== 续费优惠来源解析 ====================

export interface RenewalDiscountResolution {
  /** 最终生效的优惠来源；null 表示按原价续费 */
  source: 'official_coupon' | 'aff' | null
  /** 折扣率（0-1），无优惠时为 0 */
  discountRate: number
  /** 折扣金额（元） */
  discountAmount: number
  /** 折后应付金额（元） */
  finalAmount: number
  /** 官方优惠券剩余可折价月数；null 表示本次不受月数上限限制。 */
  discountedMonths: number | null
  /** 生效的 AFF 优惠码（source === 'aff' 时） */
  affCodeId: number | null
  affCodeCode: string | null
  /** 生效绑定是否为用户明确设置的覆盖（官方优惠券被 AFF 取代） */
  supersedesOfficialCoupon: boolean
  /** 生效的官方优惠券（source === 'official_coupon' 时） */
  officialCouponCode: string | null
  officialCouponName: string | null
}

export interface RenewalDiscountInstanceInput {
  id: number
  packageId: number | null
  packagePlanId: number | null
  userId: number
}

/**
 * 统一解析实例续费的优惠来源，至多返回一个生效来源。
 *
 * 优先级：用户明确覆盖的 AFF（supersedesOfficialCoupon）> 官方优惠券 > 普通 AFF 绑定。
 * 续费价格预览、手动/自动/批量续费、账单备注与 AFF 返利必须复用本函数，
 * 避免出现"前端显示使用 B，后端实际却使用官方券"的问题。
 */
export async function resolveInstanceRenewalDiscount(
  instance: RenewalDiscountInstanceInput,
  originalAmount: number,
  tx?: Prisma.TransactionClient,
  requestedMonths?: number
): Promise<RenewalDiscountResolution> {
  const resolution: RenewalDiscountResolution = {
    source: null,
    discountRate: 0,
    discountAmount: 0,
    finalAmount: originalAmount,
    discountedMonths: null,
    affCodeId: null,
    affCodeCode: null,
    supersedesOfficialCoupon: false,
    officialCouponCode: null,
    officialCouponName: null
  }

  const affEnabled = await isAffRebateEnabled()
  const affBinding = affEnabled ? await getInstanceAffBinding(instance.id, tx) : null

  // AFF 适用于当前方案：全局码任意方案可用，方案专有码必须匹配实例当前方案
  const affUsable = !!affBinding
    && affBinding.affCode.enabled
    && (affBinding.affCode.packagePlanId === null
      || (instance.packagePlanId !== null && affBinding.affCode.packagePlanId === instance.packagePlanId))
  // 用户明确绑定/更换的 AFF 覆盖官方优惠券的续费折扣
  const affOverridesOfficial = affUsable && affBinding!.supersedesOfficialCoupon

  const applyAffDiscount = (): void => {
    const discountRate = Number(affBinding!.affCode.discountRate) || 0
    resolution.source = 'aff'
    resolution.discountRate = discountRate
    resolution.discountAmount = calculateDiscountAmount(originalAmount, discountRate)
    resolution.finalAmount = calculateDiscountedPrice(originalAmount, discountRate)
    resolution.affCodeId = affBinding!.affCode.id
    resolution.affCodeCode = affBinding!.affCode.code
    resolution.supersedesOfficialCoupon = affBinding!.supersedesOfficialCoupon
  }

  const applyOfficialCouponDiscount = (
    discountRate: number,
    couponCode: string,
    couponName: string,
    discountedMonthsRemaining: number | null
  ): void => {
    resolution.source = 'official_coupon'
    resolution.discountRate = discountRate
    resolution.discountedMonths = discountedMonthsRemaining
    const effectiveDiscountedMonths = requestedMonths === undefined || discountedMonthsRemaining === null
      ? requestedMonths
      : Math.min(requestedMonths, discountedMonthsRemaining)
    resolution.discountAmount = requestedMonths === undefined
      ? calculateDiscountAmount(originalAmount, discountRate)
      : calculateDiscountAmountForMonths(
          originalAmount,
          requestedMonths,
          effectiveDiscountedMonths ?? 0,
          discountRate
        )
    resolution.finalAmount = Number((originalAmount - resolution.discountAmount).toFixed(2))
    resolution.officialCouponCode = couponCode
    resolution.officialCouponName = couponName
  }

  // 官方优惠券：只有使用官方券购买的实例才参与续期折扣；被用户覆盖的 AFF 压制时跳过
  let officialUsable = false
  let officialDiscountRate = 0
  let officialCouponCode: string | null = null
  let officialCouponName: string | null = null
  let officialDiscountedMonths: number | null = null

  if (!affOverridesOfficial && instance.packageId !== null) {
    const purchaseCoupon = await getInstancePurchaseCoupon(instance.id, tx)
    if (purchaseCoupon) {
      const { coupon } = purchaseCoupon
      const discountedMonthsUsed = await countDiscountedMonthsForInstance(coupon.id, instance.id, tx)
      if (getDiscountedMonthsForRenewal({
        renewalMode: coupon.renewalMode,
        discountedChargeLimit: coupon.discountedChargeLimit,
        discountedMonthsUsed,
        requestedMonths: requestedMonths ?? 1
      }) > 0) {
        const validation = await validateOfficialCoupon({
          code: coupon.code,
          packageId: instance.packageId,
          userId: instance.userId,
          client: tx,
          // 每用户/全站次数只约束首购，不阻断已取得资格的实例续费折扣
          checkUserLimit: false,
          checkTotalUsageLimit: false
        })
        if (validation.valid) {
          officialUsable = true
          officialDiscountRate = validation.discountRate
          officialCouponCode = coupon.code
          officialCouponName = coupon.name
          officialDiscountedMonths = getRemainingDiscountedMonths({
            renewalMode: coupon.renewalMode,
            discountedChargeLimit: coupon.discountedChargeLimit,
            discountedMonthsUsed
          })
        }
      }
    }
  }

  if (affOverridesOfficial) {
    applyAffDiscount()
  } else if (officialUsable) {
    applyOfficialCouponDiscount(
      officialDiscountRate,
      officialCouponCode!,
      officialCouponName!,
      officialDiscountedMonths
    )
  } else if (affUsable) {
    applyAffDiscount()
  }

  return resolution
}

// ==================== 业务操作函数 ====================

/**
 * 执行续费操作（带乐观锁并发控制）
 * 支持 AFF 优惠码折扣和返利
 */
export async function performRenewal(
  userId: number,
  instance: Instance,
  months: number
): Promise<{ newExpiresAt: Date; amount: number; balanceLogId: number; discountAmount?: number; hostingIncomeResult?: { hostOwnerId: number; hostName: string } | null }> {
  // 验证付费实例
  if (!isPackageInstance(instance)) {
    throw new Error('免费实例无需续费')
  }

  // 验证续费月数
  if (months < 1 || months > 24) {
    throw new Error('续费月数必须在 1-24 之间')
  }

  const isExpiredSuspension = instance.status === 'suspended' && instance.suspendReason === 'expired'
  const isRenewableStatus = instance.status === 'running' || instance.status === 'stopped' || isExpiredSuspension

  // 只有已完成开通的实例，或因到期被系统封停的实例，才允许续费。
  if (!isRenewableStatus) {
    if (instance.status === 'suspended') {
      throw new Error('实例已被手动封停，请联系宿主机所有者解封后再续费')
    }
    throw new Error('当前实例状态不允许续费')
  }

  const { amount: originalAmount, newExpiresAt } = calculateRenewBilling(instance, months)

  // 折扣金额与折扣来源在事务内通过统一解析函数重新计算，避免续费与优惠券状态变更竞争
  let discountAmount = 0
  let finalAmount = originalAmount
  let discountSource: 'official_coupon' | 'aff' | null = null
  let appliedOfficialCouponCode: string | null = null
  let appliedOfficialCouponDiscountedMonths = 0
  let appliedAffCodeId: number | null = null
  let appliedAffCodeCode: string | null = null

  // 执行事务（带乐观锁）
  const result = await prisma.$transaction(async (tx) => {
    // 与到期封停/删除共用实例锁，避免外部资源操作使用过期快照。
    await advisoryTransactionLock(tx, INSTANCE_OPERATION_LOCK_NAMESPACE, instance.id)

    const currentInstance = await tx.instance.findUnique({
      where: { id: instance.id },
      select: { status: true, suspendReason: true, version: true }
    })

    const currentIsExpiredSuspension = currentInstance?.status === 'suspended' && currentInstance.suspendReason === 'expired'
    const currentIsRenewable = currentInstance?.status === 'running' || currentInstance?.status === 'stopped' || currentIsExpiredSuspension
    if (!currentInstance || currentInstance.version !== instance.version || !currentIsRenewable) {
      throw new Error('实例状态已变更，请重试')
    }

    // ===== 统一解析续费优惠来源（用户覆盖的 AFF > 官方优惠券 > 普通 AFF） =====
    const discount = await resolveInstanceRenewalDiscount({
      id: instance.id,
      packageId: instance.packageId,
      packagePlanId: instance.packagePlanId,
      userId
    }, originalAmount, tx, months)
    discountAmount = discount.discountAmount
    finalAmount = discount.finalAmount
    discountSource = discount.source
    appliedOfficialCouponCode = discount.officialCouponCode
    if (discount.source === 'official_coupon') {
      appliedOfficialCouponDiscountedMonths = discount.discountedMonths === null
        ? months
        : Math.min(months, discount.discountedMonths)
    }
    appliedAffCodeId = discount.affCodeId
    appliedAffCodeCode = discount.affCodeCode

    // 获取用户当前余额
    const user = await tx.user.findUnique({
      where: { id: userId },
      select: { balance: true }
    })

    if (!user) {
      throw new Error('用户不存在')
    }

    const balanceSnapshot = Number(user.balance)
    if (balanceSnapshot < finalAmount) {
      throw new Error('余额不足')
    }

    // 扣除余额（使用条件更新确保并发安全）
    const updateResult = await tx.user.updateMany({
      where: {
        id: userId,
        balance: { gte: finalAmount }
      },
      data: { balance: { decrement: finalAmount } }
    })

    if (updateResult.count === 0) {
      throw new Error('余额不足或并发冲突')
    }

    const updatedUser = await tx.user.findUnique({
      where: { id: userId },
      select: { balance: true }
    })
    if (!updatedUser) throw new Error('用户不存在')
    const newBalance = Number(updatedUser.balance)
    const oldBalance = Number((newBalance + finalAmount).toFixed(2))

    // 乐观锁：检查实例版本号并更新
    const instanceUpdateResult = await tx.instance.updateMany({
      where: {
        id: instance.id,
        version: instance.version,  // 确保版本号未变
        OR: [
          { status: 'running' },
          { status: 'stopped' },
          { status: 'suspended', suspendReason: 'expired' }
        ]
      },
      data: {
        expiresAt: newExpiresAt,
        autoRenewAttempts: 0,
        version: { increment: 1 },  // 增加版本号
        // 如果因到期被封停，续费后解除封停（恢复为 stopped）
        ...(currentIsExpiredSuspension ? {
          status: 'stopped',
          suspendedAt: null,
          suspendedBy: null,
          suspendReason: null
        } : {})
      }
    })

    if (instanceUpdateResult.count === 0) {
      throw new Error('实例状态已变更，请重试')
    }

    // 记录余额日志
    const discountRemark = discountSource === 'official_coupon'
      ? `，官方优惠券 ${appliedOfficialCouponCode} 折扣 -¥${discountAmount.toFixed(2)}`
      : discountSource === 'aff'
        ? `，AFF 优惠码 ${appliedAffCodeCode} 折扣 -¥${discountAmount.toFixed(2)}`
        : ''
    const remarkText = `续费（${months}个月）：${instance.name}${discountRemark}`

    const balanceLog = await tx.balanceLog.create({
      data: {
        userId,
        type: 'consume',
        amount: -finalAmount,
        balanceBefore: oldBalance,
        balanceAfter: newBalance,
        instanceId: instance.id,
        remark: remarkText
      }
    })

    // 记录扣费记录
    const billingRecordRemark = discountSource === 'official_coupon'
      ? `续费 ${months} 个月，官方优惠券 ${appliedOfficialCouponCode} 折扣 -¥${discountAmount.toFixed(2)}`
      : discountSource === 'aff'
        ? `续费 ${months} 个月，AFF 优惠码 ${appliedAffCodeCode} 折扣 -¥${discountAmount.toFixed(2)}`
        : `续费 ${months} 个月`

    await tx.instanceBillingRecord.create({
      data: {
        instanceId: instance.id,
        userId,
        type: 'renew',
        amount: finalAmount,
        months,
        periodStart: instance.expiresAt || new Date(),
        periodEnd: newExpiresAt,
        balanceLogId: balanceLog.id,
        remark: billingRecordRemark
      }
    })

    // 官方优惠券续费：在事务内预占使用次数（次数上限/总次数上限在此锁定）
    if (discountSource === 'official_coupon' && appliedOfficialCouponCode && instance.packageId !== null) {
      await reserveOfficialCouponUsage({
        code: appliedOfficialCouponCode,
        packageId: instance.packageId,
        userId,
        instanceId: instance.id,
        originalPrice: originalAmount,
        discountAmount,
        discountedMonths: appliedOfficialCouponDiscountedMonths,
        mode: 'renewal',
        tx
      })
    }

    // 如果走 AFF 绑定折扣，给优惠码创建者返利（官方券不产生返利；更换优惠码后返利给新码创建者）
    if (discountSource === 'aff' && appliedAffCodeId) {
      await processAffCommission(
        appliedAffCodeId,
        instance.id,
        originalAmount, // 基于原价计算返利
        'renew',
        tx as any
      )
    }

    let hostingIncomeResult: { hostOwnerId: number; hostName: string } | null = null

    const hostingOwner = await resolveHostedIncomeOwner(tx, instance.hostId)
    if (hostingOwner) {
      // 用户托管节点，记录托管收入（带快照）
      // 官方优惠券由平台承担折扣，托管主仍按原价结算
      const hostingIncomeAmount = discountSource === 'official_coupon' ? originalAmount : finalAmount
      const unfreezeAt = addMonths(new Date(), 1)
      await createHostingLogWithSnapshot(tx, {
        userId: hostingOwner.userId,
        type: 'income',
        actionType: 'renew',
        amount: hostingIncomeAmount,
        instanceId: instance.id,
        frozen: true,
        unfreezeAt,
        remark: `用户续费实例收入（冻结30天）`
      })
      console.log(`[HostingIncome] 记录续费托管收入: hostOwnerId=${hostingOwner.userId}, amount=${hostingIncomeAmount}, instanceId=${instance.id}`)
      hostingIncomeResult = { hostOwnerId: hostingOwner.userId, hostName: hostingOwner.hostName }
    }

    return { balanceLogId: balanceLog.id, hostingIncomeResult }
  })

  return {
    newExpiresAt,
    amount: finalAmount,
    balanceLogId: result.balanceLogId,
    discountAmount: discountAmount > 0 ? discountAmount : undefined,
    hostingIncomeResult: result.hostingIncomeResult
  }
}

/**
 * 执行升降级操作（带乐观锁并发控制）
 * 
 * 升级：从余额扣除差价
 * 降级：差价退款到余额
 */
export async function performPlanChange(
  userId: number,
  instance: Instance,
  newPlan: PackagePlan
): Promise<{
  priceDiff: number
  newConfig: { cpu: number; memory: number; disk: number }
  needRestart: boolean  // 标记是否需要重启
  refundAmount?: number // 降级时的退款金额
  hostingIncomeResult?: { hostOwnerId: number; hostName: string } | null // 托管收入结果
}> {
  const pkg = await prisma.package.findUnique({
    where: { id: newPlan.packageId },
    select: { instanceType: true }
  })
  const isVmPackage = pkg?.instanceType === 'vm'

  // 验证
  if (!isPackageInstance(instance)) {
    throw new Error('免费实例不支持升降级')
  }

  // 升降级状态限制：仅 running 和 stopped 可以升降级
  if (!['running', 'stopped'].includes(instance.status)) {
    throw new Error('当前实例状态不允许升降级，仅运行中或已停止的实例可以升降级')
  }

  if (newPlan.packageId !== instance.packageId) {
    throw new Error('新方案必须属于同一套餐')
  }
  if (!newPlan.isActive) {
    throw new Error('新方案已下架')
  }
  if (newPlan.isSoldOut) {
    throw new Error('新方案已售罄')
  }
  if (instance.packagePlanId === newPlan.id) {
    throw new Error('不能切换到相同方案')
  }

  // 计算升级差价
  const changeResult = await calculatePlanChange(instance, newPlan)

  // 检查是否可以变更
  if (!changeResult.canChange) {
    if (changeResult.cannotChangeReason === 'remaining_days_insufficient') {
      throw new Error('剩余时间不足 15 天，无法变更方案')
    }
    throw new Error('当前不能变更方案')
  }

  let refundAmount: number | undefined

  // 执行事务（带乐观锁）
  const txResult = await prisma.$transaction(async (tx) => {
    if (instance.trafficBillingMode === 'usage' && newPlan.trafficBillingMode !== 'usage') {
      const pendingTrafficBill = await tx.trafficBillingRecord.findFirst({
        where: { instanceId: instance.id, status: 'pending' },
        select: { id: true }
      })
      if (pendingTrafficBill) {
        throw new Error('存在未支付流量账单，结清后才能切换到套餐流量计费')
      }
    }

    // 获取用户当前余额
    const user = await tx.user.findUnique({
      where: { id: userId },
      select: { balance: true }
    })

    if (!user) {
      throw new Error('用户不存在')
    }

    const balanceSnapshot = Number(user.balance)
    let hostingIncomeResult: { hostOwnerId: number; hostName: string } | null = null

    // 升级需要补差价
    if (changeResult.priceDiff > 0) {
      if (balanceSnapshot < changeResult.priceDiff) {
        throw new Error(`余额不足，需补差价 ${changeResult.priceDiff} 元`)
      }

      const balanceUpdateResult = await tx.user.updateMany({
        where: { id: userId, balance: { gte: changeResult.priceDiff } },
        data: { balance: { decrement: changeResult.priceDiff } }
      })

      if (balanceUpdateResult.count === 0) {
        throw new Error('余额不足或并发冲突')
      }

      const updatedUser = await tx.user.findUnique({
        where: { id: userId },
        select: { balance: true }
      })
      if (!updatedUser) throw new Error('用户不存在')
      const balanceAfter = Number(updatedUser.balance)
      const balanceBefore = roundCurrency(balanceAfter + changeResult.priceDiff)

      // 升级扣费记录
      await tx.balanceLog.create({
        data: {
          userId,
          type: 'consume',
          amount: -changeResult.priceDiff,
          balanceBefore,
          balanceAfter,
          instanceId: instance.id,
          remark: `升级方案：${changeResult.oldPlan.name} → ${newPlan.name}`
        }
      })

      const hostingOwner = await resolveHostedIncomeOwner(tx, instance.hostId)
      if (hostingOwner) {
        // 用户托管节点，记录托管收入（升级差价，带快照）
        const unfreezeAt = addMonths(new Date(), 1)
        await createHostingLogWithSnapshot(tx, {
          userId: hostingOwner.userId,
          type: 'income',
          actionType: 'upgrade',
          amount: changeResult.priceDiff,
          instanceId: instance.id,
          frozen: true,
          unfreezeAt,
          remark: `用户升级实例方案收入（冻结30天）`
        })
        console.log(`[HostingIncome] 记录升级托管收入: hostOwnerId=${hostingOwner.userId}, amount=${changeResult.priceDiff}, instanceId=${instance.id}`)
        hostingIncomeResult = { hostOwnerId: hostingOwner.userId, hostName: hostingOwner.hostName }
      }
    }

    // 降级退款到余额
    if (changeResult.priceDiff < 0) {
      const requestedRefundAmount = Math.abs(changeResult.priceDiff)
      const maxRefundable = (await getMaxRefundableForClient(tx, instance.id)).maxRefundable
      refundAmount = roundCurrency(Math.min(requestedRefundAmount, maxRefundable))

      if (refundAmount > 0) {
        const updatedUser = await tx.user.update({
          where: { id: userId },
          data: { balance: { increment: refundAmount } },
          select: { balance: true }
        })
        const newBalance = Number(updatedUser.balance)
        const oldBalance = roundCurrency(newBalance - refundAmount)

        // 降级退款记录
        const downgradeRefundLog = await tx.balanceLog.create({
          data: {
            userId,
            type: 'refund',
            amount: refundAmount,
            balanceBefore: oldBalance,
            balanceAfter: newBalance,
            instanceId: instance.id,
            remark: `降级方案退款：${changeResult.oldPlan.name} → ${newPlan.name}`
          }
        })

        // 退款可能来自官方券折后账单；托管收入按原价比例同步回收。
        const hostedRefundAmount = await calculateHostedRefundAmountForClient(
          tx,
          instance.id,
          refundAmount
        )

        // 余额日志不是实例退款上限的唯一账本；必须同步写入 refund
        // billing record，否则之后销毁实例/管理员退款会再次退回这笔钱。
        await tx.instanceBillingRecord.create({
          data: {
            instanceId: instance.id,
            userId,
            type: 'refund',
            amount: -refundAmount,
            months: 0,
            periodStart: new Date(),
            periodEnd: new Date(),
            balanceLogId: downgradeRefundLog.id,
            remark: `降级方案退款：${changeResult.oldPlan.name} → ${newPlan.name}`
          }
        })

        if (hostedRefundAmount > 0) {
          const hostingOwner = await resolveHostedIncomeOwner(tx, instance.hostId)
          if (hostingOwner) {
            await deductHostingBalance(
              instance.hostId,
              hostedRefundAmount,
              instance.id,
              `实例降级退款扣除托管收入：${instance.name}`,
              tx
            )
            hostingIncomeResult = {
              hostOwnerId: hostingOwner.userId,
              hostName: hostingOwner.hostName
            }
          }
        }
      }
    }

    const monthlyTrafficLimit = await resolveInstanceTrafficLimitForHost(tx as any, {
      packageId: instance.packageId,
      hostId: instance.hostId,
      baseTrafficLimit: newPlan.trafficLimit
    })

    // 乐观锁：更新实例配置，同时检查版本号
    const instanceUpdateResult = await tx.instance.updateMany({
      where: {
        id: instance.id,
        version: instance.version  // 确保版本号未变
      },
      data: {
        packagePlanId: newPlan.id,
        cpu: newPlan.cpu,
        memory: newPlan.memory,
        disk: newPlan.disk,
        // 更新计费信息（注意：newPlan.price 是分，需要除以100转元）
        billingPrice: Number(newPlan.price) / 100,
        billingCycle: newPlan.billingCycle,
        // 配额限制
        portLimit: newPlan.portLimit,
        snapshotLimit: newPlan.snapshotLimit,
        backupLimit: newPlan.backupLimit,
        siteLimit: newPlan.siteLimit,
        swapEnabled: isVmPackage ? false : instance.swapEnabled,
        swapSize: isVmPackage
          ? null
          : (shouldSyncInstanceSwapSizeWithPlan(instance.swapSize, changeResult.oldPlan.swapSize)
              ? newPlan.swapSize
              : instance.swapSize),
        monthlyTrafficLimit,
        trafficStatus: newPlan.trafficBillingMode === 'usage'
          ? 'NORMAL'
          : calculateInstanceTrafficStatus(instance.monthlyTrafficUsed, monthlyTrafficLimit),
        trafficBillingMode: newPlan.trafficBillingMode,
        trafficUnitPrice: newPlan.trafficUnitPrice,
        limitsIngress: newPlan.trafficBillingMode === 'usage' ? null : normalizePlanTrafficLimitSpeed(newPlan.trafficLimitSpeed),
        limitsEgress: newPlan.trafficBillingMode === 'usage' ? null : normalizePlanTrafficLimitSpeed(newPlan.trafficLimitSpeed),
        trafficSettledBytes: calculatePlanChangeSettledBytes({
          monthlyTrafficUsed: instance.monthlyTrafficUsed,
          previousBillingMode: instance.trafficBillingMode,
          previousSettledBytes: instance.trafficSettledBytes,
          previousMonthlyTrafficLimit: instance.monthlyTrafficLimit,
          newBillingMode: newPlan.trafficBillingMode,
          newMonthlyTrafficLimit: monthlyTrafficLimit
        }),
        // Preserve the current traffic-period accounting trail across plan
        // changes. Monthly resets remain responsible for clearing this value.
        trafficSettledCost: instance.trafficSettledCost,
        nextTrafficBillingAt: newPlan.trafficBillingMode === 'usage' ? new Date(Date.now() + 60 * 60 * 1000) : null,
        // 更新冷却期时间
        lastPlanChangeAt: new Date(),
        // 版本号递增
        version: { increment: 1 }
        // 注意：到期时间保持不变
      }
    })

    if (instanceUpdateResult.count === 0) {
      throw new Error('实例状态已变更，请重试')
    }

    // 记录计费记录
    await tx.instanceBillingRecord.create({
      data: {
        instanceId: instance.id,
        userId,
    type: changeResult.isUpgrade ? 'upgrade' : 'downgrade',
        amount: changeResult.priceDiff > 0 ? changeResult.priceDiff : 0,
        months: 0, // 升降级不改变时长
        periodStart: new Date(),
        periodEnd: instance.expiresAt!,
        remark: `${changeResult.oldPlan.name} → ${newPlan.name}${refundAmount ? `，退款 ¥${refundAmount.toFixed(2)}` : ''}`
      }
    })

    return { hostingIncomeResult }
  })

  return {
    priceDiff: changeResult.priceDiff < 0
      ? -(refundAmount || 0)
      : changeResult.priceDiff,
    newConfig: changeResult.newConfig,
    needRestart: true,  // 升降级后需要重启实例才能生效
    refundAmount,
    hostingIncomeResult: txResult.hostingIncomeResult
  }
}

/**
 * 更新自动续费设置
 */
export async function updateAutoRenew(
  instanceId: number,
  autoRenew: boolean
): Promise<void> {
  await prisma.instance.update({
    where: { id: instanceId },
    data: { autoRenew }
  })
}

/**
 * 获取实例计费信息
 */
export async function getInstanceBillingInfo(instanceId: number): Promise<{
  isPaid: boolean
  expiresAt: Date | null
  billingPrice: number | null
  billingCycle: number | null
  monthlyPrice: number | null
  autoRenew: boolean
  status: string
  suspendReason: string | null
  packagePlan: {
    id: number
    name: string
    isActive: boolean
  } | null
  renewPreview: Array<{ months: number; amount: number; discountedAmount: number; expiresAt: Date }> | null
  affDiscount: {
    discountRate: number  // 折扣率，如 0.05 表示 5%
    affCodeId: number
    code: string  // 优惠码字符串
    supersedesOfficialCoupon: boolean  // 是否覆盖官方优惠券
  } | null
  // 官方优惠券续期折扣（优先于 AFF 绑定）
  officialCouponDiscount: {
    discountRate: number
    discountPercent: number
    couponCode: string
    couponName: string
  } | null
  // 托管实例相关信息
  isHostedInstance: boolean
  daysUntilExpire: number | null
  hostingRenewRestriction: { monthsOnly: number; daysBeforeExpire: number } | null
} | null> {
  const instance = await prisma.instance.findUnique({
    where: { id: instanceId },
    include: {
      packagePlan: {
        select: { id: true, name: true, isActive: true }
      },
      host: {
        select: {
          userId: true,
          user: {
            select: {
              role: true
            }
          }
        }
      }
    }
  })

  if (!instance) return null

  const isPaid = isPackageInstance(instance)

  // 判断是否为托管实例（节点所有者不是管理员）
  const isHostedInstance = instance.host?.user.role === 'user'

  // 计算剩余天数
  let daysUntilExpire: number | null = null
  if (instance.expiresAt) {
    const now = new Date()
    daysUntilExpire = Math.ceil((instance.expiresAt.getTime() - now.getTime()) / (1000 * 60 * 60 * 24))
  }

  // 托管续费限制
  const hostingRenewRestriction = isHostedInstance ? { monthsOnly: 1, daysBeforeExpire: 7 } : null

  let monthlyPrice: number | null = null
  let renewPreview: Array<{ months: number; amount: number; discountedAmount: number; expiresAt: Date }> | null = null
  let affDiscount: { discountRate: number; affCodeId: number; code: string; supersedesOfficialCoupon: boolean } | null = null
  let officialCouponDiscount: { discountRate: number; discountPercent: number; couponCode: string; couponName: string } | null = null

  if (isPaid && instance.billingPrice) {
    monthlyPrice = calculateMonthlyPrice({
      billingPrice: instance.billingPrice,
      billingCycle: instance.billingCycle
    })

    // 统一解析续费优惠来源（用户覆盖的 AFF > 官方优惠券 > 普通 AFF），至多一个生效
    const discount = await resolveInstanceRenewalDiscount({
      id: instanceId,
      packageId: instance.packageId,
      packagePlanId: instance.packagePlanId,
      userId: instance.userId
    }, 0)
    const discountRate = discount.discountRate

    if (discount.source === 'official_coupon') {
      officialCouponDiscount = {
        discountRate,
        discountPercent: Math.round(discountRate * 100),
        couponCode: discount.officialCouponCode!,
        couponName: discount.officialCouponName!
      }
    } else if (discount.source === 'aff') {
      affDiscount = {
        discountRate,
        affCodeId: discount.affCodeId!,
        code: discount.affCodeCode!,
        supersedesOfficialCoupon: discount.supersedesOfficialCoupon
      }
    }

    // 计算续费预览（包含折扣价）
    const originalPreview = previewRenewPrices({
      billingPrice: instance.billingPrice,
      billingCycle: instance.billingCycle,
      expiresAt: instance.expiresAt
    })

    // 托管实例只返回1个月的续费选项
    const filteredPreview = isHostedInstance
      ? originalPreview.filter(p => p.months === 1)
      : originalPreview

    renewPreview = filteredPreview.map(p => {
      const discountedMonths = discount.source === 'official_coupon' && discount.discountedMonths !== null
        ? Math.min(p.months, discount.discountedMonths)
        : (discount.source ? p.months : 0)
      const previewDiscountAmount = discount.source && discountRate > 0
        ? calculateDiscountAmountForMonths(
            p.amount,
            p.months,
            discountedMonths,
            discountRate
          )
        : 0

      return {
        months: p.months,
        amount: p.amount,  // 原价（元）
        discountedAmount: Number((p.amount - previewDiscountAmount).toFixed(2)),
        expiresAt: p.expiresAt
      }
    })
  }

  return {
    isPaid,
    expiresAt: instance.expiresAt,
    billingPrice: instance.billingPrice ? Number(instance.billingPrice) : null,
    billingCycle: instance.billingCycle,
    monthlyPrice,
    autoRenew: instance.autoRenew,
    status: instance.status,
    suspendReason: instance.suspendReason,
    packagePlan: instance.packagePlan,
    renewPreview,
    affDiscount,
    officialCouponDiscount,
    isHostedInstance,
    daysUntilExpire,
    hostingRenewRestriction
  }
}

// ==================== 辅助函数 ====================

/**
 * 添加月份到日期
 * 使用公共方法 calcAddMonths
 */
function addMonths(date: Date, months: number): Date {
  return calcAddMonths(date, months)
}

/**
 * 检查实例是否为免费实例
 */
export function isHourlyInstance(instance: { billingMode?: string | null; packagePlanId: number | null }): boolean {
  return instance.billingMode === 'hourly'
}

export function isPackageInstance(instance: { billingMode?: string | null; packagePlanId: number | null }): boolean {
  return !isHourlyInstance(instance) && instance.packagePlanId !== null
}

export function isFreeInstance(instance: { billingMode?: string | null; packagePlanId: number | null }): boolean {
  return !isHourlyInstance(instance) && instance.packagePlanId === null
}

/**
 * 检查实例是否为付费实例
 */
export function isPaidInstance(instance: { billingMode?: string | null; packagePlanId: number | null }): boolean {
  return isPackageInstance(instance)
}

/**
 * 检查实例是否已过期
 */
export function isExpired(instance: { expiresAt: Date | null }): boolean {
  if (instance.expiresAt === null) return false
  return new Date() > instance.expiresAt
}

// ==================== 托管余额结算 ====================

/**
 * 内部辅助函数：统一创建带快照的托管日志
 * 用于所有实例相关托管日志的写入，确保快照字段一致性
 */
async function createHostingLogWithSnapshot(
  client: any,
  params: {
    userId: number
    type: 'income' | 'deduction'
    actionType: string
    amount: number
    instanceId: number
    frozen: boolean
    unfreezeAt?: Date | null
    remark: string
  }
) {
  // 查询实例及关联信息用于快照
  const instance = await client.instance.findUnique({
    where: { id: params.instanceId },
    select: {
      name: true,
      user: { select: { username: true, email: true, avatarStyle: true } },
      host: { select: { name: true } },
      package: { select: { name: true } },
      packagePlan: { select: { name: true } }
    }
  })

  await client.hostingBalanceLog.create({
    data: {
      userId: params.userId,
      type: params.type,
      actionType: params.actionType,
      amount: params.amount,
      frozen: params.frozen,
      unfreezeAt: params.unfreezeAt ?? null,
      relatedId: params.instanceId,
      remark: params.remark,
      snapshotBuyerName: instance?.user.username ?? null,
      snapshotBuyerEmail: instance?.user.email ?? null,
      snapshotBuyerAvatar: instance?.user.avatarStyle ?? null,
      snapshotInstanceName: instance?.name ?? null,
      snapshotHostName: instance?.host.name ?? null,
      snapshotPackageName: instance?.package?.name ?? null,
      snapshotPlanName: instance?.packagePlan?.name ?? null
    }
  })
}

async function resolveHostedIncomeOwner(
  client: any,
  hostId: number,
  options: {
    instanceId?: number | null
    allowHistoricalFallback?: boolean
  } = {}
): Promise<{ userId: number; hostName: string } | null> {
  const { instanceId = null, allowHistoricalFallback = false } = options

  const host = await client.host.findUnique({
    where: { id: hostId },
    select: {
      userId: true,
      name: true,
      user: {
        select: {
          role: true
        }
      }
    }
  })

  if (!host) {
    return null
  }

  if (host.user.role !== 'admin') {
    return {
      userId: host.userId,
      hostName: host.name
    }
  }

  if (!allowHistoricalFallback || !instanceId) {
    return null
  }

  const latestIncomeLog = await client.hostingBalanceLog.findFirst({
    where: {
      relatedId: instanceId,
      type: 'income'
    },
    orderBy: {
      createdAt: 'desc'
    },
    select: {
      userId: true
    }
  })

  if (!latestIncomeLog) {
    return null
  }

  const historicalOwner = await client.user.findUnique({
    where: { id: latestIncomeLog.userId },
    select: {
      role: true
    }
  })

  if (!historicalOwner || historicalOwner.role === 'admin') {
    return null
  }

  return {
    userId: latestIncomeLog.userId,
    hostName: host.name
  }
}

/**
 * 判断节点是否为用户托管节点（非管理员节点）
 */
export async function isUserHostedNode(hostId: number): Promise<boolean> {
  const host = await prisma.host.findUnique({
    where: { id: hostId },
    select: {
      user: {
        select: {
          role: true
        }
      }
    }
  })
  return host?.user.role === 'user'
}

/**
 * 获取节点所有者ID
 */
export async function getHostOwnerId(hostId: number): Promise<number | null> {
  const host = await prisma.host.findUnique({
    where: { id: hostId },
    select: { userId: true }
  })
  return host?.userId ?? null
}

/**
 * 记录托管收入（用户购买/续费用户托管节点上的实例时调用）
 * 
 * @param hostOwnerId 节点所有者用户ID
 * @param amount 金额（元）
 * @param instanceId 关联的实例ID
 * @param remark 备注
 * @param actionType 操作类型（purchase/renew/upgrade/destroy等）
 * @param tx 可选的事务客户端
 */
export async function recordHostingIncome(
  hostOwnerId: number,
  amount: number,
  instanceId: number,
  remark: string,
  actionType: 'purchase' | 'renew' | 'upgrade' | 'destroy' | 'unfreeze' | 'withdraw',
  tx?: any
): Promise<void> {
  const client = tx || prisma

  // 计算解冻时间（30天后）
  const unfreezeAt = addMonths(new Date(), 1) // 使用 1 个月作为 30 天的近似

  await createHostingLogWithSnapshot(client, {
    userId: hostOwnerId,
    type: 'income',
    actionType,
    amount,
    instanceId,
    frozen: true,
    unfreezeAt,
    remark
  })
}

/**
 * 处理托管收入结算
 * 在用户购买或续费实例时调用，检查节点是否为用户托管，如是则记录收入
 * 
 * @param hostId 节点ID
 * @param amount 金额（元）
 * @param instanceId 实例ID
 * @param type 类型：'purchase' | 'renew' | 'upgrade'
 * @param tx 可选的事务客户端
 * @returns 如果是用户托管节点，返回节点所有者信息；否则返回 null
 */
export async function processHostingIncome(
  hostId: number,
  amount: number,
  instanceId: number,
  type: 'purchase' | 'renew' | 'upgrade',
  tx?: any
): Promise<{ hostOwnerId: number; hostName: string } | null> {
  const client = tx || prisma

  // 获取节点所有者和节点名称
  const host = await client.host.findUnique({
    where: { id: hostId },
    select: {
      userId: true,
      name: true,
      user: {
        select: {
          role: true
        }
      }
    }
  })

  if (!host || host.user.role === 'admin') {
    // 管理员所有的节点不需要记录托管收入
    return null
  }

  // 用户托管节点，记录托管收入
  const remark = type === 'purchase'
    ? `用户购买实例收入（冻结30天）`
    : type === 'renew'
      ? `用户续费实例收入（冻结30天）`
      : `用户升级实例收入（冻结30天）`

  await recordHostingIncome(host.userId, amount, instanceId, remark, type, client)

  console.log(`[HostingIncome] 记录托管收入: hostOwnerId=${host.userId}, amount=${amount}, instanceId=${instanceId}, type=${type}`)

  return { hostOwnerId: host.userId, hostName: host.name }
}

/**
 * 获取实例剩余天数
 * 使用公共方法 calculateRemainingDays
 */
export function getRemainingDays(instance: { expiresAt: Date | null }): number | null {
  if (instance.expiresAt === null) return null
  return calculateRemainingDays(instance.expiresAt)
}

/**
 * 托管实例销毁时扣除节点所有者的托管余额
 * 
 * 优先从该实例相关的冻结收入中扣除，不足部分从可用余额扣除
 * 
 * @param hostId 节点ID
 * @param amount 扣除金额（元）
 * @param instanceId 实例ID
 * @param remark 备注
 * @param tx 可选的事务客户端
 * @returns 如果是用户托管节点，返回扣除结果；否则返回 null
 */
export async function deductHostingBalance(
  hostId: number,
  amount: number,
  instanceId: number,
  remark: string,
  tx?: any
): Promise<HostingBalanceDeductionResult | null> {
  const run = async (client: Prisma.TransactionClient): Promise<HostingBalanceDeductionResult | null> => {
    const hostingOwner = await resolveHostedIncomeOwner(client, hostId, {
      instanceId,
      allowHistoricalFallback: true
    })
    if (!hostingOwner) {
      return null
    }
    const hostOwnerId = hostingOwner.userId

    const locked = await tryAdvisoryTransactionLock(client, HOSTING_BALANCE_LOG_LOCK_NAMESPACE, hostOwnerId)
    if (!locked) {
      throw new Error('托管余额正在处理，请稍后重试')
    }

    // 查找该实例相关的冻结托管收入记录
    const frozenLogs = await client.hostingBalanceLog.findMany({
      where: {
        userId: hostOwnerId,
        relatedId: instanceId,
        type: 'income',
        frozen: true
      },
      orderBy: { createdAt: 'asc' }
    })

    let remainingToDeduct = amount
    let fromFrozen = 0
    let fromAvailable = 0
    let fromBalance = 0

    // 第一步：优先从冻结收入中扣除
    // 冻结记录尚未计入 hostingBalance，通过删除/减少原记录来确保这部分钱不会被计入，
    // 即账务上正确地抵消了这笔收入。同时在下方统一新建一条独立的审计扣除记录。
    for (const log of frozenLogs) {
      if (remainingToDeduct <= 0) break

      const logAmount = Number(log.amount)
      const deductFromThis = Math.min(logAmount, remainingToDeduct)

      if (deductFromThis >= logAmount) {
        // 全额抵扣：删除整条冻结收入记录（此笔收入永远不会进入 hostingBalance）
        await client.hostingBalanceLog.delete({
          where: { id: log.id }
        })
      } else {
        // 部分抵扣：减少冻结记录金额，剩余部分继续冻结等待解冻
        await client.hostingBalanceLog.update({
          where: { id: log.id },
          data: { amount: { decrement: deductFromThis } }
        })
      }

      fromFrozen += deductFromThis
      remainingToDeduct -= deductFromThis
    }

    // 第二步：如果冻结收入不足，从已解冻的托管余额扣除
    if (remainingToDeduct > 0) {
      const user = await client.user.findUnique({
        where: { id: hostOwnerId },
        select: { hostingBalance: true, balance: true }
      })

      const availableHostingBalance = Number(user?.hostingBalance || 0)
      const deductFromAvailable = Math.min(availableHostingBalance, remainingToDeduct)

      if (deductFromAvailable > 0) {
        const availableUpdate = await client.user.updateMany({
          where: {
            id: hostOwnerId,
            hostingBalance: { gte: deductFromAvailable }
          },
          data: { hostingBalance: { decrement: deductFromAvailable } }
        })

        if (availableUpdate.count === 1) {
          fromAvailable = deductFromAvailable
          remainingToDeduct -= deductFromAvailable
        }
      }

      // 第三步：如果托管余额仍不足，从面板余额扣除
      if (remainingToDeduct > 0) {
        const currentUser = await client.user.findUnique({
          where: { id: hostOwnerId },
          select: { balance: true }
        })
        const availableBalance = Number(currentUser?.balance || 0)
        const deductFromBalance = Math.min(availableBalance, remainingToDeduct)

        if (deductFromBalance > 0) {
          const balanceUpdate = await client.user.updateMany({
            where: {
              id: hostOwnerId,
              balance: { gte: deductFromBalance }
            },
            data: { balance: { decrement: deductFromBalance } }
          })

          if (balanceUpdate.count !== 1) {
            // 余额已被并发支出，保留未扣部分，不得将余额扣成负数。
            console.warn(`[HostingBalance] 面板余额并发变化，跳过本次补扣: hostOwnerId=${hostOwnerId}, instanceId=${instanceId}`)
          } else {
            const updatedUser = await client.user.findUnique({
              where: { id: hostOwnerId },
              select: { balance: true }
            })
            const balanceAfter = Number(updatedUser?.balance || 0)
            const balanceBefore = Number((balanceAfter + deductFromBalance).toFixed(2))

            // 记录面板余额变动日志
            await client.balanceLog.create({
              data: {
                userId: hostOwnerId,
                type: 'hosting_deduction',
                amount: -deductFromBalance,
                balanceBefore,
                balanceAfter,
                instanceId,
                remark: `托管实例销毁扣款：用户退款需从面板余额补扣`
              }
            })

            fromBalance = deductFromBalance
            remainingToDeduct -= deductFromBalance
          }
        }
      }
    }

    const totalDeducted = fromFrozen + fromAvailable + fromBalance

    // 始终创建一条独立的销毁扣除审计记录（无论扣款来自冻结、托管余额还是面板余额）
    // 原来的条件 (fromFrozen>0 || fromAvailable>0) 遗漏了纯从面板余额扣款的情况，
    // 且金额也未包含 fromBalance，现统一修正。
    if (totalDeducted > 0) {
      const parts: string[] = []
      if (fromFrozen > 0) parts.push(`冻结抵扣 ¥${fromFrozen.toFixed(2)}`)
      if (fromAvailable > 0) parts.push(`托管余额扣除 ¥${fromAvailable.toFixed(2)}`)
      if (fromBalance > 0) parts.push(`面板余额补扣 ¥${fromBalance.toFixed(2)}`)

      await createHostingLogWithSnapshot(client, {
        userId: hostOwnerId,
        type: 'deduction',
        actionType: 'destroy',
        amount: -totalDeducted,
        instanceId,
        frozen: false,
        remark: `${remark}（${parts.join('，')}）`
      })
    }

    console.log(`[HostingBalance] 扣除托管余额: hostOwnerId=${hostOwnerId}, amount=${amount}, deducted=${totalDeducted}, fromFrozen=${fromFrozen}, fromAvailable=${fromAvailable}, fromBalance=${fromBalance}, instanceId=${instanceId}`)

    return { hostOwnerId, deductedAmount: totalDeducted, fromFrozen, fromAvailable, fromBalance }
  }

  if (tx) {
    return run(tx)
  }

  return prisma.$transaction(async (transaction) => run(transaction))
}
