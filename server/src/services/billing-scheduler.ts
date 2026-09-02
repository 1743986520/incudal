/**
 * 计费调度器
 * 负责定时执行自动续费、到期封停、到期删除、到期提醒等任务
 */

import { schedule } from 'node-cron'
import pLimit from 'p-limit'
import { prisma } from '../db/prisma.js'
import * as db from '../db/index.js'
import { sendHostManagedInstanceNotification, sendNotification } from '../lib/notifier.js'
import { 
  sendExpiryReminderEmail, 
  sendAutoRenewSuccessEmail, 
  sendAutoRenewFailedEmail 
} from '../lib/mailer.js'
import { createLog } from '../db/logs.js'
import {
  performRenewal,
  calculateRenewBilling
} from '../db/billing-operations.js'
import {
  getAutoRenewInstances,
  getExpiredUnsuspendedInstances,
  getSuspendedInstancesOlderThan,
  suspendInstanceByExpiry,
  claimExpiredInstanceForDeletion,
  restoreExpiredInstanceDeletionClaim,
  updateAutoRenewAttempt,
  updateExpiryNotifiedAt
} from '../db/instance-suspend.js'
import { deleteInstance as deleteIncusInstance, getIncusClient } from '../lib/incus/index.js'
import { deleteExpiredInstanceAndRollbackResources } from '../db/quota-operations.js'
import { sendReleaseNotification } from '../lib/release-notifier.js'

// 并发限制
const limit = pLimit(5)

// 配置常量
const AUTO_RENEW_HOURS_BEFORE = 24 // 到期前24小时尝试自动续费
const AUTO_RENEW_MAX_ATTEMPTS = 3 // 最大自动续费尝试次数
const SUSPEND_AFTER_DELETE_DAYS = 3 // 封停后3天自动删除
const EXPIRY_NOTIFY_DAYS = [3] // 仅在到期前3天提醒一次

/**
 * 延迟函数
 */
function delay(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}

// ==================== 自动续费任务 ====================

/**
 * 执行自动续费
 */
async function executeAutoRenew(): Promise<void> {
  console.log('[Billing] Starting auto-renew job...')
  const startTime = Date.now()

  try {
    // 获取24小时内到期且开启了自动续费的实例
    const instances = await getAutoRenewInstances(AUTO_RENEW_HOURS_BEFORE)

    console.log(`[Billing] Found ${instances.length} instances for auto-renew`)

    // 并发处理
    await Promise.all(
      instances.map(instance =>
        limit(() => processAutoRenew(instance))
      )
    )

    const duration = Date.now() - startTime
    console.log(`[Billing] Auto-renew job completed in ${duration}ms`)
  } catch (error) {
    console.error('[Billing] Auto-renew job failed:', error)
  }
}

/**
 * 处理单个实例的自动续费
 */
async function processAutoRenew(instance: any): Promise<void> {
  const attempts = (instance.autoRenewAttempts || 0) + 1

  // 检查是否超过最大尝试次数
  if (attempts > AUTO_RENEW_MAX_ATTEMPTS) {
    console.log(`[Billing] Instance ${instance.id} exceeded max auto-renew attempts, disabling`)
    await updateAutoRenewAttempt(instance.id, attempts, true)
    return
  }

  try {
    // 按原计费周期续费（如季付续3个月）
    const renewMonths = instance.billingCycle || 1
    const renewInfo = calculateRenewBilling(instance, renewMonths)

    // 获取用户信息（包括邮箱）
    const user = await prisma.user.findUnique({
      where: { id: instance.userId },
      select: { balance: true, email: true, username: true }
    })

    if (!user) {
      console.log(`[Billing] User ${instance.userId} not found for instance ${instance.id}`)
      await updateAutoRenewAttempt(instance.id, attempts)
      return
    }

    const balance = Number(user.balance)

    // 余额不足
    if (balance < renewInfo.amount) {
      console.log(`[Billing] Insufficient balance for instance ${instance.id}: need ${renewInfo.amount}, have ${balance}`)
      await updateAutoRenewAttempt(instance.id, attempts)

      // 发送自动续费失败站内通知
      await sendNotification(instance.userId, 'auto_renew_failed', {
        instanceName: instance.name,
        failReason: `余额不足（需要 ¥${renewInfo.amount.toFixed(2)}，当前 ¥${balance.toFixed(2)}）`,
        renewAmount: renewInfo.amount  // 元（calculateRenewBilling 返回的是元）
      })

      // 发送自动续费失败邮件
      if (user.email) {
        try {
          await sendAutoRenewFailedEmail(user.email, {
            username: user.username,
            instanceName: instance.name,
            failReason: `余额不足（需要 ¥${renewInfo.amount.toFixed(2)}，当前 ¥${balance.toFixed(2)}）`,
            currentAttempt: attempts,
            maxAttempts: AUTO_RENEW_MAX_ATTEMPTS,
            expiresAt: instance.expiresAt
          })
        } catch (emailErr) {
          console.warn(`[Billing] Failed to send auto-renew failed email:`, emailErr)
        }
      }

      await createLog(
        instance.userId,
        'instance',
        'instance.auto_renew_failed',
        `Auto-renew failed for instance "${instance.name}": insufficient balance`,
        'failed',
        { instanceId: instance.id }
      )
      return
    }

    // 执行续费
    const result = await performRenewal(instance.userId, instance, renewMonths)

    // 发送续费成功站内通知
    await sendNotification(instance.userId, 'instance_renewed', {
      instanceName: instance.name,
      renewAmount: result.amount,  // 元（performRenewal 返回的是元）
      renewMonths: renewMonths,
      newExpiresAt: result.newExpiresAt.toISOString()
    })

    if (result.hostingIncomeResult) {
      sendHostManagedInstanceNotification(
        instance.hostId,
        'renew',
        {
          username: user.username,
          instanceName: instance.name,
          amount: result.amount
        }
      ).catch(err => {
        console.warn('[Billing] Failed to send host renew notification:', err)
      })
    }

    // 发送自动续费成功邮件
    if (user.email) {
      try {
        // 获取续费后的余额
        const userAfter = await prisma.user.findUnique({
          where: { id: instance.userId },
          select: { balance: true }
        })
        const newBalance = Number(userAfter?.balance ?? 0)

        await sendAutoRenewSuccessEmail(user.email, {
          username: user.username,
          instanceName: instance.name,
          amount: result.amount,
          months: renewMonths,
          newExpiresAt: result.newExpiresAt,
          newBalance
        })
      } catch (emailErr) {
        console.warn(`[Billing] Failed to send auto-renew success email:`, emailErr)
      }
    }

    await createLog(
      instance.userId,
      'instance',
      'instance.auto_renew',
      `Auto-renewed instance "${instance.name}" for ${renewMonths} month(s), amount: ${result.amount}`,
      'success',
      { instanceId: instance.id }
    )

    console.log(`[Billing] Auto-renewed instance ${instance.id}`)

  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error'
    console.error(`[Billing] Auto-renew failed for instance ${instance.id}:`, errorMessage)
    await updateAutoRenewAttempt(instance.id, attempts)

    // 发送失败站内通知
    await sendNotification(instance.userId, 'auto_renew_failed', {
      instanceName: instance.name,
      failReason: errorMessage
    })

    // 发送自动续费失败邮件
    const userForEmail = await prisma.user.findUnique({
      where: { id: instance.userId },
      select: { email: true, username: true }
    })
    if (userForEmail?.email) {
      try {
        await sendAutoRenewFailedEmail(userForEmail.email, {
          username: userForEmail.username,
          instanceName: instance.name,
          failReason: errorMessage,
          currentAttempt: attempts,
          maxAttempts: AUTO_RENEW_MAX_ATTEMPTS,
          expiresAt: instance.expiresAt
        })
      } catch (emailErr) {
        console.warn(`[Billing] Failed to send auto-renew failed email:`, emailErr)
      }
    }

    await createLog(
      instance.userId,
      'instance',
      'instance.auto_renew_failed',
      `Auto-renew failed for instance "${instance.name}": ${errorMessage}`,
      'failed',
      { instanceId: instance.id }
    )
  }
}

// ==================== 到期封停任务 ====================

/**
 * 执行到期封停
 */
async function executeExpirySuspend(): Promise<void> {
  console.log('[Billing] Starting expiry suspend job...')
  const startTime = Date.now()

  try {
    // 获取已到期但未封停的实例
    const instances = await getExpiredUnsuspendedInstances()

    console.log(`[Billing] Found ${instances.length} expired instances to suspend`)

    // 并发处理
    await Promise.all(
      instances.map(instance =>
        limit(() => processExpirySuspend(instance))
      )
    )

    const duration = Date.now() - startTime
    console.log(`[Billing] Expiry suspend job completed in ${duration}ms`)
  } catch (error) {
    console.error('[Billing] Expiry suspend job failed:', error)
  }
}

/**
 * 处理单个实例的到期封停
 */
async function processExpirySuspend(instance: any): Promise<void> {
  try {
    // 封停实例
    const suspended = await suspendInstanceByExpiry(instance.id, async () => {
      // 在实例锁仍持有时停止外部实例，避免续费解封后又被旧任务停止。
      try {
        const host = await db.getHostById(instance.hostId)
        if (host) {
          const client = await getIncusClient(host)
          const { stopInstance } = await import('../lib/incus/index.js')
          await stopInstance(client, instance.incusId, true) // force stop
        }
      } catch (stopError) {
        // 停止失败不影响数据库封停逻辑
        console.log(`[Billing] Failed to stop Incus instance ${instance.incusId}:`, stopError)
      }
    })
    if (!suspended) {
      console.log(`[Billing] Skipped expiry suspension for instance ${instance.id}: status changed or not provisioned`)
      return
    }

    // 发送封停通知
    await sendNotification(instance.userId, 'instance_suspended', {
      instanceName: instance.name,
      suspendReason: '实例已到期'
    })

    await createLog(
      instance.userId,
      'instance',
      'instance.suspended_expired',
      `Instance "${instance.name}" suspended due to expiry`,
      'success',
      { instanceId: instance.id }
    )

    console.log(`[Billing] Suspended expired instance ${instance.id}`)

  } catch (error) {
    console.error(`[Billing] Failed to suspend instance ${instance.id}:`, error)
  }
}

// ==================== 到期删除任务 ====================

/**
 * 执行到期删除（封停超过3天的实例）
 */
async function executeExpiryDelete(): Promise<void> {
  console.log('[Billing] Starting expiry delete job...')
  const startTime = Date.now()

  try {
    // 获取封停超过3天的实例（仅限到期封停的）
    const instances = await getSuspendedInstancesOlderThan(SUSPEND_AFTER_DELETE_DAYS)

    // 过滤出到期封停的（非手动封停）
    const expiredInstances = instances.filter(i => i.suspendReason === 'expired')

    console.log(`[Billing] Found ${expiredInstances.length} expired instances to delete`)

    // 串行处理删除（避免并发问题）
    for (const instance of expiredInstances) {
      await processExpiryDelete(instance)
      await delay(1000) // 间隔1秒
    }

    const duration = Date.now() - startTime
    console.log(`[Billing] Expiry delete job completed in ${duration}ms`)
  } catch (error) {
    console.error('[Billing] Expiry delete job failed:', error)
  }
}

/**
 * 处理单个实例的到期删除
 */
async function processExpiryDelete(instance: any): Promise<void> {
  let claimVersion: number | null = null
  try {
    if (!instance.suspendedAt) return

    // 先在数据库中认领，再执行外部删除；续费必须通过同一实例锁和版本
    // 检查，因此不会在本任务拿到旧快照后误删刚续费的 Incus 实例。
    const claimed = await claimExpiredInstanceForDeletion(
      instance.id,
      instance.version,
      instance.suspendedAt
    )
    if (!claimed) {
      console.log(`[Billing] Skipped expired instance ${instance.id}: state changed or already claimed`)
      return
    }
    claimVersion = claimed.version

    const host = await db.getHostById(claimed.hostId)
    if (!host) {
      throw new Error(`Host ${claimed.hostId} not found while deleting expired instance ${claimed.id}`)
    }
    const client = await getIncusClient(host)

    // 尝试删除 Incus 实例
    try {
      await deleteIncusInstance(client, claimed.incusId)
    } catch (incusError) {
      const message = incusError instanceof Error ? incusError.message : String(incusError)
      // 删除接口幂等：实例已经不存在时可以继续清理数据库；其他错误必须保留记录，
      // 让下一轮调度重试，避免外部资源和数据库状态分叉。
      if (!message.toLowerCase().includes('not found')) {
        throw incusError
      }
      console.log(`[Billing] Incus instance ${claimed.incusId} already absent, continuing cleanup`)
    }

    const isNatNetwork = ['nat', 'nat_ipv6', 'nat_ipv6_nat', 'ipv6_nat', 'ipv6_only']
      .includes(claimed.networkMode)

    // 删除数据库记录和回滚资源必须是同一个事务，防止删除成功后资源回滚失败导致永久泄漏。
    const deleted = await deleteExpiredInstanceAndRollbackResources({
      instanceId: claimed.id,
      hostId: claimed.hostId,
      cpu: claimed.cpu,
      memory: claimed.memory,
      disk: claimed.disk,
      // 释放创建时按实例 portLimit 预占的数量，而不是实际映射数量。
      portCount: isNatNetwork ? (claimed.portLimit || 0) : 0,
      expectedVersion: claimed.version,
      expectedSuspendedAt: claimed.suspendedAt!
    })

    if (!deleted) {
      console.log(`[Billing] Skipped expired instance ${claimed.id}: record was already handled`)
      return
    }
    // 数据库清理已成功，后续通知失败不能把已删除实例恢复成候选。
    claimVersion = null

    // 发送删除通知
    await sendNotification(claimed.userId, 'instance_deleted', {
      instanceName: claimed.name
    })

    await createLog(
      claimed.userId,
      'instance',
      'instance.deleted_expired',
      `Instance "${claimed.name}" automatically deleted after ${SUSPEND_AFTER_DELETE_DAYS} days of suspension`,
      'success'
    )

    console.log(`[Billing] Deleted expired instance ${claimed.id}`)

    // 向套餐绑定的通知渠道发送"资源释放"通知
    if (claimed.packageId) {
      sendReleaseNotification({
        packageId: claimed.packageId,
        cpu: claimed.cpu,
        memory: claimed.memory,
        source: '实例过期自动删除'
      }).catch(() => {})
    }

  } catch (error) {
    if (claimVersion !== null) {
      const restored = await restoreExpiredInstanceDeletionClaim(instance.id, claimVersion).catch(restoreError => {
        console.error(`[Billing] Failed to restore expired deletion claim for instance ${instance.id}:`, restoreError)
        return false
      })
      if (!restored) {
        console.error(`[Billing] Expired deletion claim for instance ${instance.id} was not restored`)
      }
    }
    console.error(`[Billing] Failed to delete instance ${instance.id}:`, error)
  }
}

// ==================== 到期提醒任务 ====================

/**
 * 执行到期提醒（邮件）
 */
async function executeExpiryNotify(): Promise<void> {
  console.log('[Billing] Starting expiry notify job...')
  const startTime = Date.now()

  try {
    // 对每个提醒时间点检查（天数）
    for (const days of EXPIRY_NOTIFY_DAYS) {
      await notifyExpiringInstances(days)
    }

    const duration = Date.now() - startTime
    console.log(`[Billing] Expiry notify job completed in ${duration}ms`)
  } catch (error) {
    console.error('[Billing] Expiry notify job failed:', error)
  }
}

/**
 * 通知指定天数内到期的实例（发送邮件）
 */
async function notifyExpiringInstances(days: number): Promise<void> {
  const now = new Date()
  // 计算天数范围（前后12小时窗口）
  const minThreshold = new Date(now.getTime() + (days * 24 - 12) * 60 * 60 * 1000)
  const maxThreshold = new Date(now.getTime() + (days * 24 + 12) * 60 * 60 * 1000)

  // 查询在指定时间窗口内到期的实例
  const instances = await prisma.instance.findMany({
    where: {
      expiresAt: {
        gte: minThreshold,
        lt: maxThreshold
      },
      autoRenew: false,
      status: { notIn: ['suspended', 'deleted'] },
      // 在过去24小时内没有发送过通知
      OR: [
        { expiryNotifiedAt: null },
        { expiryNotifiedAt: { lt: new Date(now.getTime() - 24 * 60 * 60 * 1000) } }
      ]
    },
    include: {
      user: {
        select: { email: true, username: true }
      }
    }
  })

  console.log(`[Billing] Found ${instances.length} instances expiring in ${days} days`)

  // 并发发送邮件通知
  await Promise.all(
    instances.map(instance =>
      limit(async () => {
        try {
          const daysRemaining = days

          // 发送站内通知
          await sendNotification(instance.userId, 'instance_expiring', {
            instanceName: instance.name,
            daysRemaining,
            newExpiresAt: instance.expiresAt?.toISOString()
          })

          // 发送邮件通知
          if (instance.user?.email) {
            try {
              await sendExpiryReminderEmail(instance.user.email, {
                username: instance.user.username,
                instanceName: instance.name,
                daysRemaining,
                expiresAt: instance.expiresAt!
              })
            } catch (emailErr) {
              console.warn(`[Billing] Failed to send expiry email for instance ${instance.id}:`, emailErr)
            }
          }

          await updateExpiryNotifiedAt(instance.id)

          console.log(`[Billing] Sent expiry notification for instance ${instance.id}`)
        } catch (error) {
          console.error(`[Billing] Failed to notify instance ${instance.id}:`, error)
        }
      })
    )
  )
}

// ==================== 充值订单清理任务 ====================

/**
 * 清理过期的充值订单（pending状态且已过期）
 * 每小时执行，将过期订单标记为 cancelled
 */
async function cleanExpiredRechargeOrders(): Promise<void> {
  console.log('[Billing] Starting expired recharge orders cleanup job...')
  const startTime = Date.now()

  try {
    const result = await prisma.rechargeRecord.updateMany({
      where: {
        status: 'pending',
        expiredAt: { lt: new Date() }
      },
      data: {
        status: 'cancelled'
      }
    })

    const duration = Date.now() - startTime
    if (result.count > 0) {
      console.log(`[Billing] Cancelled ${result.count} expired recharge orders in ${duration}ms`)
    }
  } catch (error) {
    console.error('[Billing] Expired recharge orders cleanup failed:', error)
  }
}

/**
 * 清理旧的支付回调防重放记录（30天前）
 * 每天执行，避免数据无限增长
 */
async function cleanOldPaymentCallbacks(): Promise<void> {
  console.log('[Billing] Starting old payment callbacks cleanup job...')
  const startTime = Date.now()

  try {
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)
    const result = await prisma.paymentCallback.deleteMany({
      where: {
        createdAt: { lt: thirtyDaysAgo }
      }
    })

    const duration = Date.now() - startTime
    if (result.count > 0) {
      console.log(`[Billing] Deleted ${result.count} old payment callback records in ${duration}ms`)
    }
  } catch (error) {
    console.error('[Billing] Old payment callbacks cleanup failed:', error)
  }
}

/**
 * 清理过期的临时数据（验证码、Token 失效记录、Agent Nonce 等）
 * 每天凌晨 5:00 执行，防止临时表无限增长
 */
async function cleanExpiredTemporaryData(): Promise<void> {
  console.log('[Billing] Starting expired temporary data cleanup...')
  const startTime = Date.now()
  const now = new Date()
  const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)

  try {
    // 并行执行各表清理
    const [emailCodes, opVerifications, agentNonces, tokenInvalidations] = await Promise.all([
      // 清理过期的邮箱验证码
      prisma.emailVerificationCode.deleteMany({
        where: { expiresAt: { lt: now } }
      }),
      // 清理已过期的操作验证码（保留 7 天已验证的记录用于审计）
      prisma.operationVerification.deleteMany({
        where: {
          OR: [
            { expiresAt: { lt: now } },
            { verified: true, createdAt: { lt: sevenDaysAgo } }
          ]
        }
      }),
      // 清理过期的 Agent Nonce（防重放）
      prisma.hostAgentNonce.deleteMany({
        where: { expiresAt: { lt: now } }
      }),
      // 清理 30 天前的 Token 失效记录
      prisma.tokenInvalidation.deleteMany({
        where: { createdAt: { lt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) } }
      })
    ])

    const duration = Date.now() - startTime
    const total = emailCodes.count + opVerifications.count + agentNonces.count + tokenInvalidations.count
    if (total > 0) {
      console.log(
        `[Billing] Cleaned expired temp data in ${duration}ms: ` +
        `emailCodes=${emailCodes.count}, opVerifications=${opVerifications.count}, ` +
        `agentNonces=${agentNonces.count}, tokenInvalidations=${tokenInvalidations.count}`
      )
    }
  } catch (error) {
    console.error('[Billing] Expired temporary data cleanup failed:', error)
  }
}

// ==================== 调度器入口 ====================

/**
 * 启动计费调度器
 */
export function startBillingScheduler(): void {
  // 每小时检查自动续费（整点）
  schedule('0 * * * *', () => {
    executeAutoRenew().catch(console.error)
  })

  // 每30分钟检查到期封停
  schedule('*/30 * * * *', () => {
    executeExpirySuspend().catch(console.error)
  })

  // 每天凌暨3点检查到期删除
  schedule('0 3 * * *', () => {
    executeExpiryDelete().catch(console.error)
  })

  // 每小时检查到期提醒
  schedule('15 * * * *', () => {
    executeExpiryNotify().catch(console.error)
  })

  // 每小时清理过期的充值订单（在 :30 执行）
  schedule('30 * * * *', () => {
    cleanExpiredRechargeOrders().catch(console.error)
  })

  // 每天凌晨 4:30 清理旧的支付回调防重放记录（30天前）
  schedule('30 4 * * *', () => {
    cleanOldPaymentCallbacks().catch(console.error)
  })

  // 每天凌晨 5:00 清理过期的临时数据（验证码、Token 失效、Agent Nonce）
  schedule('0 5 * * *', () => {
    cleanExpiredTemporaryData().catch(console.error)
  })

  console.log('[Billing] Scheduler started')
  console.log('[Billing] - Auto-renew: hourly at :00 (24h before expiry, max 3 attempts)')
  console.log('[Billing] - Expiry suspend: every 30 minutes')
  console.log('[Billing] - Expiry delete: daily at 03:00 (3 days after suspend)')
  console.log('[Billing] - Expiry notify (email): hourly at :15 (3 days before, auto-renew instances skipped)')
  console.log('[Billing] - Expired recharge cleanup: hourly at :30')
  console.log('[Billing] - Payment callback cleanup: daily at 04:30')
  console.log('[Billing] - Temporary data cleanup: daily at 05:00')
}

/**
 * 手动运行所有计费任务（用于测试）
 */
export async function runAllBillingJobs(): Promise<void> {
  await executeAutoRenew()
  await executeExpirySuspend()
  await executeExpiryDelete()
  await executeExpiryNotify()
}

// 导出单独的任务函数（用于测试）
export {
  executeAutoRenew,
  executeExpirySuspend,
  executeExpiryDelete,
  executeExpiryNotify,
  cleanExpiredRechargeOrders,
  cleanOldPaymentCallbacks,
  cleanExpiredTemporaryData
}
