/**
 * 用户余额相关数据库操作
 * 使用 Prisma ORM
 */

import { prisma } from './prisma.js'
import { Prisma, type BalanceLog, type BalanceLogType, type User } from '@prisma/client'
import {
  MAX_USER_BALANCE,
  createBalanceTransferNo,
  normalizeBalanceTransferAmount,
  normalizeBalanceTransferFee,
  roundMoney
} from '../lib/balance-transfer.js'

type BalanceQueryClient = typeof prisma | Prisma.TransactionClient

// 余额事务使用 Serializable 隔离级别，防止并发读写导致余额不一致
const BALANCE_TRANSACTION_OPTIONS = {
  isolationLevel: Prisma.TransactionIsolationLevel.Serializable,
  timeout: 10000,
} as const

function isRetryableBalanceTransactionError(error: unknown): boolean {
  if (!(error instanceof Error)) return false
  const prismaError = error as Error & { code?: string }
  return prismaError.code === 'P2034' ||
    prismaError.message.includes('deadlock') ||
    prismaError.message.includes('write conflict') ||
    prismaError.message.includes('could not serialize')
}

async function runBalanceTransaction<T>(handler: (tx: Prisma.TransactionClient) => Promise<T>): Promise<T> {
  const maxRetries = 3
  let lastError: unknown = null

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await prisma.$transaction(handler, BALANCE_TRANSACTION_OPTIONS)
    } catch (error) {
      lastError = error
      if (!isRetryableBalanceTransactionError(error) || attempt === maxRetries) {
        throw error
      }

      const delay = (Math.floor(Math.random() * 120) + 40) * attempt
      await new Promise(resolve => setTimeout(resolve, delay))
    }
  }

  throw lastError
}

function toNumber(value: unknown): number {
  if (value === null || value === undefined) return 0
  const numberValue = Number(value)
  return Number.isFinite(numberValue) ? numberValue : 0
}

// ==================== 余额查询 ====================

/**
 * 获取用户余额
 */
export async function getUserBalance(userId: number): Promise<number> {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { balance: true }
  })
  return user ? Number(user.balance) : 0
}

// 余额日志带实例信息的类型
export type BalanceLogWithInstance = BalanceLog & {
  instance?: { id: number; name: string } | null
}

/**
 * 获取用户余额变动日志（分页）
 * 包含关联的实例名称
 * @param lotteryGift - 'exclude' 排除抽奖赠送记录（默认）, 'only' 仅显示抽奖赠送记录, undefined 显示全部
 */
export async function getBalanceLogs(
  userId: number,
  options: {
    page?: number
    pageSize?: number
    type?: BalanceLogType
    lotteryGift?: 'exclude' | 'only'
  } = {}
): Promise<{
  logs: BalanceLogWithInstance[]
  total: number
  page: number
  pageSize: number
}> {
  const { page = 1, pageSize = 20, type, lotteryGift } = options
  const skip = (page - 1) * pageSize

  // 构建查询条件
  const where: Prisma.BalanceLogWhereInput = {
    userId,
    ...(type ? { type } : {})
  }

  // 处理抽奖赠送筛选（抽奖赠送特征：type='gift' AND remark 包含 '抽奖中奖'）
  if (lotteryGift === 'exclude') {
    // 排除抽奖赠送：NOT (type='gift' AND remark contains '抽奖中奖')
    where.NOT = {
      type: 'gift',
      remark: { contains: '抽奖中奖' }
    }
  } else if (lotteryGift === 'only') {
    // 仅抽奖赠送
    where.type = 'gift'
    where.remark = { contains: '抽奖中奖' }
  }

  const [logs, total] = await Promise.all([
    prisma.balanceLog.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      skip,
      take: pageSize
    }),
    prisma.balanceLog.count({ where })
  ])

  // 查询关联的实例信息
  const instanceIds = logs.filter(l => l.instanceId).map(l => l.instanceId!) as number[]
  const instances = instanceIds.length > 0
    ? await prisma.instance.findMany({
        where: { id: { in: instanceIds } },
        select: { id: true, name: true }
      })
    : []
  const instanceMap = new Map(instances.map(i => [i.id, i]))

  // 合并实例信息
  const logsWithInstance: BalanceLogWithInstance[] = logs.map(log => ({
    ...log,
    instance: log.instanceId ? instanceMap.get(log.instanceId) || null : null
  }))

  return { logs: logsWithInstance, total, page, pageSize }
}

// ==================== 余额变动操作（事务安全） ====================

export interface BalanceChangeInput {
  userId: number
  type: BalanceLogType
  amount: number // 正数=增加，负数=减少
  orderId?: string
  instanceId?: number
  remark?: string
}

export interface BalanceChangeResult {
  success: boolean
  balanceLog?: BalanceLog
  newBalance?: number
  error?: string
}

export interface BalanceTransferPreview {
  transferNo?: string
  fromUserId: number
  recipient: Pick<User, 'id' | 'username' | 'email' | 'avatarStyle' | 'avatarBadgeId'>
  amount: number
  fee: number
  totalDeduction: number
  currentBalance: number
  balanceAfter: number
}

export async function buildBalanceTransferPreview(input: {
  fromUserId: number
  recipientId: number
  amount: number
  fee: number
}): Promise<BalanceTransferPreview> {
  const amount = normalizeBalanceTransferAmount(input.amount)
  const fee = normalizeBalanceTransferFee(input.fee)

  if (input.fromUserId === input.recipientId) {
    throw new Error('BALANCE_TRANSFER_TO_SELF')
  }

  const [sender, recipient] = await Promise.all([
    prisma.user.findUnique({
      where: { id: input.fromUserId },
      select: { balance: true }
    }),
    prisma.user.findUnique({
      where: { id: input.recipientId },
      select: { id: true, username: true, email: true, avatarStyle: true, avatarBadgeId: true, status: true, balance: true }
    })
  ])

  if (!sender || !recipient) {
    throw new Error('USER_NOT_FOUND')
  }

  if (recipient.status === 'banned') {
    throw new Error('BALANCE_TRANSFER_RECIPIENT_BANNED')
  }

  if (roundMoney(Number(recipient.balance) + amount) > MAX_USER_BALANCE) {
    throw new Error('BALANCE_TRANSFER_BALANCE_LIMIT_EXCEEDED')
  }

  const currentBalance = Number(sender.balance)
  const totalDeduction = roundMoney(amount + fee)
  const balanceAfter = roundMoney(currentBalance - totalDeduction)
  if (balanceAfter < 0) {
    throw new Error('BALANCE_TRANSFER_INSUFFICIENT_BALANCE')
  }

  return {
    fromUserId: input.fromUserId,
    recipient: {
      id: recipient.id,
      username: recipient.username,
      email: recipient.email,
      avatarStyle: recipient.avatarStyle,
      avatarBadgeId: recipient.avatarBadgeId
    },
    amount,
    fee,
    totalDeduction,
    currentBalance,
    balanceAfter
  }
}

export async function transferBalanceBetweenUsers(input: {
  fromUserId: number
  recipientId: number
  amount: number
  fee: number
}): Promise<BalanceTransferPreview & { transferNo: string }> {
  const amount = normalizeBalanceTransferAmount(input.amount)
  const fee = normalizeBalanceTransferFee(input.fee)

  if (input.fromUserId === input.recipientId) {
    throw new Error('BALANCE_TRANSFER_TO_SELF')
  }

  return runBalanceTransaction(async (tx) => {
    const [sender, recipient] = await Promise.all([
      tx.user.findUnique({
        where: { id: input.fromUserId },
        select: { id: true, username: true, balance: true }
      }),
      tx.user.findUnique({
        where: { id: input.recipientId },
        select: { id: true, username: true, email: true, avatarStyle: true, avatarBadgeId: true, status: true, balance: true }
      })
    ])

    if (!sender || !recipient) {
      throw new Error('USER_NOT_FOUND')
    }

    if (recipient.status === 'banned') {
      throw new Error('BALANCE_TRANSFER_RECIPIENT_BANNED')
    }

    const totalDeduction = roundMoney(amount + fee)
    const senderBalanceBefore = Number(sender.balance)
    const senderBalanceAfterTransfer = roundMoney(senderBalanceBefore - amount)
    const senderBalanceAfterFee = roundMoney(senderBalanceAfterTransfer - fee)

    if (senderBalanceAfterFee < 0) {
      throw new Error('BALANCE_TRANSFER_INSUFFICIENT_BALANCE')
    }

    const recipientBalanceBefore = Number(recipient.balance)
    const recipientBalanceAfter = roundMoney(recipientBalanceBefore + amount)
    if (recipientBalanceAfter > MAX_USER_BALANCE) {
      throw new Error('BALANCE_TRANSFER_BALANCE_LIMIT_EXCEEDED')
    }

    const transferNo = createBalanceTransferNo()

    await tx.user.update({
      where: { id: sender.id },
      data: { balance: senderBalanceAfterFee }
    })

    await tx.user.update({
      where: { id: recipient.id },
      data: { balance: recipientBalanceAfter }
    })

    await tx.balanceLog.create({
      data: {
        userId: sender.id,
        type: 'balance_transfer_out',
        amount: -amount,
        balanceBefore: senderBalanceBefore,
        balanceAfter: senderBalanceAfterTransfer,
        orderId: transferNo,
        remark: `转账给 ${recipient.username}`
      }
    })

    if (fee > 0) {
      await tx.balanceLog.create({
        data: {
          userId: sender.id,
          type: 'balance_transfer_fee',
          amount: -fee,
          balanceBefore: senderBalanceAfterTransfer,
          balanceAfter: senderBalanceAfterFee,
          orderId: transferNo,
          remark: `余额转账手续费`
        }
      })
    }

    await tx.balanceLog.create({
      data: {
        userId: recipient.id,
        type: 'balance_transfer_in',
        amount,
        balanceBefore: recipientBalanceBefore,
        balanceAfter: recipientBalanceAfter,
        orderId: transferNo,
        remark: `收到 ${sender.username} 转账`
      }
    })

    return {
      transferNo,
      fromUserId: sender.id,
      recipient: {
        id: recipient.id,
        username: recipient.username,
        email: recipient.email,
        avatarStyle: recipient.avatarStyle,
        avatarBadgeId: recipient.avatarBadgeId
      },
      amount,
      fee,
      totalDeduction,
      currentBalance: senderBalanceBefore,
      balanceAfter: senderBalanceAfterFee
    }
  })
}

/**
 * 变更用户余额（事务安全）
 * 所有余额变动都应该通过这个函数进行，确保日志记录和数据一致性
 */
export async function changeBalance(
  input: BalanceChangeInput
): Promise<BalanceChangeResult> {
  const { userId, type, amount, orderId, instanceId, remark } = input

  try {
    const result = await runBalanceTransaction(async (tx) => {
      // 1. 获取当前余额（Serializable 隔离保证读取的值不会被其他事务修改）
      const user = await tx.user.findUnique({
        where: { id: userId },
        select: { balance: true }
      })

      if (!user) {
        throw new Error('用户不存在')
      }

      const balanceBefore = Number(user.balance)
      const balanceAfter = roundMoney(balanceBefore + amount)

      // 2. 检查余额是否足够（如果是扣款）
      if (amount < 0 && balanceAfter < 0) {
        throw new Error('余额不足')
      }

      // 3. 更新用户余额
      await tx.user.update({
        where: { id: userId },
        data: { balance: balanceAfter }
      })

      // 4. 创建余额变动日志
      const balanceLog = await tx.balanceLog.create({
        data: {
          userId,
          type,
          amount,
          balanceBefore,
          balanceAfter,
          orderId,
          instanceId,
          remark
        }
      })

      return { balanceLog, newBalance: balanceAfter }
    })

    return {
      success: true,
      balanceLog: result.balanceLog,
      newBalance: result.newBalance
    }
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : '余额变动失败'
    }
  }
}

/**
 * 充值到账（从充值订单完成）
 */
export async function rechargeToBalance(
  userId: number,
  amount: number,
  orderId: string,
  remark?: string
): Promise<BalanceChangeResult> {
  return changeBalance({
    userId,
    type: 'recharge',
    amount,
    orderId,
    remark: remark || `充值订单 ${orderId}`
  })
}

/**
 * 消费扣款（开通/续费实例）
 */
export async function consumeBalance(
  userId: number,
  amount: number,
  instanceId: number,
  remark?: string
): Promise<BalanceChangeResult> {
  return changeBalance({
    userId,
    type: 'consume',
    amount: -Math.abs(amount), // 确保是负数
    instanceId,
    remark
  })
}

/**
 * 退款到余额
 */
export async function refundToBalance(
  userId: number,
  amount: number,
  instanceId: number,
  remark?: string
): Promise<BalanceChangeResult> {
  return changeBalance({
    userId,
    type: 'refund',
    amount: Math.abs(amount), // 确保是正数
    instanceId,
    remark
  })
}

/**
 * 管理员调整余额
 */
export async function adminAdjustBalance(
  userId: number,
  amount: number,
  remark: string
): Promise<BalanceChangeResult> {
  return changeBalance({
    userId,
    type: 'admin_adjust',
    amount,
    remark
  })
}

/**
 * 赠送余额
 */
export async function giftBalance(
  userId: number,
  amount: number,
  remark?: string
): Promise<BalanceChangeResult> {
  return changeBalance({
    userId,
    type: 'gift',
    amount: Math.abs(amount), // 确保是正数
    remark
  })
}

/**
 * 获取用户实际消费额。
 * 历史上部分业务把 consume.amount 写成正数，不能直接 SUM(amount) 再取绝对值。
 * 这里优先使用余额前后差额，兼容正负号不一致的历史日志。
 */
export async function getUsersTotalConsumeMap(
  userIds: number[],
  client: BalanceQueryClient = prisma
): Promise<Map<number, number>> {
  const validUserIds = Array.from(new Set(
    userIds.filter(id => Number.isInteger(id) && id > 0)
  ))

  if (validUserIds.length === 0) {
    return new Map()
  }

  const rows = await client.$queryRaw<Array<{ userId: number; totalConsume: unknown }>>(Prisma.sql`
    SELECT
      user_id AS "userId",
      COALESCE(SUM(
        CASE
          WHEN balance_before > balance_after THEN balance_before - balance_after
          ELSE ABS(amount)
        END
      ), 0)::numeric AS "totalConsume"
    FROM balance_logs
    WHERE user_id IN (${Prisma.join(validUserIds)})
      AND type IN ('consume', 'hourly_consume')
    GROUP BY user_id
  `)

  return new Map(rows.map(row => [row.userId, toNumber(row.totalConsume)]))
}

export async function getUserTotalConsume(
  userId: number,
  client: BalanceQueryClient = prisma
): Promise<number> {
  const consumeMap = await getUsersTotalConsumeMap([userId], client)
  return consumeMap.get(userId) || 0
}

// ==================== 检查操作 ====================

/**
 * 检查用户余额是否足够
 */
export async function hasEnoughBalance(
  userId: number,
  amount: number
): Promise<boolean> {
  const balance = await getUserBalance(userId)
  return balance >= amount
}

/**
 * 获取用户消费统计
 */
export async function getUserConsumeStats(userId: number): Promise<{
  totalRecharge: number
  totalConsume: number
  totalRefund: number
  totalDestroyedValue: number
}> {
  const [logs, destroyedRefund, totalConsume] = await Promise.all([
    prisma.balanceLog.groupBy({
      by: ['type'],
      where: { userId },
      _sum: { amount: true }
    }),
    prisma.balanceLog.aggregate({
      where: {
        userId,
        type: 'refund',
        amount: { gt: 0 },
        remark: { contains: '用户销毁实例退款' }
      },
      _sum: { amount: true }
    }),
    getUserTotalConsume(userId)
  ])

  const stats = {
    totalRecharge: 0,
    totalConsume,
    totalRefund: 0,
    totalDestroyedValue: destroyedRefund._sum.amount !== null && destroyedRefund._sum.amount !== undefined
      ? parseFloat(String(destroyedRefund._sum.amount))
      : 0
  }

  for (const log of logs) {
    // 注意：Prisma aggregate 返回的 Decimal 类型需要先转为字符串再转数字
    const amount = log._sum.amount !== null
      ? parseFloat(String(log._sum.amount))
      : 0
    switch (log.type) {
      case 'recharge':
        stats.totalRecharge = amount
        break
      case 'refund':
        stats.totalRefund = amount
        break
    }
  }

  return stats
}

/**
 * 获取实例的历史消费总额（用于退款上限计算）
 */
export async function getInstanceTotalConsume(instanceId: number): Promise<number> {
  const result = await prisma.balanceLog.aggregate({
    where: {
      instanceId,
      type: 'consume'
    },
    _sum: { amount: true }
  })
  // 注意：Prisma aggregate 返回的 Decimal 类型需要先转为字符串再转数字
  return result._sum.amount !== null
    ? Math.abs(parseFloat(String(result._sum.amount)))
    : 0
}

/**
 * 获取实例的历史退款总额
 */
export async function getInstanceTotalRefund(instanceId: number): Promise<number> {
  const result = await prisma.balanceLog.aggregate({
    where: {
      instanceId,
      type: 'refund'
    },
    _sum: { amount: true }
  })
  // 注意：Prisma aggregate 返回的 Decimal 类型需要先转为字符串再转数字
  return result._sum.amount !== null
    ? parseFloat(String(result._sum.amount))
    : 0
}

/**
 * 计算实例可退款金额（历史消费 - 已退款）
 */
export async function getInstanceRefundableAmount(instanceId: number): Promise<number> {
  const [totalConsume, totalRefund] = await Promise.all([
    getInstanceTotalConsume(instanceId),
    getInstanceTotalRefund(instanceId)
  ])
  return Math.max(0, totalConsume - totalRefund)
}
