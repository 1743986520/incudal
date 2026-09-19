/**
 * 余额管理路由
 */

import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify'
import * as db from '../db/index.js'
import { createLog } from '../db/logs.js'
import { apiError, ErrorCode } from '../lib/errors.js'
import { sendBalanceAdjustedEmail } from '../lib/mailer.js'

const balanceTransferErrorStatus: Record<string, number> = {
  USER_NOT_FOUND: 404,
  BALANCE_TRANSFER_DISABLED: 403,
  BALANCE_TRANSFER_TO_SELF: 400,
  BALANCE_TRANSFER_RECIPIENT_BANNED: 400,
  BALANCE_TRANSFER_AMOUNT_INVALID: 400,
  BALANCE_TRANSFER_INSUFFICIENT_BALANCE: 400,
  BALANCE_TRANSFER_BALANCE_LIMIT_EXCEEDED: 400
}

function mapBalanceTransferError(error: unknown): { status: number; code: typeof ErrorCode[keyof typeof ErrorCode] } {
  const message = error instanceof Error ? error.message : String(error)
  if (message === 'USER_NOT_FOUND') {
    return { status: 404, code: ErrorCode.USER_NOT_FOUND }
  }
  if (message in balanceTransferErrorStatus && message in ErrorCode) {
    return {
      status: balanceTransferErrorStatus[message],
      code: ErrorCode[message as keyof typeof ErrorCode]
    }
  }
  return { status: 500, code: ErrorCode.INTERNAL_ERROR }
}

export default async function balanceRoutes(fastify: FastifyInstance) {
  // ==================== 用户余额 API ====================

  // 获取当前用户余额
  fastify.get('/me', {
    onRequest: [fastify.authenticate]
  }, async (request: FastifyRequest) => {
    const { user } = request
    const balanceAmount = await db.getUserBalance(user.id)
    const stats = await db.getUserConsumeStats(user.id)

    return {
      balance: {
        balance: balanceAmount,
        frozen: 0,  // 暂无冻结功能
        totalRecharge: stats.totalRecharge,
        totalConsume: stats.totalConsume,
        destroyedValue: stats.totalDestroyedValue
      }
    }
  })

  // 获取当前用户余额变动日志
  fastify.get<{
    Querystring: {
      page?: string
      pageSize?: string
      type?: string
      lotteryGift?: string
    }
  }>('/me/logs', {
    onRequest: [fastify.authenticate]
  }, async (request: FastifyRequest<{ Querystring: { page?: string; pageSize?: string; type?: string; lotteryGift?: string } }>) => {
    const { user } = request
    const { type, lotteryGift } = request.query

    const result = await db.getBalanceLogs(user.id, {
      ...db.parsePagination(request.query, { maxPageSize: 100 }),
      type: type as any,
      lotteryGift: (lotteryGift === 'exclude' || lotteryGift === 'only') ? lotteryGift : undefined
    })

    return {
      records: result.logs.map(log => ({
        id: log.id,
        type: log.type,
        amount: Number(log.amount),
        balanceBefore: Number(log.balanceBefore),
        balanceAfter: Number(log.balanceAfter),
        orderId: log.orderId,
        instanceId: log.instanceId,
        instanceName: log.instance?.name || null,
        remark: log.remark,
        createdAt: log.createdAt.toISOString()
      })),
      total: result.total,
      page: result.page,
      pageSize: result.pageSize
    }
  })

  // 获取当前用户计费记录
  fastify.get<{
    Querystring: {
      page?: string
      pageSize?: string
      type?: string
    }
  }>('/me/billing', {
    onRequest: [fastify.authenticate]
  }, async (request: FastifyRequest<{ Querystring: { page?: string; pageSize?: string; type?: string } }>) => {
    const { user } = request
    const { page = '1', pageSize = '20', type } = request.query

    const result = await db.getUserBillingRecords(user.id, {
      page: Number(page),
      pageSize: Number(pageSize),
      type: type as any
    })

    const stats = await db.getUserBillingStats(user.id)

    return {
      records: result.records.map(record => ({
        id: record.id,
        instanceId: record.instanceId,
        instance: (record as any).instance ? {
          id: (record as any).instance.id,
          name: (record as any).instance.name
        } : null,
        type: record.type,
        amount: Number(record.amount),
        months: record.months,
        periodStart: record.periodStart.toISOString(),
        periodEnd: record.periodEnd.toISOString(),
        remark: record.remark,
        createdAt: record.createdAt.toISOString()
      })),
      total: result.total,
      page: result.page,
      pageSize: result.pageSize,
      stats
    }
  })

  // 解析余额转账收款人
  fastify.get<{
    Querystring: { username: string }
  }>('/transfer/recipient', {
    onRequest: [fastify.authenticateUser],
    config: { rateLimit: { max: 30, timeWindow: '1 minute' } }
  }, async (request: FastifyRequest<{ Querystring: { username: string } }>, reply: FastifyReply) => {
    const transferEnabled = await db.getSystemConfigBoolean('balance_transfer_enabled', false)
    if (!transferEnabled) {
      return reply.code(403).send(apiError(ErrorCode.BALANCE_TRANSFER_DISABLED))
    }

    const username = request.query.username?.trim()
    if (!username || username.length < 2) {
      return reply.code(400).send(apiError(ErrorCode.INVALID_PARAMS, 'Username must be at least 2 characters'))
    }

    const recipient = await db.findUserByUsername(username)
    if (!recipient) {
      return reply.code(404).send(apiError(ErrorCode.USER_NOT_FOUND))
    }
    if (recipient.id === request.user.id) {
      return reply.code(400).send(apiError(ErrorCode.BALANCE_TRANSFER_TO_SELF))
    }
    if (recipient.status === 'banned') {
      return reply.code(400).send(apiError(ErrorCode.BALANCE_TRANSFER_RECIPIENT_BANNED))
    }

    return {
      recipient: {
        id: recipient.id,
        username: recipient.username,
        avatarStyle: recipient.avatar_style,
        avatarBadgeId: recipient.avatar_badge_id ?? null
      }
    }
  })

  // 预览余额转账
  fastify.post<{
    Body: { recipientId: number; amount: number }
  }>('/transfer/preview', {
    onRequest: [fastify.authenticateUser],
    config: { rateLimit: { max: 30, timeWindow: '1 minute' } },
    schema: {
      body: {
        type: 'object',
        required: ['recipientId', 'amount'],
        properties: {
          recipientId: { type: 'integer', minimum: 1 },
          amount: { type: 'number', minimum: 0.01 }
        }
      }
    }
  }, async (request: FastifyRequest<{ Body: { recipientId: number; amount: number } }>, reply: FastifyReply) => {
    const transferEnabled = await db.getSystemConfigBoolean('balance_transfer_enabled', false)
    if (!transferEnabled) {
      return reply.code(403).send(apiError(ErrorCode.BALANCE_TRANSFER_DISABLED))
    }

    try {
      const fee = await db.getSystemConfigFloat('balance_transfer_fee', 0)
      const preview = await db.buildBalanceTransferPreview({
        fromUserId: request.user.id,
        recipientId: request.body.recipientId,
        amount: request.body.amount,
        fee
      })

      return {
        preview: {
          recipient: {
            id: preview.recipient.id,
            username: preview.recipient.username,
            avatarStyle: preview.recipient.avatarStyle,
            avatarBadgeId: preview.recipient.avatarBadgeId ?? null
          },
          amount: preview.amount,
          fee: preview.fee,
          totalDeduction: preview.totalDeduction,
          currentBalance: preview.currentBalance,
          balanceAfter: preview.balanceAfter
        }
      }
    } catch (error) {
      const mapped = mapBalanceTransferError(error)
      return reply.code(mapped.status).send(apiError(mapped.code))
    }
  })

  // 提交余额转账
  fastify.post<{
    Body: { recipientId: number; amount: number }
  }>('/transfer', {
    onRequest: [fastify.authenticateUser],
    config: { rateLimit: { max: 10, timeWindow: '1 minute' } },
    schema: {
      body: {
        type: 'object',
        required: ['recipientId', 'amount'],
        properties: {
          recipientId: { type: 'integer', minimum: 1 },
          amount: { type: 'number', minimum: 0.01 }
        }
      }
    }
  }, async (request: FastifyRequest<{ Body: { recipientId: number; amount: number } }>, reply: FastifyReply) => {
    const transferEnabled = await db.getSystemConfigBoolean('balance_transfer_enabled', false)
    if (!transferEnabled) {
      return reply.code(403).send(apiError(ErrorCode.BALANCE_TRANSFER_DISABLED))
    }

    try {
      const fee = await db.getSystemConfigFloat('balance_transfer_fee', 0)
      const result = await db.transferBalanceBetweenUsers({
        fromUserId: request.user.id,
        recipientId: request.body.recipientId,
        amount: request.body.amount,
        fee
      })

      await createLog(
        request.user.id,
        'balance',
        'balance.transfer',
        `Transferred ${result.amount} to user ${result.recipient.username}, fee ${result.fee}, transferNo ${result.transferNo}`,
        'success'
      )

      return {
        transfer: {
          transferNo: result.transferNo,
          recipient: {
            id: result.recipient.id,
            username: result.recipient.username,
            avatarStyle: result.recipient.avatarStyle,
            avatarBadgeId: result.recipient.avatarBadgeId ?? null
          },
          amount: result.amount,
          fee: result.fee,
          totalDeduction: result.totalDeduction,
          currentBalance: result.currentBalance,
          balanceAfter: result.balanceAfter
        }
      }
    } catch (error) {
      const mapped = mapBalanceTransferError(error)
      return reply.code(mapped.status).send(apiError(mapped.code))
    }
  })

  // ==================== 管理员余额管理 API ====================

  // 获取用户余额（管理员）
  fastify.get<{ Params: { userId: string } }>('/admin/:userId', {
    onRequest: [fastify.authenticate, fastify.requireAdmin]
  }, async (request: FastifyRequest<{ Params: { userId: string } }>, reply: FastifyReply) => {
    const userId = Number(request.params.userId)
    if (isNaN(userId)) {
      return reply.code(400).send(apiError(ErrorCode.INVALID_ID))
    }

    const targetUser = await db.findUserById(userId)
    if (!targetUser) {
      return reply.code(404).send(apiError(ErrorCode.USER_NOT_FOUND))
    }

    const balance = await db.getUserBalance(userId)
    const stats = await db.getUserConsumeStats(userId)

    return {
      userId,
      username: targetUser.username,
      balance,
      ...stats
    }
  })

  // 获取用户余额日志（管理员）
  fastify.get<{
    Params: { userId: string }
    Querystring: {
      page?: string
      pageSize?: string
      type?: string
      lotteryGift?: string
    }
  }>('/admin/:userId/logs', {
    onRequest: [fastify.authenticate, fastify.requireAdmin]
  }, async (request: FastifyRequest<{ Params: { userId: string }; Querystring: { page?: string; pageSize?: string; type?: string; lotteryGift?: string } }>, reply: FastifyReply) => {
    const userId = Number(request.params.userId)
    if (isNaN(userId)) {
      return reply.code(400).send(apiError(ErrorCode.INVALID_ID))
    }

    const { type, lotteryGift } = request.query

    const result = await db.getBalanceLogs(userId, {
      ...db.parsePagination(request.query, { maxPageSize: 100 }),
      type: type as any,
      lotteryGift: (lotteryGift === 'exclude' || lotteryGift === 'only') ? lotteryGift : undefined
    })

    return {
      logs: result.logs.map(log => ({
        id: log.id,
        type: log.type,
        amount: Number(log.amount),
        balanceBefore: Number(log.balanceBefore),
        balanceAfter: Number(log.balanceAfter),
        orderId: log.orderId,
        instanceId: log.instanceId,
        instanceName: log.instance?.name || null,
        remark: log.remark,
        createdAt: log.createdAt.toISOString()
      })),
      total: result.total,
      page: result.page,
      pageSize: result.pageSize
    }
  })

  // 管理员调整用户余额
  fastify.post<{
    Params: { userId: string }
    Body: {
      amount: number
      remark: string
    }
  }>('/admin/:userId/adjust', {
    onRequest: [fastify.authenticate, fastify.requireAdmin],
    config: { rateLimit: { max: 20, timeWindow: '1 minute' } }
  }, async (request: FastifyRequest<{ Params: { userId: string }; Body: { amount: number; remark: string } }>, reply: FastifyReply) => {
    const { user } = request
    const userId = Number(request.params.userId)
    const { amount, remark } = request.body

    if (isNaN(userId)) {
      return reply.code(400).send(apiError(ErrorCode.INVALID_ID))
    }

    // 参数校验
    if (amount === null || amount === undefined || typeof amount !== 'number' || isNaN(amount)) {
      return reply.code(400).send({ error: '调整金额必须是有效的数字' })
    }

    if (amount === 0) {
      return reply.code(400).send({ error: '调整金额不能为 0' })
    }

    if (!remark || remark.trim().length === 0) {
      return reply.code(400).send({ error: '必须填写调整原因' })
    }

    if (remark.trim().length > 500) {
      return reply.code(400).send({ error: '调整原因不能超过 500 字符' })
    }

    const targetUser = await db.findUserById(userId)
    if (!targetUser) {
      return reply.code(404).send(apiError(ErrorCode.USER_NOT_FOUND))
    }

    const result = await db.adminAdjustBalance(
      userId,
      amount,
      `[管理员 ${user.username}] ${remark}`
    )

    if (!result.success) {
      return reply.code(400).send({ error: result.error })
    }

    await createLog(
      user.id,
      'admin',
      'balance.adjust',
      `Adjusted balance for user ${targetUser.username}: ${amount > 0 ? '+' : ''}${amount}, reason: ${remark}`,
      'success'
    )

    // 发送余额调整邮件通知
    try {
      if (targetUser.email) {
        await sendBalanceAdjustedEmail(targetUser.email, {
          username: targetUser.username,
          amount,
          remark,
          newBalance: result.newBalance!,
          time: new Date()
        })
      }
    } catch (emailErr) {
      // 邮件失败不影响主流程
      console.warn(`[余额调整] 发送邮件失败:`, emailErr)
    }

    return {
      message: '余额调整成功',
      newBalance: result.newBalance,
      balanceLog: result.balanceLog ? {
        id: result.balanceLog.id,
        type: result.balanceLog.type,
        amount: Number(result.balanceLog.amount),
        balanceBefore: Number(result.balanceLog.balanceBefore),
        balanceAfter: Number(result.balanceLog.balanceAfter)
      } : null
    }
  })

  // 管理员赠送余额
  fastify.post<{
    Params: { userId: string }
    Body: {
      amount: number
      remark?: string
    }
  }>('/admin/:userId/gift', {
    onRequest: [fastify.authenticate, fastify.requireAdmin],
    config: { rateLimit: { max: 20, timeWindow: '1 minute' } }
  }, async (request: FastifyRequest<{ Params: { userId: string }; Body: { amount: number; remark?: string } }>, reply: FastifyReply) => {
    const { user } = request
    const userId = Number(request.params.userId)
    const { amount, remark } = request.body

    if (isNaN(userId)) {
      return reply.code(400).send(apiError(ErrorCode.INVALID_ID))
    }

    // 参数校验
    if (amount === null || amount === undefined || typeof amount !== 'number' || isNaN(amount)) {
      return reply.code(400).send({ error: '赠送金额必须是有效的数字' })
    }

    if (amount <= 0) {
      return reply.code(400).send({ error: '赠送金额必须大于 0' })
    }

    const targetUser = await db.findUserById(userId)
    if (!targetUser) {
      return reply.code(404).send(apiError(ErrorCode.USER_NOT_FOUND))
    }

    const result = await db.giftBalance(
      userId,
      amount,
      remark || `管理员 ${user.username} 赠送`
    )

    if (!result.success) {
      return reply.code(400).send({ error: result.error })
    }

    await createLog(
      user.id,
      'admin',
      'balance.gift',
      `Gifted ${amount} to user ${targetUser.username}`,
      'success'
    )

    // 发送余额赠送邮件通知
    try {
      if (targetUser.email) {
        await sendBalanceAdjustedEmail(targetUser.email, {
          username: targetUser.username,
          amount,
          remark: remark || '管理员赠送',
          newBalance: result.newBalance!,
          time: new Date()
        })
      }
    } catch (emailErr) {
      // 邮件失败不影响主流程
      console.warn(`[余额赠送] 发送邮件失败:`, emailErr)
    }

    return {
      message: '赠送成功',
      newBalance: result.newBalance
    }
  })
}
