/**
 * 官方优惠券管理路由（管理员）
 *
 * 官方优惠券的折扣由平台承担，与 AFF 优惠码独立：
 * 使用官方券不产生 AFF 绑定，也不产生返利，托管主仍按原价结算。
 */

import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify'
import type { OfficialCouponScope } from '@prisma/client'
import * as db from '../db/index.js'
import { createLog } from '../db/logs.js'
import { apiError, ErrorCode, type ErrorCodeType } from '../lib/errors.js'
import { OFFICIAL_COUPON_CODE_MAX_LENGTH, isValidDiscountRate } from '../lib/official-coupon-rules.js'

const COUPON_SCOPES: OfficialCouponScope[] = ['all', 'official_only', 'hosted_only']
const MAX_NAME_LENGTH = 64
const MAX_REMARK_LENGTH = 500
const MAX_USES_LIMIT = 1000000

interface CouponBody {
  code?: string
  name?: string
  remark?: string | null
  discountRate?: number
  scope?: string
  reusable?: boolean
  maxUsesPerUser?: number | null
  totalUsageLimit?: number | null
  enabled?: boolean
  startsAt?: string | null
  expiresAt?: string | null
}

interface ParsedCouponInput {
  code?: string
  name: string
  remark: string | null
  discountRate: number
  scope: OfficialCouponScope
  reusable: boolean
  maxUsesPerUser: number | null
  totalUsageLimit: number | null
  enabled: boolean
  startsAt: Date | null
  expiresAt: Date | null
}

interface CouponInputOverrides {
  partial?: boolean
}

function parseOptionalDate(value: string | null | undefined, field: string): Date | null {
  if (value === null || value === undefined || value === '') return null
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    throw new Error(`${ErrorCode.INVALID_PARAMS}: ${field} is not a valid date`)
  }
  return date
}

/**
 * 把 parseCouponInput 抛出的 `CODE: detail` 错误转换成结构化响应
 */
function parseErrorResponse(error: unknown): { code: ErrorCodeType; details?: string } {
  const message = String((error as Error).message)
  const separatorIndex = message.indexOf(': ')
  const rawCode = separatorIndex === -1 ? message : message.slice(0, separatorIndex)
  const details = separatorIndex === -1 ? undefined : message.slice(separatorIndex + 2)
  const known = (Object.values(ErrorCode) as string[]).includes(rawCode)
  return {
    code: known ? rawCode as ErrorCodeType : ErrorCode.INVALID_PARAMS,
    details
  }
}

function parseOptionalUses(value: number | null | undefined, field: string): number | null {
  if (value === null || value === undefined) return null
  if (!Number.isInteger(value) || value < 1 || value > MAX_USES_LIMIT) {
    throw new Error(`${ErrorCode.INVALID_PARAMS}: ${field} must be an integer between 1 and ${MAX_USES_LIMIT}`)
  }
  return value
}

/**
 * 校验并归一化管理端提交的优惠券字段
 *
 * @throws Error `INVALID_PARAMS` 字段不合法
 */
function parseCouponInput(body: CouponBody, overrides: CouponInputOverrides = {}): Partial<ParsedCouponInput> {
  const partial = overrides.partial === true
  const result: Partial<ParsedCouponInput> = {}

  if (body.name !== undefined || !partial) {
    const name = typeof body.name === 'string' ? body.name.trim() : ''
    if (!name) {
      throw new Error(`${ErrorCode.INVALID_PARAMS}: name is required`)
    }
    if (name.length > MAX_NAME_LENGTH) {
      throw new Error(`${ErrorCode.INVALID_PARAMS}: name is too long`)
    }
    result.name = name
  }

  if (body.code !== undefined) {
    if (body.code === null) {
      throw new Error(`${ErrorCode.INVALID_PARAMS}: code cannot be null`)
    }
    const code = body.code.trim()
    if (code.length > OFFICIAL_COUPON_CODE_MAX_LENGTH) {
      throw new Error(`${ErrorCode.INVALID_PARAMS}: code is too long`)
    }
    // 留空表示自动生成
    if (code) result.code = code
  }

  if (body.remark !== undefined) {
    if (body.remark === null || body.remark === '') {
      result.remark = null
    } else if (typeof body.remark !== 'string' || body.remark.length > MAX_REMARK_LENGTH) {
      throw new Error(`${ErrorCode.INVALID_PARAMS}: remark is too long`)
    } else {
      result.remark = body.remark
    }
  } else if (!partial) {
    result.remark = null
  }

  if (body.discountRate !== undefined || !partial) {
    const discountRate = Number(body.discountRate)
    if (!isValidDiscountRate(discountRate)) {
      throw new Error(`${ErrorCode.COUPON_INVALID_DISCOUNT}: discountRate must be greater than 0 and less than 1`)
    }
    // 折扣率保留到万分位（数据库 Decimal(5,4)）
    result.discountRate = Number(discountRate.toFixed(4))
  }

  if (body.scope !== undefined || !partial) {
    const scope = body.scope === undefined ? 'all' : body.scope
    if (!COUPON_SCOPES.includes(scope as OfficialCouponScope)) {
      throw new Error(`${ErrorCode.INVALID_PARAMS}: scope must be one of ${COUPON_SCOPES.join(', ')}`)
    }
    result.scope = scope as OfficialCouponScope
  }

  if (body.reusable !== undefined || !partial) {
    result.reusable = body.reusable === undefined ? false : Boolean(body.reusable)
  }

  if (!partial || body.maxUsesPerUser !== undefined) {
    const reusable = result.reusable === undefined ? false : result.reusable
    result.maxUsesPerUser = reusable ? parseOptionalUses(body.maxUsesPerUser, 'maxUsesPerUser') : null
  }

  if (!partial || body.totalUsageLimit !== undefined) {
    result.totalUsageLimit = parseOptionalUses(body.totalUsageLimit, 'totalUsageLimit')
  }

  if (body.enabled !== undefined || !partial) {
    result.enabled = body.enabled === undefined ? true : Boolean(body.enabled)
  }

  if (body.startsAt !== undefined) {
    result.startsAt = parseOptionalDate(body.startsAt, 'startsAt')
  } else if (!partial) {
    result.startsAt = null
  }

  if (body.expiresAt !== undefined) {
    result.expiresAt = parseOptionalDate(body.expiresAt, 'expiresAt')
  } else if (!partial) {
    result.expiresAt = null
  }

  if (result.startsAt && result.expiresAt && result.startsAt >= result.expiresAt) {
    throw new Error(`${ErrorCode.INVALID_PARAMS}: expiresAt must be later than startsAt`)
  }

  return result
}

/**
 * 更新时的有效期校验：需要拿到合并后的最终值，避免只改一端产生非法区间
 */
function assertValidityRange(
  startsAt: Date | null | undefined,
  expiresAt: Date | null | undefined,
  current: { startsAt: Date | null; expiresAt: Date | null }
): void {
  const nextStartsAt = startsAt === undefined ? current.startsAt : startsAt
  const nextExpiresAt = expiresAt === undefined ? current.expiresAt : expiresAt
  if (nextStartsAt && nextExpiresAt && nextStartsAt >= nextExpiresAt) {
    throw new Error(`${ErrorCode.INVALID_PARAMS}: expiresAt must be later than startsAt`)
  }
}

export default async function adminOfficialCouponRoutes(app: FastifyInstance): Promise<void> {
  // ==================== 优惠券列表 ====================

  app.get<{
    Querystring: { page?: string; pageSize?: string; search?: string; enabled?: string; scope?: string }
  }>('/api/admin/official-coupons', {
    onRequest: [app.authenticate, app.requireAdmin]
  }, async (request) => {
    const query = request.query
    const enabled = query.enabled === undefined || query.enabled === '' || query.enabled === 'all'
      ? undefined
      : query.enabled === 'true' || query.enabled === '1'

    const scope = query.scope && COUPON_SCOPES.includes(query.scope as OfficialCouponScope)
      ? query.scope as OfficialCouponScope
      : undefined

    return db.listOfficialCoupons({
      page: query.page ? Number(query.page) : 1,
      pageSize: query.pageSize ? Number(query.pageSize) : 20,
      search: query.search,
      enabled,
      scope
    })
  })

  // ==================== 新增优惠券 ====================

  app.post<{ Body: CouponBody }>('/api/admin/official-coupons', {
    onRequest: [app.authenticate, app.requireAdmin],
    config: { rateLimit: { max: 30, timeWindow: '1 minute' } }
  }, async (request: FastifyRequest<{ Body: CouponBody }>, reply: FastifyReply) => {
    const { user } = request

    let input: Partial<ParsedCouponInput>
    try {
      input = parseCouponInput(request.body || {})
    } catch (error) {
      const { code, details } = parseErrorResponse(error)
      return reply.code(400).send(apiError(code, details))
    }

    try {
      const coupon = await db.createOfficialCoupon({
        code: input.code,
        name: input.name!,
        remark: input.remark,
        discountRate: input.discountRate!,
        scope: input.scope as OfficialCouponScope,
        reusable: input.reusable!,
        maxUsesPerUser: input.maxUsesPerUser,
        totalUsageLimit: input.totalUsageLimit,
        enabled: input.enabled!,
        startsAt: input.startsAt,
        expiresAt: input.expiresAt,
        createdById: user.id
      })

      await createLog(user.id, 'admin', 'official_coupon.create', `Created official coupon ${coupon.code}`, 'success')

      return coupon
    } catch (error) {
      if (String((error as Error).message).startsWith(ErrorCode.COUPON_CODE_EXISTS)) {
        return reply.code(409).send(apiError(ErrorCode.COUPON_CODE_EXISTS))
      }
      throw error
    }
  })

  // ==================== 更新优惠券 ====================

  app.patch<{ Params: { id: string }; Body: CouponBody }>('/api/admin/official-coupons/:id', {
    onRequest: [app.authenticate, app.requireAdmin],
    config: { rateLimit: { max: 60, timeWindow: '1 minute' } }
  }, async (request: FastifyRequest<{ Params: { id: string }; Body: CouponBody }>, reply: FastifyReply) => {
    const { user } = request
    const id = Number(request.params.id)
    if (!Number.isInteger(id) || id <= 0) {
      return reply.code(400).send(apiError(ErrorCode.INVALID_ID))
    }

    const existing = await db.getOfficialCouponById(id)
    if (!existing) {
      return reply.code(404).send(apiError(ErrorCode.NOT_FOUND))
    }

    let input: Partial<ParsedCouponInput>
    try {
      input = parseCouponInput(request.body || {}, { partial: true })
      assertValidityRange(input.startsAt, input.expiresAt, {
        startsAt: existing.startsAt,
        expiresAt: existing.expiresAt
      })
    } catch (error) {
      const { code, details } = parseErrorResponse(error)
      return reply.code(400).send(apiError(code, details))
    }

    try {
      const updated = await db.updateOfficialCoupon(id, input)
      if (!updated) {
        return reply.code(404).send(apiError(ErrorCode.NOT_FOUND))
      }

      await createLog(user.id, 'admin', 'official_coupon.update', `Updated official coupon ${updated.code}`, 'success')

      return updated
    } catch (error) {
      if (String((error as Error).message).startsWith(ErrorCode.COUPON_CODE_EXISTS)) {
        return reply.code(409).send(apiError(ErrorCode.COUPON_CODE_EXISTS))
      }
      throw error
    }
  })

  // ==================== 删除优惠券 ====================

  app.delete<{ Params: { id: string } }>('/api/admin/official-coupons/:id', {
    onRequest: [app.authenticate, app.requireAdmin],
    config: { rateLimit: { max: 30, timeWindow: '1 minute' } }
  }, async (request: FastifyRequest<{ Params: { id: string } }>, reply: FastifyReply) => {
    const { user } = request
    const id = Number(request.params.id)
    if (!Number.isInteger(id) || id <= 0) {
      return reply.code(400).send(apiError(ErrorCode.INVALID_ID))
    }

    const result = await db.deleteOfficialCoupon(id)
    if (result === 'not_found') {
      return reply.code(404).send(apiError(ErrorCode.NOT_FOUND))
    }
    if (result === 'in_use') {
      return reply.code(400).send(apiError(ErrorCode.COUPON_IN_USE))
    }

    await createLog(user.id, 'admin', 'official_coupon.delete', `Deleted official coupon #${id}`, 'success')

    return { success: true }
  })

  // ==================== 使用记录 ====================

  app.get<{ Params: { id: string }; Querystring: { page?: string; pageSize?: string } }>('/api/admin/official-coupons/:id/usages', {
    onRequest: [app.authenticate, app.requireAdmin]
  }, async (request: FastifyRequest<{ Params: { id: string }; Querystring: { page?: string; pageSize?: string } }>, reply: FastifyReply) => {
    const id = Number(request.params.id)
    if (!Number.isInteger(id) || id <= 0) {
      return reply.code(400).send(apiError(ErrorCode.INVALID_ID))
    }

    const coupon = await db.getOfficialCouponById(id)
    if (!coupon) {
      return reply.code(404).send(apiError(ErrorCode.NOT_FOUND))
    }

    const page = request.query.page ? Number(request.query.page) : 1
    const pageSize = request.query.pageSize ? Number(request.query.pageSize) : 20

    const usages = await db.listOfficialCouponUsages(id, page, pageSize)

    return {
      coupon: db.serializeOfficialCoupon(coupon),
      ...usages
    }
  })
}
