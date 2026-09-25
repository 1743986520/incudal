/**
 * 官方优惠券路由（用户端）
 *
 * 优惠券代码在实例创建页提交前校验，也可用于展示折扣预览。
 * 实际下单时后端会在购买事务内重新校验并写入使用记录，前端无法绕过。
 */

import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify'
import * as db from '../db/index.js'
import { apiError, ErrorCode } from '../lib/errors.js'
import { calculateDiscountAmountForMonths, getDiscountedMonthsForPurchase } from '../lib/official-coupon-rules.js'

export default async function officialCouponRoutes(fastify: FastifyInstance) {
  // 校验官方优惠券（实例开通页调用）
  fastify.post<{
    Body: {
      code: string
      packageId: number
      planId?: number
    }
  }>('/validate', {
    onRequest: [fastify.authenticate],
    config: { rateLimit: { max: 30, timeWindow: '1 minute' } }
  }, async (request: FastifyRequest<{ Body: { code: string; packageId: number; planId?: number } }>, reply: FastifyReply) => {
    const { user } = request
    const { code, packageId, planId } = request.body

    if (!code || !code.trim()) {
      return reply.code(400).send(apiError(ErrorCode.COUPON_NOT_FOUND))
    }

    if (!packageId || typeof packageId !== 'number') {
      return reply.code(400).send(apiError(ErrorCode.INVALID_PARAMS, 'packageId is required'))
    }

    const validation = await db.validateOfficialCoupon({
      code,
      packageId,
      userId: user.id
    })

    if (!validation.valid) {
      return reply.code(400).send({
        error: validation.error,
        code: validation.errorCode
      })
    }

    // 折扣金额按方案原价计算，作为前端价格明细的权威预览
    let planPrice: number | null = null
    let discountAmount: number | null = null
    let finalPrice: number | null = null
    let discountedMonths: number | null = null

    if (planId && typeof planId === 'number') {
      const plan = await db.getPlanById(planId)
      if (plan && plan.packageId === packageId && plan.isActive && plan.billingMode !== 'hourly') {
        planPrice = Number(plan.price) / 100
        discountedMonths = getDiscountedMonthsForPurchase({
          renewalMode: validation.coupon.renewalMode,
          discountedChargeLimit: validation.coupon.discountedChargeLimit,
          purchaseMonths: plan.billingCycle
        })
        discountAmount = calculateDiscountAmountForMonths(
          planPrice,
          plan.billingCycle,
          discountedMonths,
          validation.discountRate
        )
        finalPrice = Number((planPrice - discountAmount).toFixed(2))
      }
    }

    return {
      valid: true,
      code: validation.code,
      name: validation.name,
      remark: validation.remark,
      discountRate: validation.discountRate,
      remainingUses: validation.remainingUses,
      planPrice,
      discountAmount,
      finalPrice,
      discountedMonths
    }
  })
}
