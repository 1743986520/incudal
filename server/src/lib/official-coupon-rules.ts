/**
 * 官方优惠券规则（纯函数，不依赖数据库）
 *
 * 与购买流程共用的判定规则集中在这里，便于单独测试：
 * - 代码规范化与生成
 * - 适用范围匹配（官方直营 / 托管）
 * - 每用户可用次数上限
 * - 续期可折价月数
 */

import crypto from 'crypto'
import type { OfficialCouponRenewalMode, OfficialCouponScope } from '@prisma/client'

// 自动生成的优惠券代码字符集（去除易混淆字符）
const COUPON_CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
const COUPON_CODE_PREFIX = 'PROMO-'
const COUPON_CODE_RANDOM_LENGTH = 8

/** 优惠券代码最大长度（与实例开通接口的 promoCode 字段限制保持一致） */
export const OFFICIAL_COUPON_CODE_MAX_LENGTH = 32

/** 套餐归属：官方直营（管理员创建）或托管（普通用户创建） */
export type PackageCouponScope = 'official' | 'hosted'

/**
 * 规范化优惠券代码（去空格 + 大写）
 */
export function normalizeOfficialCouponCode(code: string): string {
  return code.trim().toUpperCase()
}

/**
 * 生成随机优惠券代码
 */
export function generateOfficialCouponCode(): string {
  const bytes = crypto.randomBytes(COUPON_CODE_RANDOM_LENGTH)
  let randomPart = ''
  for (let i = 0; i < COUPON_CODE_RANDOM_LENGTH; i++) {
    randomPart += COUPON_CODE_ALPHABET[bytes[i] % COUPON_CODE_ALPHABET.length]
  }
  return `${COUPON_CODE_PREFIX}${randomPart}`
}

/**
 * 判断优惠券适用范围是否覆盖套餐归属
 */
export function isCouponScopeMatched(scope: OfficialCouponScope, packageScope: PackageCouponScope): boolean {
  if (scope === 'all') return true
  if (scope === 'official_only') return packageScope === 'official'
  return packageScope === 'hosted'
}

/**
 * 计算同一用户可使用次数上限
 * - reusable=false：每位用户仅可使用一次
 * - reusable=true：maxUsesPerUser 为 null 时表示不限次数
 */
export function resolveUserUsageLimit(coupon: { reusable: boolean; maxUsesPerUser: number | null }): number | null {
  if (!coupon.reusable) return 1
  return coupon.maxUsesPerUser
}

/**
 * 判断管理员提交的折扣率是否合法（0 到 1 之间，不含端点）
 */
export function isValidDiscountRate(discountRate: number): boolean {
  return Number.isFinite(discountRate) && discountRate > 0 && discountRate < 1
}

/**
 * 计算该实例还剩多少个月可以享受官方券折扣。
 *
 * `discountedChargeLimit` 保留原数据库/API 字段名以兼容现有数据，
 * 但 limited 模式的语义是「含首次购买在内的总折价月数」。
 * null 表示没有月数上限（recurring），0 表示本次续费不可折价。
 */
export function getRemainingDiscountedMonths(input: {
  renewalMode: OfficialCouponRenewalMode
  discountedChargeLimit: number | null
  discountedMonthsUsed: number
}): number | null {
  switch (input.renewalMode) {
    case 'recurring':
      return null
    case 'limited': {
      const limit = input.discountedChargeLimit
      if (limit === null || !Number.isInteger(limit) || limit < 1) return 0
      return Math.max(0, limit - Math.max(0, Math.floor(input.discountedMonthsUsed)))
    }
    case 'purchase_only':
    default:
      return 0
  }
}

/** 计算本次新购实际可折价的月数。 */
export function getDiscountedMonthsForPurchase(input: {
  renewalMode: OfficialCouponRenewalMode
  discountedChargeLimit: number | null
  purchaseMonths: number
}): number {
  if (!Number.isInteger(input.purchaseMonths) || input.purchaseMonths < 1) return 0
  // purchase_only means the coupon is valid for the initial purchase but
  // never for renewals. It must therefore still cover the full initial term.
  if (input.renewalMode === 'purchase_only') return input.purchaseMonths

  const remaining = getRemainingDiscountedMonths({
    renewalMode: input.renewalMode,
    discountedChargeLimit: input.discountedChargeLimit,
    discountedMonthsUsed: 0
  })
  return remaining === null ? input.purchaseMonths : Math.min(input.purchaseMonths, remaining)
}

/** 计算本次续费实际可折价的月数。 */
export function getDiscountedMonthsForRenewal(input: {
  renewalMode: OfficialCouponRenewalMode
  discountedChargeLimit: number | null
  discountedMonthsUsed: number
  requestedMonths: number
}): number {
  if (!Number.isInteger(input.requestedMonths) || input.requestedMonths < 1) return 0
  const remaining = getRemainingDiscountedMonths(input)
  return remaining === null ? input.requestedMonths : Math.min(input.requestedMonths, remaining)
}

/**
 * 按折价月数计算折扣金额。
 * 例如原价 ¥120、续费 12 个月、仅 3 个月可折价、折扣率 90%，
 * 返回 ¥27，而不是把 ¥120 全部乘上 90%。
 */
export function calculateDiscountAmountForMonths(
  originalAmount: number,
  requestedMonths: number,
  discountedMonths: number,
  discountRate: number
): number {
  if (!Number.isFinite(originalAmount) || originalAmount <= 0) return 0
  if (!Number.isInteger(requestedMonths) || requestedMonths < 1) return 0
  if (!Number.isFinite(discountRate) || discountRate <= 0) return 0

  const effectiveMonths = Math.max(0, Math.min(requestedMonths, Math.floor(discountedMonths)))
  if (effectiveMonths === 0) return 0

  const discountedBase = Number((originalAmount * effectiveMonths / requestedMonths).toFixed(2))
  return Number((discountedBase * discountRate).toFixed(2))
}

/**
 * 向后兼容的布尔判定：调用方若只需要知道至少还有 1 个月可折价，
 * 应使用 getDiscountedMonthsForRenewal 获取准确月数。
 */
export function shouldDiscountRenewal(input: {
  renewalMode: OfficialCouponRenewalMode
  discountedChargeLimit: number | null
  discountedMonthsUsed?: number
  /** 兼容旧调用方，旧字段表示次数，现在按已折价月数处理。 */
  discountedChargeCount?: number
}): boolean {
  return getDiscountedMonthsForRenewal({
    renewalMode: input.renewalMode,
    discountedChargeLimit: input.discountedChargeLimit,
    discountedMonthsUsed: input.discountedMonthsUsed ?? input.discountedChargeCount ?? 0,
    requestedMonths: 1
  }) > 0
}
