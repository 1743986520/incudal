/**
 * 官方优惠券规则（纯函数，不依赖数据库）
 *
 * 与购买流程共用的判定规则集中在这里，便于单独测试：
 * - 代码规范化与生成
 * - 适用范围匹配（官方直营 / 托管）
 * - 每用户可用次数上限
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
 * 判断本次续费是否享受官方券折扣
 *
 * - purchase_only：仅首购折价，续费一律原价
 * - limited：含首次购买在内共折价 discountedChargeLimit 次，用满后原价
 * - recurring：续费一律按折扣价（仍受券的启用状态、有效期与总次数上限约束）
 *
 * @param discountedChargeCount 该实例目前已折价的次数（含首次购买）
 */
export function shouldDiscountRenewal(input: {
  renewalMode: OfficialCouponRenewalMode
  discountedChargeLimit: number | null
  discountedChargeCount: number
}): boolean {
  switch (input.renewalMode) {
    case 'recurring':
      return true
    case 'limited': {
      const limit = input.discountedChargeLimit
      if (limit === null || !Number.isInteger(limit) || limit < 1) return false
      return input.discountedChargeCount < limit
    }
    case 'purchase_only':
    default:
      return false
  }
}
