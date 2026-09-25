import assert from 'node:assert/strict'
import test from 'node:test'
import {
  calculateDiscountAmountForMonths,
  generateOfficialCouponCode,
  getDiscountedMonthsForPurchase,
  getDiscountedMonthsForRenewal,
  isCouponScopeMatched,
  isValidDiscountRate,
  normalizeOfficialCouponCode,
  resolveUserUsageLimit,
  shouldDiscountRenewal
} from './official-coupon-rules.js'

test('normalizeOfficialCouponCode trims and uppercases input', () => {
  assert.equal(normalizeOfficialCouponCode('  promo-abcd1234 '), 'PROMO-ABCD1234')
})

test('generateOfficialCouponCode produces unique uppercase codes within the length limit', () => {
  const codes = new Set<string>()
  for (let i = 0; i < 200; i++) {
    const code = generateOfficialCouponCode()
    assert.match(code, /^PROMO-[A-Z2-9]{8}$/)
    assert.ok(code.length <= 32)
    codes.add(code)
  }
  assert.equal(codes.size, 200)
})

test('scope "all" applies to both official and hosted packages', () => {
  assert.equal(isCouponScopeMatched('all', 'official'), true)
  assert.equal(isCouponScopeMatched('all', 'hosted'), true)
})

test('scope "official_only" rejects hosted packages', () => {
  assert.equal(isCouponScopeMatched('official_only', 'official'), true)
  assert.equal(isCouponScopeMatched('official_only', 'hosted'), false)
})

test('scope "hosted_only" rejects official packages', () => {
  assert.equal(isCouponScopeMatched('hosted_only', 'hosted'), true)
  assert.equal(isCouponScopeMatched('hosted_only', 'official'), false)
})

test('non-reusable coupons are limited to one use per user', () => {
  assert.equal(resolveUserUsageLimit({ reusable: false, maxUsesPerUser: null }), 1)
  // reusable=false 时即使前端误传次数，也按一次处理
  assert.equal(resolveUserUsageLimit({ reusable: false, maxUsesPerUser: 10 }), 1)
})

test('reusable coupons honour maxUsesPerUser and treat null as unlimited', () => {
  assert.equal(resolveUserUsageLimit({ reusable: true, maxUsesPerUser: 3 }), 3)
  assert.equal(resolveUserUsageLimit({ reusable: true, maxUsesPerUser: null }), null)
})

test('discount rate must be between 0 and 1 exclusive', () => {
  assert.equal(isValidDiscountRate(0.05), true)
  assert.equal(isValidDiscountRate(0.9999), true)
  assert.equal(isValidDiscountRate(0), false)
  assert.equal(isValidDiscountRate(1), false)
  assert.equal(isValidDiscountRate(Number.NaN), false)
})

test('purchase_only renewals are never discounted', () => {
  assert.equal(shouldDiscountRenewal({ renewalMode: 'purchase_only', discountedChargeLimit: null, discountedChargeCount: 0 }), false)
  assert.equal(shouldDiscountRenewal({ renewalMode: 'purchase_only', discountedChargeLimit: 9, discountedChargeCount: 1 }), false)
})

test('purchase_only coupons still discount the full initial purchase term', () => {
  assert.equal(getDiscountedMonthsForPurchase({
    renewalMode: 'purchase_only',
    discountedChargeLimit: null,
    purchaseMonths: 12
  }), 12)
})

test('recurring renewals are always discounted', () => {
  assert.equal(shouldDiscountRenewal({ renewalMode: 'recurring', discountedChargeLimit: null, discountedChargeCount: 0 }), true)
  assert.equal(shouldDiscountRenewal({ renewalMode: 'recurring', discountedChargeLimit: null, discountedChargeCount: 999 }), true)
})

test('limited renewals discount until the month limit is reached', () => {
  // 兼容旧字段名：现在按含首次购买的折价月数累计
  const limited = (count: number) => shouldDiscountRenewal({ renewalMode: 'limited', discountedChargeLimit: 9, discountedChargeCount: count })
  assert.equal(limited(0), true)
  assert.equal(limited(8), true)
  assert.equal(limited(9), false)
})

test('limited renewals with a missing or invalid limit never discount', () => {
  assert.equal(shouldDiscountRenewal({ renewalMode: 'limited', discountedChargeLimit: null, discountedChargeCount: 1 }), false)
  assert.equal(shouldDiscountRenewal({ renewalMode: 'limited', discountedChargeLimit: 0, discountedChargeCount: 1 }), false)
})

test('limited coupons cap a 12-month renewal at the remaining discounted months', () => {
  assert.equal(getDiscountedMonthsForRenewal({
    renewalMode: 'limited',
    discountedChargeLimit: 3,
    discountedMonthsUsed: 0,
    requestedMonths: 12
  }), 3)
  assert.equal(getDiscountedMonthsForRenewal({
    renewalMode: 'limited',
    discountedChargeLimit: 3,
    discountedMonthsUsed: 2,
    requestedMonths: 12
  }), 1)
  assert.equal(getDiscountedMonthsForRenewal({
    renewalMode: 'limited',
    discountedChargeLimit: 3,
    discountedMonthsUsed: 3,
    requestedMonths: 12
  }), 0)
})

test('limited coupons also cap the initial purchase duration', () => {
  assert.equal(getDiscountedMonthsForPurchase({
    renewalMode: 'limited',
    discountedChargeLimit: 3,
    purchaseMonths: 12
  }), 3)
  assert.equal(getDiscountedMonthsForPurchase({
    renewalMode: 'recurring',
    discountedChargeLimit: null,
    purchaseMonths: 12
  }), 12)
})

test('discount amount is prorated to the discounted months', () => {
  // 12 个月原价 ¥120，只有 3 个月按 90% 折价，实际只减 ¥27。
  assert.equal(calculateDiscountAmountForMonths(120, 12, 3, 0.9), 27)
  assert.equal(calculateDiscountAmountForMonths(120, 12, 12, 0.9), 108)
})
