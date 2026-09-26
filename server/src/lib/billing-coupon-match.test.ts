import assert from 'node:assert/strict'
import test from 'node:test'
import { matchCouponUsagesToBillingRecords } from './billing-coupon-match.js'

test('a full-price renewal before a discounted renewal does not consume the coupon usage', () => {
  const records = [
    { type: 'renew' as const, amount: 100, createdAt: new Date('2026-01-01') },
    { type: 'renew' as const, amount: 80, createdAt: new Date('2026-02-01') }
  ]
  const usages = [
    { type: 'renewal', originalPrice: 100, discountAmount: 20, createdAt: new Date('2026-02-01') }
  ]

  assert.deepEqual([...matchCouponUsagesToBillingRecords(records, usages)], [[1, 0]])
})

test('same-price renewals match the usage nearest in time', () => {
  const records = [
    { type: 'renew' as const, amount: 80, createdAt: new Date('2026-01-01') },
    { type: 'renew' as const, amount: 80, createdAt: new Date('2026-02-01') }
  ]
  const usages = [
    { type: 'renewal', originalPrice: 100, discountAmount: 20, createdAt: new Date('2026-02-01') }
  ]

  assert.deepEqual([...matchCouponUsagesToBillingRecords(records, usages)], [[1, 0]])
})

test('upgrade records never receive coupon usages', () => {
  const records = [
    { type: 'upgrade' as const, amount: 80, createdAt: new Date('2026-02-01') },
    { type: 'renew' as const, amount: 80, createdAt: new Date('2026-02-02') }
  ]
  const usages = [
    { type: 'renewal', originalPrice: 100, discountAmount: 20, createdAt: new Date('2026-02-01') }
  ]

  assert.deepEqual([...matchCouponUsagesToBillingRecords(records, usages)], [[1, 0]])
})
