import { test } from 'node:test'
import assert from 'node:assert/strict'
import { retiredRefundCents } from './retired-refund-math.mjs'

const interval = (amount, start = '2026-01-01T00:00:00Z', end = '2026-01-11T00:00:00Z') => ({ amount, period_start: start, period_end: end })
test('prorates in exact cents and rounds once', () => {
  assert.equal(retiredRefundCents([interval('10.01')], '2026-01-06T00:00:00Z', '2026-01-11T00:00:00Z'), 501n)
  assert.equal(retiredRefundCents([interval('10.00'), interval('1.00')], '2026-01-06T00:00:00Z', '2026-01-11T00:00:00Z'), 550n)
})
test('expired and future periods', () => {
  assert.equal(retiredRefundCents([interval('10.00')], '2026-01-12T00:00:00Z', '2026-01-11T00:00:00Z'), 0n)
  assert.equal(retiredRefundCents([interval('10.00')], '2025-12-31T00:00:00Z', '2026-01-11T00:00:00Z'), 1000n)
})
test('missing or invalid evidence fails closed', () => {
  assert.throws(() => retiredRefundCents([], '2026-01-06', '2026-01-11'))
  assert.throws(() => retiredRefundCents([interval('-10.00')], '2026-01-06', '2026-01-11'))
  assert.throws(() => retiredRefundCents([interval('10.00', '2026-01-11', '2026-01-01')], '2026-01-06', '2026-01-11'))
})
