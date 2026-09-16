import assert from 'node:assert/strict'
import test from 'node:test'
import { calculatePlanChangeSettledBytes } from '../src/services/traffic-utils.js'

const usage = 100n

for (const row of [
  { name: 'same allowance', oldIncluded: 50n, settled: 20n, newIncluded: 50n, expected: 20n },
  { name: 'larger allowance preserves unpaid traffic', oldIncluded: 50n, settled: 20n, newIncluded: 80n, expected: 0n },
  { name: 'smaller allowance does not double charge covered traffic', oldIncluded: 50n, settled: 20n, newIncluded: 10n, expected: 60n },
  { name: 'fully settled usage remains fully settled', oldIncluded: 50n, settled: 50n, newIncluded: 80n, expected: 20n },
  { name: 'allowance above usage has no overage', oldIncluded: 50n, settled: 20n, newIncluded: 120n, expected: 0n }
]) {
  test(`usage -> usage: ${row.name}`, () => {
    assert.equal(calculatePlanChangeSettledBytes({
      monthlyTrafficUsed: usage,
      previousBillingMode: 'usage',
      previousSettledBytes: row.settled,
      previousMonthlyTrafficLimit: row.oldIncluded,
      newBillingMode: 'usage',
      newMonthlyTrafficLimit: row.newIncluded
    }), row.expected)
  })
}

test('package -> usage grandfathers existing overage', () => {
  assert.equal(calculatePlanChangeSettledBytes({
    monthlyTrafficUsed: usage,
    previousBillingMode: 'package',
    previousSettledBytes: 0n,
    previousMonthlyTrafficLimit: 50n,
    newBillingMode: 'usage',
    newMonthlyTrafficLimit: 80n
  }), 20n)
})

test('usage -> package clears settled bytes', () => {
  assert.equal(calculatePlanChangeSettledBytes({
    monthlyTrafficUsed: usage,
    previousBillingMode: 'usage',
    previousSettledBytes: 20n,
    previousMonthlyTrafficLimit: 50n,
    newBillingMode: 'package',
    newMonthlyTrafficLimit: 80n
  }), 0n)
})
