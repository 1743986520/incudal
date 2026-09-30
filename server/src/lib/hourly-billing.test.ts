import assert from 'node:assert/strict'
import test from 'node:test'
import { Prisma } from '@prisma/client'
import {
  calculateHourlyBreakdown,
  calculateHourlyCost,
  ceilToQuantum,
  hourlyPricingFromSnapshot,
  snapshotHourlyPricing,
  validateHourlyResources
} from './hourly-billing.js'

const pricing = {
  cpuUnitPercent: 5,
  memoryUnitMb: 64,
  diskUnitMb: 512,
  minCpu: 15,
  minMemoryMb: 128,
  minDiskMb: 512,
  cpuPricePerUnit: new Prisma.Decimal('0.0012'),
  memoryPricePerUnit: new Prisma.Decimal('0.0009'),
  diskPricePerUnit: new Prisma.Decimal('0.0021'),
  reserveQuantum: new Prisma.Decimal('0.01')
}

test('hourly billing uses Decimal for component and second-level cost', () => {
  const breakdown = calculateHourlyBreakdown({ cpu: 15, memory: 128, disk: 512 }, pricing)

  assert.deepEqual(
    { cpuUnits: breakdown.cpuUnits, memoryUnits: breakdown.memoryUnits, diskUnits: breakdown.diskUnits },
    { cpuUnits: 3, memoryUnits: 2, diskUnits: 1 }
  )
  assert.equal(breakdown.hourlyPrice.toFixed(8), '0.00750000')
  assert.equal(calculateHourlyCost(breakdown.hourlyPrice, 1).toFixed(8), '0.00000208')
  assert.equal(calculateHourlyCost(breakdown.hourlyPrice, 3600).toFixed(8), '0.00750000')
  assert.equal(calculateHourlyCost(breakdown.hourlyPrice, 0).toFixed(8), '0.00000000')
  assert.throws(() => calculateHourlyCost(breakdown.hourlyPrice, 1.5), /non-negative integer/)
})

test('hourly billing enforces minimums and steps', () => {
  assert.doesNotThrow(() => validateHourlyResources({ cpu: 20, memory: 192, disk: 1024 }, pricing))
  assert.throws(
    () => validateHourlyResources({ cpu: 16, memory: 128, disk: 512 }, pricing),
    /CPU must increase in steps/
  )
  assert.throws(
    () => validateHourlyResources({ cpu: 15, memory: 64, disk: 512 }, pricing),
    /Memory must be at least 128/
  )
})

test('reserve additions round up to the configured quantum', () => {
  assert.equal(ceilToQuantum(new Prisma.Decimal('0.01000001'), new Prisma.Decimal('0.01')).toFixed(8), '0.02000000')
  assert.equal(ceilToQuantum(new Prisma.Decimal('0.01'), new Prisma.Decimal('0.01')).toFixed(8), '0.01000000')
  assert.equal(ceilToQuantum(new Prisma.Decimal('0'), new Prisma.Decimal('0.01')).toFixed(8), '0.00000000')
  assert.throws(() => ceilToQuantum(new Prisma.Decimal('0.01'), new Prisma.Decimal('0')), /greater than zero/)
})

test('hourly account price snapshots preserve exact decimal terms after plan edits', () => {
  const mutablePlan = {
    ...pricing,
    cpuPricePerUnit: new Prisma.Decimal('0.00000017')
  }
  const snapshot = snapshotHourlyPricing(mutablePlan)

  mutablePlan.cpuPricePerUnit = new Prisma.Decimal('9.99')
  const restored = hourlyPricingFromSnapshot(JSON.parse(JSON.stringify(snapshot)))

  assert.ok(restored)
  assert.equal(restored.cpuPricePerUnit, '0.00000017')
  assert.equal(restored.reserveQuantum, '0.01000000')
  assert.equal(calculateHourlyBreakdown({ cpu: 15, memory: 128, disk: 512 }, restored).cpuAmount.toFixed(8), '0.00000051')
})

test('hourly account pricing snapshot rejects malformed or unsafe terms', () => {
  assert.equal(hourlyPricingFromSnapshot(null), null)
  assert.equal(hourlyPricingFromSnapshot({ ...snapshotHourlyPricing(pricing), reserveQuantum: '0' }), null)
  assert.equal(hourlyPricingFromSnapshot({ ...snapshotHourlyPricing(pricing), cpuUnitPercent: 0 }), null)
})
