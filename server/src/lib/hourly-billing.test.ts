import assert from 'node:assert/strict'
import test from 'node:test'
import { Prisma } from '@prisma/client'
import {
  calculateHourlyBreakdown,
  calculateHourlyCost,
  ceilToQuantum,
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
})
