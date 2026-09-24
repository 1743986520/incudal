import { Prisma } from '@prisma/client'

export const DEFAULT_HOURLY_RESERVE_QUANTUM = new Prisma.Decimal('0.01')

export interface HourlyPricingLike {
  cpuUnitPercent: number
  memoryUnitMb: number
  diskUnitMb: number
  minCpu: number
  minMemoryMb: number
  minDiskMb: number
  cpuPricePerUnit: Prisma.Decimal | string | number
  memoryPricePerUnit: Prisma.Decimal | string | number
  diskPricePerUnit: Prisma.Decimal | string | number
  reserveQuantum: Prisma.Decimal | string | number
}

/**
 * PackagePlan 是新的按小时计费价格来源。
 * 保留旧字段名只用于让计算器继续复用，避免任何金额计算退回 JavaScript number。
 */
export interface PackagePlanHourlyPricingSource {
  hourlyCpuUnitPercent: number
  hourlyMemoryUnitMb: number
  hourlyDiskUnitMb: number
  hourlyMinCpu: number
  hourlyMinMemoryMb: number
  hourlyMinDiskMb: number
  hourlyCpuPricePerUnit: Prisma.Decimal | string | number
  hourlyMemoryPricePerUnit: Prisma.Decimal | string | number
  hourlyDiskPricePerUnit: Prisma.Decimal | string | number
  hourlyReserveQuantum: Prisma.Decimal | string | number
}

export function hourlyPricingFromPackagePlan(plan: PackagePlanHourlyPricingSource): HourlyPricingLike {
  return {
    cpuUnitPercent: plan.hourlyCpuUnitPercent,
    memoryUnitMb: plan.hourlyMemoryUnitMb,
    diskUnitMb: plan.hourlyDiskUnitMb,
    minCpu: plan.hourlyMinCpu,
    minMemoryMb: plan.hourlyMinMemoryMb,
    minDiskMb: plan.hourlyMinDiskMb,
    cpuPricePerUnit: plan.hourlyCpuPricePerUnit,
    memoryPricePerUnit: plan.hourlyMemoryPricePerUnit,
    diskPricePerUnit: plan.hourlyDiskPricePerUnit,
    reserveQuantum: plan.hourlyReserveQuantum
  }
}

export interface HourlyResources {
  cpu: number
  memory: number
  disk: number
}

export class HourlyResourceValidationError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'HourlyResourceValidationError'
  }
}

function assertResource(value: number, min: number, step: number, label: string): void {
  if (!Number.isInteger(value) || value < min) {
    throw new HourlyResourceValidationError(`${label} must be at least ${min}`)
  }
  if (step <= 0 || (value - min) % step !== 0) {
    throw new HourlyResourceValidationError(`${label} must increase in steps of ${step} from ${min}`)
  }
}

export function validateHourlyResources(resources: HourlyResources, pricing: HourlyPricingLike): void {
  assertResource(resources.cpu, pricing.minCpu, pricing.cpuUnitPercent, 'CPU')
  assertResource(resources.memory, pricing.minMemoryMb, pricing.memoryUnitMb, 'Memory')
  assertResource(resources.disk, pricing.minDiskMb, pricing.diskUnitMb, 'Disk')

  if (resources.cpu > 10000) throw new HourlyResourceValidationError('CPU is too large')
  if (resources.memory > 524288) throw new HourlyResourceValidationError('Memory is too large')
  if (resources.disk > 104857600) throw new HourlyResourceValidationError('Disk is too large')
}

export function calculateHourlyBreakdown(resources: HourlyResources, pricing: HourlyPricingLike): {
  cpuUnits: number
  memoryUnits: number
  diskUnits: number
  cpuAmount: Prisma.Decimal
  memoryAmount: Prisma.Decimal
  diskAmount: Prisma.Decimal
  hourlyPrice: Prisma.Decimal
} {
  validateHourlyResources(resources, pricing)

  // Keep the monetary path entirely in Decimal. The numeric unit counts are
  // only presentation values returned to the caller.
  const cpuUnitsDecimal = new Prisma.Decimal(resources.cpu).div(pricing.cpuUnitPercent)
  const memoryUnitsDecimal = new Prisma.Decimal(resources.memory).div(pricing.memoryUnitMb)
  const diskUnitsDecimal = new Prisma.Decimal(resources.disk).div(pricing.diskUnitMb)
  const cpuAmount = cpuUnitsDecimal.mul(pricing.cpuPricePerUnit)
  const memoryAmount = memoryUnitsDecimal.mul(pricing.memoryPricePerUnit)
  const diskAmount = diskUnitsDecimal.mul(pricing.diskPricePerUnit)

  return {
    cpuUnits: cpuUnitsDecimal.toNumber(),
    memoryUnits: memoryUnitsDecimal.toNumber(),
    diskUnits: diskUnitsDecimal.toNumber(),
    cpuAmount,
    memoryAmount,
    diskAmount,
    hourlyPrice: cpuAmount.add(memoryAmount).add(diskAmount)
  }
}

export function calculateHourlyCost(hourlyPrice: Prisma.Decimal | string | number, activeSeconds: number): Prisma.Decimal {
  if (!Number.isInteger(activeSeconds) || activeSeconds < 0) {
    throw new HourlyResourceValidationError('activeSeconds must be a non-negative integer')
  }
  return new Prisma.Decimal(hourlyPrice).mul(new Prisma.Decimal(activeSeconds)).div(new Prisma.Decimal(3600))
}

export function ceilToQuantum(amount: Prisma.Decimal, quantum: Prisma.Decimal): Prisma.Decimal {
  if (quantum.lte(0)) throw new Error('reserveQuantum must be greater than zero')
  if (amount.lte(0)) return new Prisma.Decimal(0)
  return amount.div(quantum).ceil().mul(quantum)
}

export function serializeHourlyDecimal(value: Prisma.Decimal | string | number): string {
  return new Prisma.Decimal(value).toDecimalPlaces(8).toFixed(8)
}
