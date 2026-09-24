import type { FastifyInstance } from 'fastify'
import { Prisma } from '@prisma/client'
import { prisma } from '../db/prisma.js'
import { canUserAccessPackage } from '../db/package-shares.js'
import { apiError, ErrorCode } from '../lib/errors.js'
import {
  calculateHourlyBreakdown,
  hourlyPricingFromPackagePlan,
  serializeHourlyDecimal,
  validateHourlyResources,
  type HourlyPricingLike,
  type HourlyResources
} from '../lib/hourly-billing.js'
import {
  runHourlyBillingJob
} from '../services/hourly-billing-scheduler.js'

function parseResources(input: Partial<HourlyResources>): HourlyResources {
  return {
    cpu: Number(input.cpu),
    memory: Number(input.memory),
    disk: Number(input.disk)
  }
}

type PricingResponseSource = HourlyPricingLike & {
  id?: number | null
  version?: number | null
  enabled?: boolean
  effectiveAt?: Date | null
  trafficUnitPrice?: Prisma.Decimal | string | number
  trafficIncludedBytes?: bigint | string | number
}

function serializePricing(pricing: PricingResponseSource) {
  return {
    id: pricing.id ?? null,
    version: pricing.version ?? null,
    enabled: pricing.enabled ?? true,
    cpuUnitPercent: pricing.cpuUnitPercent,
    memoryUnitMb: pricing.memoryUnitMb,
    diskUnitMb: pricing.diskUnitMb,
    minCpu: pricing.minCpu,
    minMemoryMb: pricing.minMemoryMb,
    minDiskMb: pricing.minDiskMb,
    cpuPricePerUnit: serializeHourlyDecimal(pricing.cpuPricePerUnit),
    memoryPricePerUnit: serializeHourlyDecimal(pricing.memoryPricePerUnit),
    diskPricePerUnit: serializeHourlyDecimal(pricing.diskPricePerUnit),
    reserveQuantum: serializeHourlyDecimal(pricing.reserveQuantum),
    trafficUnitPrice: String(pricing.trafficUnitPrice ?? '0'),
    trafficIncludedBytes: String(pricing.trafficIncludedBytes ?? '0'),
    effectiveAt: pricing.effectiveAt?.toISOString() ?? null
  }
}

function serializeBreakdown(breakdown: ReturnType<typeof calculateHourlyBreakdown>) {
  return {
    cpuUnits: breakdown.cpuUnits,
    memoryUnits: breakdown.memoryUnits,
    diskUnits: breakdown.diskUnits,
    cpuAmount: serializeHourlyDecimal(breakdown.cpuAmount),
    memoryAmount: serializeHourlyDecimal(breakdown.memoryAmount),
    diskAmount: serializeHourlyDecimal(breakdown.diskAmount),
    hourlyPrice: serializeHourlyDecimal(breakdown.hourlyPrice)
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

function canAccessInstance(user: { id: number; role: string }, instance: { userId: number; host: { userId: number } }): boolean {
  return user.role === 'admin' || user.id === instance.userId || user.id === instance.host.userId
}

async function getHourlyPlanForUser(user: { id: number; role: string }, planId: number) {
  const plan = await prisma.packagePlan.findUnique({ where: { id: planId } })
  if (!plan || plan.billingMode !== 'hourly' || !plan.isActive || plan.isSoldOut) return null
  if (user.role !== 'admin' && !(await canUserAccessPackage(user.id, plan.packageId))) return null
  return plan
}

export default async function hourlyBillingRoutes(fastify: FastifyInstance) {
  fastify.get('/hourly-billing/catalog', { onRequest: [fastify.authenticate] }, async (_request, reply) => {
    return reply.code(410).send({
      error: '按小时价格已随套餐方案配置，请先选择按小时计费方案',
      code: 'HOURLY_PLAN_REQUIRED'
    })
  })

  fastify.get<{ Querystring: { planId?: string; cpu?: string; memory?: string; disk?: string } }>('/instances/hourly/available-hosts', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    const planId = Number(request.query.planId)
    const plan = Number.isInteger(planId) && planId > 0 ? await getHourlyPlanForUser(request.user, planId) : null
    if (!plan) return reply.code(404).send({ error: '按小时计费方案不存在或无权访问', code: 'HOURLY_PLAN_NOT_FOUND' })
    const pricing = hourlyPricingFromPackagePlan(plan)
    const resources = parseResources({
      cpu: request.query.cpu ? Number(request.query.cpu) : pricing.minCpu,
      memory: request.query.memory ? Number(request.query.memory) : pricing.minMemoryMb,
      disk: request.query.disk ? Number(request.query.disk) : pricing.minDiskMb
    })
    try {
      validateHourlyResources(resources, pricing)
      const hosts = await prisma.host.findMany({
        where: { status: 'online', hourlyBillingEnabled: true },
        select: {
          id: true,
          name: true,
          location: true,
          countryCode: true,
          architecture: true,
          instanceType: true,
          cpuUsed: true,
          cpuAllowanceMax: true,
          memoryUsed: true,
          memoryMax: true,
          diskUsed: true,
          storageSize: true,
          storagePools: {
            where: { purpose: 'instance_data' },
            select: { id: true },
            take: 1
          }
        },
        orderBy: { id: 'asc' }
      })
      return {
        hosts: hosts.map(host => ({
          ...host,
          isAvailable: Boolean(
            host.storagePools.length > 0 &&
            host.cpuAllowanceMax > 0 && host.cpuUsed + resources.cpu <= host.cpuAllowanceMax &&
            host.memoryMax > 0 && host.memoryUsed + resources.memory <= host.memoryMax &&
            host.storageSize > 0 && host.diskUsed + resources.disk <= host.storageSize * 1024
          )
        }))
      }
    } catch (error) {
      return reply.code(400).send({ error: errorMessage(error), code: 'HOURLY_RESOURCE_INVALID' })
    }
  })

  fastify.post<{ Body: HourlyResources & { planId: number } }>('/instances/hourly/quote', {
    onRequest: [fastify.authenticate],
    config: { rateLimit: { max: 60, timeWindow: '1 minute' } }
  }, async (request, reply) => {
    try {
      const planId = Number(request.body.planId)
      const plan = Number.isInteger(planId) && planId > 0 ? await getHourlyPlanForUser(request.user, planId) : null
      if (!plan) return reply.code(404).send({ error: '按小时计费方案不存在或无权访问', code: 'HOURLY_PLAN_NOT_FOUND' })
      const pricing = hourlyPricingFromPackagePlan(plan)
      const resources = parseResources(request.body)
      const breakdown = calculateHourlyBreakdown(resources, pricing)
      return { pricing: serializePricing(pricing), resources, breakdown: serializeBreakdown(breakdown) }
    } catch (error) {
      const message = errorMessage(error)
      return reply.code(400).send({ error: message, code: 'HOURLY_QUOTE_INVALID' })
    }
  })

  fastify.post('/instances/hourly', {
    onRequest: [fastify.authenticateUser],
    config: { rateLimit: { max: 10, timeWindow: '1 minute' } }
  }, async (_request, reply) => {
    return reply.code(410).send({
      error: '按小时计费实例必须通过套餐方案创建',
      code: 'HOURLY_PLAN_REQUIRED'
    })
  })

  fastify.get<{ Params: { id: string } }>('/instances/:id/hourly-billing', { onRequest: [fastify.authenticate] }, async (request, reply) => {
    const id = Number(request.params.id)
    const instance = await prisma.instance.findUnique({
      where: { id },
      include: { host: { select: { userId: true } }, hourlyBillingAccount: { include: { packagePlan: true, pricingVersion: true } } }
    })
    if (!instance || instance.billingMode !== 'hourly' || !instance.hourlyBillingAccount) return reply.code(404).send({ error: 'Hourly billing account not found' })
    if (!canAccessInstance(request.user, instance)) return reply.code(403).send(apiError(ErrorCode.FORBIDDEN))
    const account = instance.hourlyBillingAccount
    const pricing = account.packagePlan
      ? hourlyPricingFromPackagePlan(account.packagePlan)
      : account.pricingVersion
    if (!pricing) return reply.code(409).send({ error: 'Hourly billing pricing is missing', code: 'HOURLY_PRICING_MISSING' })
    const breakdown = calculateHourlyBreakdown({ cpu: instance.cpu, memory: instance.memory, disk: instance.disk }, pricing)
    return {
      instanceId: id,
      billingMode: instance.billingMode,
      status: account.status,
      pricing: serializePricing(pricing),
      resources: { cpu: instance.cpu, memory: instance.memory, disk: instance.disk },
      hourlyPrice: serializeHourlyDecimal(breakdown.hourlyPrice),
      prepaidBalance: serializeHourlyDecimal(account.prepaidBalance),
      totalCost: serializeHourlyDecimal(account.totalCost),
      totalReserved: serializeHourlyDecimal(account.totalReserved),
      totalReleased: serializeHourlyDecimal(account.totalReleased),
      outstandingAmount: serializeHourlyDecimal(account.outstandingAmount),
      lastSettledAt: account.lastSettledAt.toISOString(),
      nextSettlementAt: account.nextSettlementAt?.toISOString() ?? null
    }
  })

  fastify.get<{ Params: { id: string }; Querystring: { limit?: string } }>('/instances/:id/hourly-billing/records', { onRequest: [fastify.authenticate] }, async (request, reply) => {
    const id = Number(request.params.id)
    const instance = await prisma.instance.findUnique({ where: { id }, include: { host: { select: { userId: true } } } })
    if (!instance || instance.billingMode !== 'hourly') return reply.code(404).send({ error: 'Hourly billing account not found' })
    if (!canAccessInstance(request.user, instance)) return reply.code(403).send(apiError(ErrorCode.FORBIDDEN))
    const limit = Math.min(Math.max(Number(request.query.limit || 50), 1), 200)
    const records = await prisma.hourlyBillingRecord.findMany({ where: { instanceId: id }, orderBy: { periodEnd: 'desc' }, take: limit })
    return {
      records: records.map(record => ({
        id: record.id,
        periodStart: record.periodStart.toISOString(),
        periodEnd: record.periodEnd.toISOString(),
        activeSeconds: record.activeSeconds,
        cpu: record.cpu,
        memory: record.memory,
        disk: record.disk,
        cpuAmount: serializeHourlyDecimal(record.cpuAmount),
        memoryAmount: serializeHourlyDecimal(record.memoryAmount),
        diskAmount: serializeHourlyDecimal(record.diskAmount),
        actualAmount: serializeHourlyDecimal(record.actualAmount),
        reserveAmount: serializeHourlyDecimal(record.reserveAmount),
        releaseAmount: serializeHourlyDecimal(record.releaseAmount),
        status: record.status
      }))
    }
  })

  fastify.post<{ Params: { id: string }; Body: HourlyResources }>('/instances/:id/hourly/resize-preview', { onRequest: [fastify.authenticateUser] }, async (request, reply) => {
    const id = Number(request.params.id)
    const instance = await prisma.instance.findUnique({ where: { id }, include: { hourlyBillingAccount: { include: { packagePlan: true, pricingVersion: true } } } })
    if (!instance || instance.billingMode !== 'hourly' || !instance.hourlyBillingAccount) return reply.code(404).send({ error: 'Hourly instance not found' })
    if (instance.userId !== request.user.id && request.user.role !== 'admin') return reply.code(403).send(apiError(ErrorCode.FORBIDDEN))
    try {
      const resources = parseResources(request.body)
      const pricing = instance.hourlyBillingAccount.packagePlan
        ? hourlyPricingFromPackagePlan(instance.hourlyBillingAccount.packagePlan)
        : instance.hourlyBillingAccount.pricingVersion
      if (!pricing) throw new Error('Hourly billing pricing is missing')
      const breakdown = calculateHourlyBreakdown(resources, pricing)
      return { resources, pricing: serializePricing(pricing), breakdown: serializeBreakdown(breakdown) }
    } catch (error) {
      return reply.code(400).send({ error: errorMessage(error), code: 'HOURLY_RESIZE_INVALID' })
    }
  })

  fastify.get('/admin/hourly-billing/pricing', { onRequest: [fastify.authenticateAdmin] }, async (_request, reply) => {
    return reply.code(410).send({
      error: '按小时价格已搬入套餐方案，请在方案编辑页配置',
      code: 'HOURLY_PRICING_MOVED_TO_PLAN'
    })
  })

  fastify.post('/admin/hourly-billing/pricing/versions', { onRequest: [fastify.authenticateAdmin] }, async (_request, reply) => {
    return reply.code(410).send({
      error: '按小时价格已搬入套餐方案，请在方案编辑页配置',
      code: 'HOURLY_PRICING_MOVED_TO_PLAN'
    })
  })

  fastify.patch<{ Params: { id: string }; Body: { enabled: boolean } }>('/admin/hourly-billing/hosts/:id', { onRequest: [fastify.authenticateAdmin] }, async (request, reply) => {
    const hostId = Number(request.params.id)
    if (!Number.isInteger(hostId) || typeof request.body.enabled !== 'boolean') return reply.code(400).send({ error: 'Invalid host switch' })
    const result = await prisma.host.updateMany({ where: { id: hostId }, data: { hourlyBillingEnabled: request.body.enabled } })
    if (result.count !== 1) return reply.code(404).send(apiError(ErrorCode.HOST_NOT_FOUND))
    return { hostId, hourlyBillingEnabled: request.body.enabled }
  })

  fastify.get('/admin/hourly-billing/instances', { onRequest: [fastify.authenticateAdmin] }, async () => {
    const instances = await prisma.instance.findMany({
      where: { billingMode: 'hourly' },
      include: { user: { select: { id: true, username: true } }, host: { select: { id: true, name: true } }, hourlyBillingAccount: true },
      orderBy: { id: 'desc' },
      take: 200
    })
    return {
      instances: instances.map(instance => ({
        id: instance.id,
        name: instance.name,
        status: instance.status,
        user: instance.user,
        host: instance.host,
        cpu: instance.cpu,
        memory: instance.memory,
        disk: instance.disk,
        account: instance.hourlyBillingAccount ? {
          status: instance.hourlyBillingAccount.status,
          prepaidBalance: serializeHourlyDecimal(instance.hourlyBillingAccount.prepaidBalance),
          totalCost: serializeHourlyDecimal(instance.hourlyBillingAccount.totalCost),
          outstandingAmount: serializeHourlyDecimal(instance.hourlyBillingAccount.outstandingAmount)
        } : null
      }))
    }
  })

  fastify.get<{ Querystring: { instanceId?: string; limit?: string } }>('/admin/hourly-billing/records', { onRequest: [fastify.authenticateAdmin] }, async request => {
    const limit = Math.min(Math.max(Number(request.query.limit || 100), 1), 500)
    const instanceId = request.query.instanceId ? Number(request.query.instanceId) : undefined
    const records = await prisma.hourlyBillingRecord.findMany({ where: instanceId ? { instanceId } : undefined, orderBy: { periodEnd: 'desc' }, take: limit })
    return { records: records.map(record => ({ ...record, traffic: undefined, actualAmount: serializeHourlyDecimal(record.actualAmount), cpuAmount: serializeHourlyDecimal(record.cpuAmount), memoryAmount: serializeHourlyDecimal(record.memoryAmount), diskAmount: serializeHourlyDecimal(record.diskAmount), reserveAmount: serializeHourlyDecimal(record.reserveAmount), releaseAmount: serializeHourlyDecimal(record.releaseAmount) })) }
  })

  fastify.post('/admin/hourly-billing/reconcile', { onRequest: [fastify.authenticateAdmin], config: { rateLimit: { max: 10, timeWindow: '1 minute' } } }, async () => {
    await runHourlyBillingJob()
    return { message: 'Hourly billing reconciliation completed' }
  })

}
