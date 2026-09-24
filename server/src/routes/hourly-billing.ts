import type { FastifyInstance } from 'fastify'
import { Prisma } from '@prisma/client'
import { prisma } from '../db/prisma.js'
import { apiError, ErrorCode } from '../lib/errors.js'
import {
  calculateHourlyBreakdown,
  serializeHourlyDecimal,
  validateHourlyResources,
  type HourlyResources
} from '../lib/hourly-billing.js'
import {
  getCurrentHourlyPricing,
  quoteHourlyResources,
  runHourlyBillingJob
} from '../services/hourly-billing-scheduler.js'

function parseResources(input: Partial<HourlyResources>): HourlyResources {
  return {
    cpu: Number(input.cpu),
    memory: Number(input.memory),
    disk: Number(input.disk)
  }
}

function serializePricing(pricing: NonNullable<Awaited<ReturnType<typeof getCurrentHourlyPricing>>>) {
  return {
    id: pricing.id,
    version: pricing.version,
    enabled: pricing.enabled,
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
    trafficUnitPrice: pricing.trafficUnitPrice.toString(),
    trafficIncludedBytes: pricing.trafficIncludedBytes.toString(),
    effectiveAt: pricing.effectiveAt.toISOString()
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

export default async function hourlyBillingRoutes(fastify: FastifyInstance) {
  fastify.get('/hourly-billing/catalog', { onRequest: [fastify.authenticate] }, async () => {
    const pricing = await getCurrentHourlyPricing()
    const hosts = await prisma.host.findMany({
      where: { status: 'online', hourlyBillingEnabled: true },
      select: {
        id: true,
        name: true,
        location: true,
        countryCode: true,
        architecture: true,
        instanceType: true,
        cpuAllowanceMax: true,
        memoryMax: true
      },
      orderBy: { id: 'asc' }
    })
    return {
      enabled: Boolean(pricing),
      pricing: pricing ? serializePricing(pricing) : null,
      hosts
    }
  })

  fastify.get<{ Querystring: { cpu?: string; memory?: string; disk?: string } }>('/instances/hourly/available-hosts', {
    onRequest: [fastify.authenticate]
  }, async (request, reply) => {
    const pricing = await getCurrentHourlyPricing()
    if (!pricing) return reply.code(404).send({ error: 'Hourly billing is not enabled', code: 'HOURLY_BILLING_DISABLED' })
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

  fastify.post<{ Body: HourlyResources }>('/instances/hourly/quote', {
    onRequest: [fastify.authenticate],
    config: { rateLimit: { max: 60, timeWindow: '1 minute' } }
  }, async (request, reply) => {
    try {
      const resources = parseResources(request.body)
      const { pricing, breakdown } = await quoteHourlyResources(resources)
      return { pricing: serializePricing(pricing), resources, breakdown: serializeBreakdown(breakdown) }
    } catch (error) {
      const message = errorMessage(error)
      return reply.code(message === 'HOURLY_BILLING_DISABLED' ? 404 : 400).send({ error: message, code: 'HOURLY_QUOTE_INVALID' })
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
      include: { host: { select: { userId: true } }, hourlyBillingAccount: { include: { pricingVersion: true } } }
    })
    if (!instance || instance.billingMode !== 'hourly' || !instance.hourlyBillingAccount) return reply.code(404).send({ error: 'Hourly billing account not found' })
    if (!canAccessInstance(request.user, instance)) return reply.code(403).send(apiError(ErrorCode.FORBIDDEN))
    const account = instance.hourlyBillingAccount
    const breakdown = calculateHourlyBreakdown({ cpu: instance.cpu, memory: instance.memory, disk: instance.disk }, account.pricingVersion)
    return {
      instanceId: id,
      billingMode: instance.billingMode,
      status: account.status,
      pricing: serializePricing(account.pricingVersion),
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
    const instance = await prisma.instance.findUnique({ where: { id }, include: { hourlyBillingAccount: { include: { pricingVersion: true } } } })
    if (!instance || instance.billingMode !== 'hourly' || !instance.hourlyBillingAccount) return reply.code(404).send({ error: 'Hourly instance not found' })
    if (instance.userId !== request.user.id && request.user.role !== 'admin') return reply.code(403).send(apiError(ErrorCode.FORBIDDEN))
    try {
      const resources = parseResources(request.body)
      const pricing = instance.hourlyBillingAccount.pricingVersion
      const breakdown = calculateHourlyBreakdown(resources, pricing)
      return { resources, pricing: serializePricing(pricing), breakdown: serializeBreakdown(breakdown) }
    } catch (error) {
      return reply.code(400).send({ error: errorMessage(error), code: 'HOURLY_RESIZE_INVALID' })
    }
  })

  fastify.get('/admin/hourly-billing/pricing', { onRequest: [fastify.authenticateAdmin] }, async () => {
    const versions = await prisma.hourlyPricingVersion.findMany({ orderBy: { version: 'desc' }, take: 100 })
    return { versions: versions.map(serializePricing) }
  })

  fastify.post<{ Body: {
    version?: number
    enabled?: boolean
    cpuUnitPercent?: number
    memoryUnitMb?: number
    diskUnitMb?: number
    minCpu?: number
    minMemoryMb?: number
    minDiskMb?: number
    cpuPricePerUnit: string | number
    memoryPricePerUnit: string | number
    diskPricePerUnit: string | number
    reserveQuantum?: string | number
    trafficUnitPrice?: string | number
    trafficIncludedBytes?: string
    effectiveAt?: string
  } }>('/admin/hourly-billing/pricing/versions', { onRequest: [fastify.authenticateAdmin] }, async (request, reply) => {
    const body = request.body
    try {
      const cpuUnitPercent = body.cpuUnitPercent ?? 5
      const memoryUnitMb = body.memoryUnitMb ?? 64
      const diskUnitMb = body.diskUnitMb ?? 512
      const minCpu = body.minCpu ?? 15
      const minMemoryMb = body.minMemoryMb ?? 128
      const minDiskMb = body.minDiskMb ?? 512
      const effectiveAt = body.effectiveAt ? new Date(body.effectiveAt) : new Date()
      const cpuPricePerUnit = new Prisma.Decimal(String(body.cpuPricePerUnit))
      const memoryPricePerUnit = new Prisma.Decimal(String(body.memoryPricePerUnit))
      const diskPricePerUnit = new Prisma.Decimal(String(body.diskPricePerUnit))
      const reserveQuantum = new Prisma.Decimal(String(body.reserveQuantum ?? '0.01'))
      const trafficUnitPrice = new Prisma.Decimal(String(body.trafficUnitPrice ?? '0'))
      const trafficIncludedBytes = BigInt(body.trafficIncludedBytes || '0')
      if (!Number.isInteger(cpuUnitPercent) || !Number.isInteger(memoryUnitMb) || !Number.isInteger(diskUnitMb) || cpuUnitPercent <= 0 || memoryUnitMb <= 0 || diskUnitMb <= 0) throw new Error('Invalid resource unit')
      if (![minCpu, minMemoryMb, minDiskMb].every(Number.isInteger) || minCpu < 15 || minMemoryMb < 128 || minDiskMb < 512 || minCpu % cpuUnitPercent !== 0 || minMemoryMb % memoryUnitMb !== 0 || minDiskMb % diskUnitMb !== 0) throw new Error('Minimum resources are below the product minimum or do not align with their units')
      if (Number.isNaN(effectiveAt.getTime())) throw new Error('Invalid effectiveAt')
      if (cpuPricePerUnit.lt(0) || memoryPricePerUnit.lt(0) || diskPricePerUnit.lt(0) || reserveQuantum.lte(0) || trafficUnitPrice.lt(0) || trafficIncludedBytes < 0n) throw new Error('Prices must be non-negative, trafficIncludedBytes must be non-negative, and reserveQuantum must be positive')
      const version = body.version ?? ((await prisma.hourlyPricingVersion.aggregate({ _max: { version: true } }))._max.version ?? 0) + 1
      const pricing = await prisma.$transaction(async tx => {
        // A future version becomes active at effectiveAt; keep the current
        // version enabled until then so quotes do not unexpectedly disappear.
        if (body.enabled !== false && effectiveAt <= new Date()) await tx.hourlyPricingVersion.updateMany({ data: { enabled: false } })
        return tx.hourlyPricingVersion.create({
          data: {
            version,
            enabled: body.enabled !== false,
            cpuUnitPercent,
            memoryUnitMb,
            diskUnitMb,
            minCpu,
            minMemoryMb,
            minDiskMb,
            cpuPricePerUnit,
            memoryPricePerUnit,
            diskPricePerUnit,
            reserveQuantum,
            trafficUnitPrice,
            trafficIncludedBytes,
            effectiveAt,
            createdBy: request.user.id
          }
        })
      })
      return reply.code(201).send({ pricing: serializePricing(pricing) })
    } catch (error) {
      return reply.code(400).send({ error: errorMessage(error), code: 'HOURLY_PRICING_INVALID' })
    }
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
