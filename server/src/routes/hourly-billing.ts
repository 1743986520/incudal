import type { FastifyInstance } from 'fastify'
import { Prisma } from '@prisma/client'
import * as db from '../db/index.js'
import { prisma } from '../db/prisma.js'
import { apiError, ErrorCode } from '../lib/errors.js'
import { validateName, encryptSensitiveData } from '../lib/security.js'
import { generateIncusConfig, generateRandomPassword } from '../lib/incus-config-generator.js'
import { createInstanceAsync } from './instances/create-async.js'
import { customAlphabet } from 'nanoid'
import {
  calculateHourlyBreakdown,
  serializeHourlyDecimal,
  validateHourlyResources,
  type HourlyResources
} from '../lib/hourly-billing.js'
import {
  activateHourlyBilling,
  getCurrentHourlyPricing,
  quoteHourlyResources,
  runHourlyBillingJob
} from '../services/hourly-billing-scheduler.js'
import {
  getSystemImageAvailabilityForHost,
  isImageCompatibleWithInstanceType,
  isImageCompatibleWithMemory,
  isValidSystemImage
} from '../db/images.js'
import { resolveStoragePoolForNewInstance } from '../db/storage-pools.js'
import { failCreatingInstanceAndRefund } from '../db/billing-operations.js'
import type { Host } from '../types/database.js'

const nanoid = customAlphabet('abcdefghijklmnopqrstuvwxyz0123456789', 8)
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

async function buildHourlyCreateConfig(params: {
  name: string
  image: string
  instanceType: 'container' | 'vm'
  sshKey?: string
  host: Host
  ipv4: string | null
  ipv6: string | null
  password: string
}) {
  const network = params.ipv4 || params.ipv6
    ? {
        ipAddress: params.ipv4 ? `${params.ipv4}/22` : undefined,
        gateway: params.ipv4 ? '10.10.0.1' : undefined,
        dns: params.ipv4 ? ['10.10.0.1'] : undefined,
        ipv6Address: params.ipv6 ? `${params.ipv6}/128` : undefined,
        ipv6Gateway: params.host.ipv6_gateway || undefined
      }
    : undefined

  if (params.instanceType === 'vm') {
    const { generateVmConfig } = await import('../lib/incus-config-vm.js')
    return generateVmConfig({
      instanceName: params.name,
      instanceIdSeed: params.name,
      imageAlias: params.image,
      rootPassword: params.password,
      sshKey: params.sshKey,
      network,
      extraShellCommands: undefined
    }).configPayload
  }

  return generateIncusConfig({
    instanceName: params.name,
    imageAlias: params.image,
    rootPassword: params.password,
    sshKey: params.sshKey,
    networkMode: 'nat',
    type: 'container',
    network,
    extraShellCommands: undefined
  }).configPayload
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

  fastify.post<{
    Body: {
      name: string
      hostId: number
      image: string
      cpu: number
      memory: number
      disk: number
      instanceType?: 'container' | 'vm'
      sshKeyId?: number
      sshKey?: string
    }
  }>('/instances/hourly', {
    onRequest: [fastify.authenticateUser],
    config: { rateLimit: { max: 10, timeWindow: '1 minute' } }
  }, async (request, reply) => {
    const { user } = request
    const { name, hostId, image, instanceType = 'container', sshKeyId } = request.body
    let { sshKey } = request.body
    const resources = parseResources(request.body)

    if (!Number.isInteger(hostId) || hostId <= 0) {
      return reply.code(400).send(apiError(ErrorCode.INVALID_PARAMS, '宿主机参数无效'))
    }
    const nameValidation = validateName(name, 'Instance name', 2, 64)
    if (!nameValidation.valid) return reply.code(400).send({ error: nameValidation.message, code: 'INVALID_NAME' })
    if (sshKeyId && !sshKey) {
      const key = await db.getSSHKeyById(sshKeyId)
      if (!key || key.user_id !== user.id) return reply.code(400).send(apiError(ErrorCode.SSH_KEY_NOT_OWNED))
      sshKey = key.public_key
    }
    if (!sshKey) return reply.code(400).send(apiError(ErrorCode.SSH_KEY_REQUIRED))
    if (!['container', 'vm'].includes(instanceType)) return reply.code(400).send({ error: 'Invalid instance type' })
    if (!await isValidSystemImage(image)) return reply.code(400).send(apiError(ErrorCode.IMAGE_NOT_FOUND))

    let pricing: Awaited<ReturnType<typeof getCurrentHourlyPricing>>
    let breakdown: ReturnType<typeof calculateHourlyBreakdown>
    try {
      const quote = await quoteHourlyResources(resources)
      pricing = quote.pricing
      breakdown = quote.breakdown
    } catch (error) {
      const message = errorMessage(error)
      return reply.code(message === 'HOURLY_BILLING_DISABLED' ? 404 : 400).send({ error: message, code: 'HOURLY_QUOTE_INVALID' })
    }

    const hostPreview = await db.selectAvailableHost({ ...resources, hostId, requireHourlyBillingEnabled: true })
    if (!hostPreview) return reply.code(400).send(apiError(ErrorCode.HOST_UNAVAILABLE))
    if (!await isImageCompatibleWithInstanceType(image, instanceType)) return reply.code(400).send(apiError(ErrorCode.IMAGE_TYPE_MISMATCH))
    if (!await isImageCompatibleWithMemory(image, resources.memory)) return reply.code(400).send(apiError(ErrorCode.IMAGE_MEMORY_INCOMPATIBLE))
    const hostType = hostPreview.instance_type || 'container'
    if ((instanceType === 'vm' && hostType === 'container') || (instanceType === 'container' && hostType === 'vm')) {
      return reply.code(400).send(apiError(ErrorCode.HOST_INSTANCE_TYPE_MISMATCH))
    }
    const availability = await getSystemImageAvailabilityForHost(image, hostId, { instanceType, memory: resources.memory })
    if (!availability.ok) return reply.code(400).send(apiError(ErrorCode.INSTANCE_IMAGE_UNAVAILABLE))

    const host = await db.getHostById(hostId)
    if (!host) return reply.code(404).send(apiError(ErrorCode.HOST_NOT_FOUND))
    const password = generateRandomPassword(16)
    const incusId = `u${user.id}-${nanoid()}`
    const now = new Date()
    const reserveQuantum = new Prisma.Decimal(pricing!.reserveQuantum)
    const portLimit = 0

    let instanceId = 0
    let lockedHost: Awaited<ReturnType<typeof db.selectAndReserveHostWithLock>>
    try {
      const result = await prisma.$transaction(async tx => {
        const reservedHost = await db.selectAndReserveHostWithLock(tx, {
          cpu: resources.cpu,
          memory: resources.memory,
          disk: resources.disk,
          hostId,
          portCount: 0,
          requireHourlyBillingEnabled: true
        })
        if (!reservedHost) throw new Error('HOST_RESOURCES_INSUFFICIENT')

        const walletUser = await tx.user.findUnique({ where: { id: user.id }, select: { balance: true } })
        if (!walletUser) throw new Error('USER_NOT_FOUND')
        const balanceBefore = new Prisma.Decimal(walletUser.balance)
        if (balanceBefore.lt(reserveQuantum)) throw new Error('BALANCE_INSUFFICIENT')
        const balanceAfter = balanceBefore.sub(reserveQuantum)
        const walletUpdate = await tx.user.updateMany({
          where: { id: user.id, balance: { gte: reserveQuantum } },
          data: {
            balance: { decrement: reserveQuantum },
            hourlyReservedBalance: { increment: reserveQuantum }
          }
        })
        if (walletUpdate.count !== 1) throw new Error('BALANCE_INSUFFICIENT')

        const snapshotSpecs = {
          billingMode: 'hourly',
          pricingVersionId: pricing!.id,
          pricingVersion: pricing!.version,
          cpu: resources.cpu,
          memory: resources.memory,
          disk: resources.disk,
          trafficBillingMode: 'usage',
          createdAt: now.toISOString()
        }
        const instance = await tx.instance.create({
          data: {
            incusId,
            name,
            userId: user.id,
            hostId: reservedHost.id,
            packageId: null,
            packagePlanId: null,
            billingMode: 'hourly',
            image,
            cpu: resources.cpu,
            memory: resources.memory,
            disk: resources.disk,
            networkMode: 'nat',
            status: 'creating',
            snapshottedSpecs: snapshotSpecs,
            sshPort: 22,
            rootPassword: encryptSensitiveData(password),
            portLimit,
            monthlyTrafficLimit: pricing!.trafficIncludedBytes,
            trafficBillingMode: 'usage',
            trafficUnitPrice: pricing!.trafficUnitPrice,
            nextTrafficBillingAt: pricing!.trafficUnitPrice.gt(0) ? new Date(now.getTime() + 60 * 60 * 1000) : null
          }
        })
        const balanceLog = await tx.balanceLog.create({
          data: {
            userId: user.id,
            instanceId: instance.id,
            type: 'hourly_reserve',
            amount: reserveQuantum.neg(),
            balanceBefore,
            balanceAfter,
            remark: `创建按小时计费实例，冻结预付款 ${serializeHourlyDecimal(reserveQuantum)}`
          }
        })
        await tx.hourlyBillingAccount.create({
          data: {
            instanceId: instance.id,
            pricingVersionId: pricing!.id,
            lastSettledAt: now,
            nextSettlementAt: null,
            prepaidBalance: reserveQuantum,
            totalReserved: reserveQuantum,
            status: 'paused'
          }
        })
        return { instanceId: instance.id, host: reservedHost, balanceLogId: balanceLog.id }
      }, { isolationLevel: Prisma.TransactionIsolationLevel.Serializable, timeout: 15000 })
      instanceId = result.instanceId
      lockedHost = result.host
    } catch (error) {
      const message = errorMessage(error)
      if (message.includes('BALANCE_INSUFFICIENT')) return reply.code(400).send(apiError(ErrorCode.BALANCE_INSUFFICIENT, '余额不足，需要冻结 ¥0.01'))
      if (message.includes('HOST_RESOURCES_INSUFFICIENT')) return reply.code(503).send(apiError(ErrorCode.HOST_RESOURCES_INSUFFICIENT))
      throw error
    }

    const actualHost = (await db.getHostById(lockedHost!.id)) || (lockedHost as unknown as Host)
    try {
      const needsIpv6 = false
      const reservedAddresses = await db.reserveInstanceIpAddresses({
        instanceId,
        hostId: actualHost.id,
        allocateIpv4: true,
        ipv6Subnet: needsIpv6 ? actualHost.ipv6_subnet : null
      })
      const selectedStoragePool = await resolveStoragePoolForNewInstance(actualHost.id, { packageId: null })
      if (!selectedStoragePool) throw new Error('STORAGE_POOL_NOT_CONFIGURED')
      const configPayload = await buildHourlyCreateConfig({
        name: incusId,
        image,
        instanceType,
        sshKey,
        host: actualHost,
        ipv4: reservedAddresses.ipv4,
        ipv6: reservedAddresses.ipv6,
        password
      })
      await prisma.instance.update({
        where: { id: instanceId },
        data: { storagePoolName: selectedStoragePool }
      })

      void createInstanceAsync(instanceId, actualHost, {
        name: incusId,
        image,
        cpu: resources.cpu,
        memory: resources.memory,
        disk: resources.disk,
        cloudInitConfig: configPayload,
        networkMode: 'nat',
        instanceType,
        portLimit,
        storagePool: selectedStoragePool,
        ipv4Address: reservedAddresses.ipv4,
        ipv6Address: reservedAddresses.ipv6,
        ipv6Gateway: actualHost.ipv6_gateway || null,
        hostInterface: actualHost.ipv6_parent_interface || 'eth0'
      }, user.id, resources).then(async () => {
        await activateHourlyBilling(instanceId)
      }).catch(error => {
        fastify.log.error({ err: errorMessage(error), instanceId }, 'Hourly instance provisioning failed')
      })

      return reply.code(202).send({
        message: 'Hourly instance creation queued',
        instanceId,
        billingMode: 'hourly',
        pricingVersion: pricing!.version,
        hourlyPrice: serializeHourlyDecimal(breakdown!.hourlyPrice),
        reservedAmount: serializeHourlyDecimal(reserveQuantum)
      })
    } catch (error) {
      const message = errorMessage(error)
      // The transaction above has already reserved host capacity and wallet
      // funds. This preparation phase runs before createInstanceAsync starts,
      // so its normal failure handler cannot compensate the reservation.
      try {
        await prisma.ipAddress.deleteMany({ where: { instanceId } })
      } catch (cleanupError) {
        fastify.log.error({ err: cleanupError, instanceId }, 'Failed to release hourly provisioning IP reservation')
      }
      try {
        await failCreatingInstanceAndRefund(instanceId, message, {
          hostId: actualHost.id,
          cpu: resources.cpu,
          memory: resources.memory,
          disk: resources.disk,
          portCount: 0
        })
      } catch (settlementError) {
        fastify.log.error({ err: settlementError, instanceId }, 'Failed to compensate hourly instance creation')
      }
      if (message === 'STORAGE_POOL_NOT_CONFIGURED') {
        return reply.code(400).send(apiError(ErrorCode.STORAGE_POOL_NOT_CONFIGURED))
      }
      return reply.code(500).send({ error: message, code: 'HOURLY_CREATE_FAILED' })
    }
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
