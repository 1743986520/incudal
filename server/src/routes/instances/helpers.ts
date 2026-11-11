/**
 * 实例路由共享辅助函数和类型
 */

import type { FastifyReply } from 'fastify'
import type { InstanceStatus } from '@prisma/client'
import * as db from '../../db/index.js'
import { prisma } from '../../db/prisma.js'
import { apiError, ErrorCode } from '../../lib/errors.js'
import {
  INSTANCE_OPERATION_LOCK_NAMESPACE,
  tryAdvisoryTransactionLock
} from '../../db/advisory-locks.js'
import {
  getSystemImageAvailabilityForHost
} from '../../db/images.js'
import { getPlanById } from '../../db/package-plans.js'
import {
  applyTrafficMultiplier,
  normalizeTrafficMultiplier
} from '../../lib/traffic-multiplier.js'
import { getSafeHttpUrl } from '../../lib/external-url.js'
import { notifyStoragePoolMissing } from '../../lib/storage-pool-notify.js'

// 检查实例是否被转移锁定
export async function checkTransferLock(instanceId: number, reply: FastifyReply): Promise<boolean> {
  const hasPending = await db.hasPendingTransfer(instanceId)
  if (hasPending) {
    reply.code(400).send(apiError(ErrorCode.TRANSFER_INSTANCE_LOCKED))
    return true
  }
  return false
}

export async function claimInstanceForDelete(
  instanceId: number,
  currentStatus: InstanceStatus,
  options: {
    authorization: {
      actorUserId: number
      actorRole: 'admin' | 'user'
      scope: 'instance-or-host' | 'host-only'
      expectedUserId: number
      expectedHostId: number
      expectedHostUserId: number
      expectedIncusId: string
      expectedVersion: number
      expectedPackagePlanId: number | null
      expectedPackageId: number | null
      expectedSuspendReason: string | null
      expectedBillingMode: 'package' | 'hourly'
      expectedTrafficBillingMode?: 'package' | 'usage'
    }
    deletionBillingPending?: boolean
    deletionBillingMode?: 'privileged_delete' | 'hourly_close' | null
    deletionRefundableValue?: number | null
    pending?: { requestedById: number; reason?: string }
  }
): Promise<boolean> {
  // A deleted instance is already claimed or finalized; never reset its
  // pending settlement by treating its current status as a fresh claim.
  if (currentStatus === 'deleted' || currentStatus === 'deleting' || (options.pending && currentStatus === 'creating')) return false

  return prisma.$transaction(async (tx) => {
    const locked = await tryAdvisoryTransactionLock(tx, INSTANCE_OPERATION_LOCK_NAMESPACE, instanceId)
    if (!locked) return false

    // Lock the host owner row through the claim commit. A stale host-owner
    // permission snapshot must not authorize deletion after ownership changes.
    const auth = options.authorization
    // User role and ban changes update this same row. Holding it through the
    // claim prevents an in-flight request from using revoked authorization.
    const actors = await tx.$queryRaw<Array<{ role: string; status: string }>>`
      SELECT "role", "status" FROM "users" WHERE "id" = ${auth.actorUserId} FOR UPDATE
    `
    if (actors[0]?.status !== 'active' || actors[0]?.role !== auth.actorRole) return false
    const hosts = await tx.$queryRaw<Array<{ userId: number }>>`
      SELECT "user_id" AS "userId" FROM "hosts" WHERE "id" = ${auth.expectedHostId} FOR UPDATE
    `
    const hostOwnerId = hosts[0]?.userId
    if (hostOwnerId !== auth.expectedHostUserId) return false
    const authorized = auth.actorRole === 'admin' || auth.actorUserId === hostOwnerId
      || (auth.scope === 'instance-or-host' && auth.actorUserId === auth.expectedUserId)
    if (!authorized) return false

    // Regular instance owners remain subject to the package deletion policy.
    // A shared row lock prevents that policy changing between revalidation and
    // the claim; privileged host owners/admins retain the existing exemption.
    const privileged = auth.actorRole === 'admin' || auth.actorUserId === hostOwnerId
    if (!privileged && auth.scope === 'instance-or-host') {
      if (auth.expectedPackagePlanId !== null || currentStatus === 'suspended') return false
      if (auth.expectedPackageId !== null) {
        const policies = await tx.$queryRaw<Array<{ allowed: boolean }>>`
          SELECT "allow_instance_deletion" AS "allowed" FROM "packages" WHERE "id" = ${auth.expectedPackageId} FOR SHARE
        `
        if (policies[0]?.allowed !== true) return false
      }
    }

    const [activeRestoreTask, activeUploadTask, activeInstanceTask, activeTransfer] = await Promise.all([
      tx.restoreTask.findFirst({
        where: { instanceId, status: { in: ['PENDING', 'PROCESSING'] } },
        select: { id: true }
      }),
      tx.backupUploadTask.findFirst({
        where: { instanceId, status: { in: ['PENDING', 'PROCESSING'] } },
        select: { id: true }
      }),
      tx.instanceTask.findFirst({
        where: { instanceId, status: { in: ['PENDING', 'PROCESSING'] } },
        select: { id: true }
      }),
      tx.instanceTransfer.findFirst({
        where: { instanceId, status: { in: ['pending', 'processing'] } },
        select: { id: true }
      })
    ])
    if (activeRestoreTask || activeUploadTask || activeInstanceTask || activeTransfer) return false

    const result = await tx.instance.updateMany({
      where: {
        id: instanceId,
        status: currentStatus,
        userId: auth.expectedUserId,
        hostId: auth.expectedHostId,
        incusId: auth.expectedIncusId,
        version: auth.expectedVersion,
        packagePlanId: auth.expectedPackagePlanId,
        packageId: auth.expectedPackageId,
        suspendReason: auth.expectedSuspendReason,
        billingMode: auth.expectedBillingMode,
        ...(auth.expectedTrafficBillingMode === undefined ? {} : { trafficBillingMode: auth.expectedTrafficBillingMode }),
        // Provisioning cleanup is a separate, externally visible operation.
        // Never claim a row while its cleanup owner could still act on it.
        ...(options.pending ? { provisioningCleanupPending: false } : {})
      },
      data: {
        status: options.pending ? 'deleting' : 'deleted',
        ...(options.pending ? {
          version: { increment: 1 },
          deletionOriginalStatus: currentStatus,
          deletionRequestedAt: new Date(),
          deletionRequestedById: options.pending.requestedById,
          deletionReason: options.pending.reason?.trim() || null
        } : {}),
        deletionBillingPending: options.deletionBillingPending === true,
        deletionRemoteDeleted: false,
        deletionBillingMode: options.deletionBillingMode ?? null,
        deletionRefundableValue: options.deletionRefundableValue ?? null,
        deletionFeeWaiver: false
      }
    })

    return result.count === 1
  })
}

/**
 * 存储池前置校验守卫：节点没有可用的系统盘存储池时直接拒绝创建/重试，
 * 不扣款、不扣配额、不创建实例记录、不生成部署任务。
 * 拦截时记录审计日志，并在冷却窗口内向操作用户发送提醒邮件。
 * @returns true 表示校验通过；false 表示已发送 400 响应
 */
export async function ensureHostStoragePoolOrReply(
  reply: FastifyReply,
  opts: { userId: number; hostId: number; source: string; instanceId?: number }
): Promise<boolean> {
  if (await db.hostHasInstanceDataPool(opts.hostId)) {
    return true
  }
  const host = await db.getHostById(opts.hostId)
  // notifyStoragePoolMissing 内部已捕获全部异常，fire-and-forget 即可
  void notifyStoragePoolMissing({
    userId: opts.userId,
    hostId: opts.hostId,
    hostName: host?.name || `#${opts.hostId}`,
    source: opts.source,
    instanceId: opts.instanceId
  })
  reply.code(400).send(apiError(ErrorCode.STORAGE_POOL_NOT_CONFIGURED,
    '当前节点尚未创建存储池，请创建存储池后再创建实例'))
  return false
}

/**
 * 封停状态守卫：实例被封禁时禁止操作（过期封禁返回专用错误码）
 * @returns true 表示允许继续操作
 */
export function ensureInstanceNotSuspended(
  instance: { status: string; suspend_reason?: string | null },
  reply: FastifyReply
): boolean {
  if (instance.status === 'deleting') {
    reply.code(409).send({ error: 'Instance deletion in progress', code: 'INSTANCE_DELETE_IN_PROGRESS' })
    return false
  }
  if (instance.status !== 'suspended') {
    return true
  }
  if (instance.suspend_reason === 'expired') {
    reply.code(403).send(apiError(ErrorCode.INSTANCE_SUSPENDED_EXPIRED))
  } else {
    reply.code(403).send(apiError(ErrorCode.INSTANCE_SUSPENDED))
  }
  return false
}

// ==================== Change Host 类型 ====================

export type ChangeHostUnavailableReason =
  | 'current_host'
  | 'host_offline'
  | 'host_type_mismatch'
  | 'cpu_full'
  | 'memory_full'
  | 'resource_unconfigured'
  | 'image_unavailable'

export interface ChangeHostHostOption {
  id: number
  name: string
  location: string | null
  countryCode: string
  architecture: string
  status: string
  probeUrl: string | null
  isCurrent: boolean
  canChange: boolean
  unavailableReason: ChangeHostUnavailableReason | null
  resources: {
    cpuUsed: number
    cpuAllowanceMax: number
    cpuAvailable: number
    memoryUsed: number
    memoryMax: number
    memoryAvailable: number
  }
  trafficMultiplier: number
  effectiveTrafficLimit: string | null
}

export interface ChangeHostOptionsResponse {
  packageId: number | null
  packageName: string | null
  currentHostId: number
  required: {
    cpu: number
    memory: number
  }
  hosts: ChangeHostHostOption[]
  sshKeys: Array<{
    id: number
    name: string
    fingerprint: string | null
  }>
  canChangeHost: boolean
  unavailableReason?: 'no_package' | 'single_host' | 'no_ssh_key'
}

export function isHostCompatibleWithPackageInstanceType(
  hostInstanceType: string | null | undefined,
  packageInstanceType: 'container' | 'vm'
): boolean {
  const type = hostInstanceType || 'container'
  if (packageInstanceType === 'vm') return type === 'vm' || type === 'both'
  return type === 'container' || type === 'both'
}

export async function buildChangeHostOptions(instance: {
  id: number
  user_id: number
  host_id: number
  package_id: number | null
  image: string
  cpu: number
  memory: number
  package_plan_id?: number | null
}): Promise<ChangeHostOptionsResponse> {
  const sshKeys = await db.getSSHKeysByUserId(instance.user_id)

  const baseResponse = {
    packageId: null,
    packageName: null,
    currentHostId: instance.host_id,
    required: {
      cpu: instance.cpu,
      memory: instance.memory
    },
    hosts: [],
    sshKeys: sshKeys.map(key => ({
      id: key.id,
      name: key.name,
      fingerprint: key.fingerprint ?? null
    })),
    canChangeHost: false
  } satisfies ChangeHostOptionsResponse

  if (!instance.package_id) {
    return { ...baseResponse, unavailableReason: 'no_package' }
  }

  const pkg = await db.getPackageById(instance.package_id)
  if (!pkg) {
    return { ...baseResponse, unavailableReason: 'no_package' }
  }

  const packageHosts = await prisma.packageHost.findMany({
    where: { packageId: instance.package_id },
    select: {
      hostId: true,
      trafficMultiplier: true,
      host: {
        select: {
          id: true,
          name: true,
          location: true,
          countryCode: true,
          architecture: true,
          status: true,
          cpuUsed: true,
          cpuAllowanceMax: true,
          memoryUsed: true,
          memoryMax: true,
          instanceType: true,
          probeUrl: true
        }
      }
    },
    orderBy: { createdAt: 'asc' }
  })

  const hostIds = packageHosts.map(binding => binding.hostId)
  if (hostIds.length === 0) {
    return {
      ...baseResponse,
      packageId: pkg.id,
      packageName: pkg.name,
      unavailableReason: 'single_host'
    }
  }

  const resourceRows = await prisma.instance.groupBy({
    by: ['hostId'],
    where: {
      hostId: { in: hostIds },
      status: { not: 'deleted' }
    },
    _sum: {
      cpu: true,
      memory: true
    }
  })

  const resourceByHostId = new Map(resourceRows.map(row => [
    row.hostId,
    {
      cpuUsed: row._sum.cpu ?? 0,
      memoryUsed: row._sum.memory ?? 0
    }
  ]))

  const packageInstanceType = ((pkg as { instance_type?: 'container' | 'vm' }).instance_type || 'container')
  let baseTrafficLimit = pkg.monthly_traffic_limit ? BigInt(pkg.monthly_traffic_limit) : null
  if (instance.package_plan_id) {
    const plan = await getPlanById(instance.package_plan_id)
    if (plan && plan.packageId === instance.package_id) {
      baseTrafficLimit = plan.trafficLimit
    }
  }

  const hosts = await Promise.all(packageHosts.map(async binding => {
    const host = binding.host
    const used = resourceByHostId.get(host.id) || { cpuUsed: 0, memoryUsed: 0 }
    const cpuUsed = Math.max(used.cpuUsed, host.cpuUsed || 0)
    const memoryUsed = Math.max(used.memoryUsed, host.memoryUsed || 0)
    const cpuAllowanceMax = host.cpuAllowanceMax || 0
    const memoryMax = host.memoryMax || 0
    const cpuAvailable = cpuAllowanceMax > 0 ? Math.max(0, cpuAllowanceMax - cpuUsed) : 0
    const memoryAvailable = memoryMax > 0 ? Math.max(0, memoryMax - memoryUsed) : 0
    const isCurrent = host.id === instance.host_id

    let unavailableReason: ChangeHostUnavailableReason | null = null
    if (isCurrent) {
      unavailableReason = 'current_host'
    } else if (host.status !== 'online') {
      unavailableReason = 'host_offline'
    } else if (!isHostCompatibleWithPackageInstanceType(host.instanceType, packageInstanceType)) {
      unavailableReason = 'host_type_mismatch'
    } else if (cpuAllowanceMax <= 0 || memoryMax <= 0) {
      unavailableReason = 'resource_unconfigured'
    } else if (cpuAvailable < instance.cpu) {
      unavailableReason = 'cpu_full'
    } else if (memoryAvailable < instance.memory) {
      unavailableReason = 'memory_full'
    } else {
      const imageAvailability = await getSystemImageAvailabilityForHost(instance.image, host.id, {
        instanceType: packageInstanceType,
        memory: instance.memory
      })
      if (!imageAvailability.ok) {
        unavailableReason = 'image_unavailable'
      }
    }

    return {
      id: host.id,
      name: host.name,
      location: host.location,
      countryCode: host.countryCode || 'us',
      architecture: host.architecture || 'x86_64',
      status: host.status,
      probeUrl: getSafeHttpUrl(host.probeUrl),
      isCurrent,
      canChange: unavailableReason === null,
      unavailableReason,
      resources: {
        cpuUsed,
        cpuAllowanceMax,
        cpuAvailable,
        memoryUsed,
        memoryMax,
        memoryAvailable
      },
      trafficMultiplier: normalizeTrafficMultiplier(binding.trafficMultiplier),
      effectiveTrafficLimit: applyTrafficMultiplier(baseTrafficLimit, binding.trafficMultiplier)?.toString() ?? null
    } satisfies ChangeHostHostOption
  }))

  const hasTarget = hosts.some(host => host.canChange)
  return {
    packageId: pkg.id,
    packageName: pkg.name,
    currentHostId: instance.host_id,
    required: {
      cpu: instance.cpu,
      memory: instance.memory
    },
    hosts: hosts.sort((a, b) => {
      if (a.isCurrent !== b.isCurrent) return a.isCurrent ? -1 : 1
      if (a.canChange !== b.canChange) return a.canChange ? -1 : 1
      return a.name.localeCompare(b.name)
    }),
    sshKeys: baseResponse.sshKeys,
    canChangeHost: hasTarget && sshKeys.length > 0,
    unavailableReason: hostIds.length <= 1
      ? 'single_host'
      : (sshKeys.length === 0 ? 'no_ssh_key' : undefined)
  }
}
