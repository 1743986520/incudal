/**
 * 官方优惠券数据库操作
 *
 * 官方优惠券由平台（管理员）发放，与 AFF 优惠码相互独立：
 * - 折扣金额由平台承担：用户支付「原价 - 折扣金额」，托管主仍按原价结算
 * - 官方券不建立 AFF 绑定，也不产生 AFF 返利
 * - 适用范围按套餐归属判定：管理员创建的套餐为官方直营，普通用户创建的套餐为托管
 * - 次数控制在使用事务内通过 advisory lock + 条件更新完成，避免并发超发
 */

import { Prisma, type OfficialCoupon, type OfficialCouponRenewalMode, type OfficialCouponScope } from '@prisma/client'
import { prisma } from './prisma.js'
import { OFFICIAL_COUPON_LOCK_NAMESPACE, tryAdvisoryTransactionLock } from './advisory-locks.js'
import { ErrorCode, type ErrorCodeType } from '../lib/errors.js'
import {
  generateOfficialCouponCode,
  isCouponScopeMatched,
  normalizeOfficialCouponCode,
  resolveUserUsageLimit,
  type PackageCouponScope
} from '../lib/official-coupon-rules.js'

type DbClient = Prisma.TransactionClient | typeof prisma

export {
  generateOfficialCouponCode,
  isCouponScopeMatched,
  normalizeOfficialCouponCode,
  resolveUserUsageLimit,
  type PackageCouponScope
} from '../lib/official-coupon-rules.js'

export interface OfficialCouponScopeInfo {
  scope: OfficialCouponScope
  name: string
  remark: string | null
  discountRate: number
  reusable: boolean
  maxUsesPerUser: number | null
  totalUsageLimit: number | null
  usedCount: number
  enabled: boolean
  startsAt: string | null
  expiresAt: string | null
  createdAt: string
  updatedAt: string
}

/**
 * 查询套餐归属范围（官方直营 / 托管）
 */
export async function getPackageCouponScope(
  packageId: number,
  client: DbClient = prisma
): Promise<PackageCouponScope | null> {
  const pkg = await client.package.findUnique({
    where: { id: packageId },
    select: { user: { select: { role: true } } }
  })

  if (!pkg) return null
  return pkg.user.role === 'admin' ? 'official' : 'hosted'
}

export interface OfficialCouponValidationFailure {
  valid: false
  errorCode: ErrorCodeType
  error: string
}

export interface OfficialCouponValidationSuccess {
  valid: true
  coupon: OfficialCoupon
  code: string
  name: string
  remark: string | null
  discountRate: number
  /** 优惠券本身可用的剩余次数（总次数上限 - 已使用），无上限时为 null */
  remainingUses: number | null
}

export type OfficialCouponValidationResult = OfficialCouponValidationSuccess | OfficialCouponValidationFailure

/**
 * 校验官方优惠券（不写入任何数据）
 *
 * 校验项：是否存在、是否启用、是否在有效期内、是否适用于当前套餐、用户次数、全站总次数
 *
 * @param checkUserLimit 是否检查「每用户使用次数」上限。续费场景传入 false，
 *                       因为每用户次数只约束新购次数，不应阻断实例的后续续费折扣。
 */
export async function validateOfficialCoupon(params: {
  code: string
  packageId: number
  userId: number
  client?: DbClient
  checkUserLimit?: boolean
}): Promise<OfficialCouponValidationResult> {
  const client = params.client || prisma
  const checkUserLimit = params.checkUserLimit !== false
  const code = normalizeOfficialCouponCode(params.code)

  if (!code) {
    return {
      valid: false,
      errorCode: ErrorCode.COUPON_NOT_FOUND,
      error: 'Official coupon not found'
    }
  }

  const coupon = await client.officialCoupon.findUnique({ where: { code } })
  if (!coupon) {
    return {
      valid: false,
      errorCode: ErrorCode.COUPON_NOT_FOUND,
      error: 'Official coupon not found'
    }
  }

  if (!coupon.enabled) {
    return {
      valid: false,
      errorCode: ErrorCode.COUPON_DISABLED,
      error: 'This official coupon has been disabled'
    }
  }

  const now = new Date()
  if (coupon.startsAt && coupon.startsAt > now) {
    return {
      valid: false,
      errorCode: ErrorCode.COUPON_NOT_STARTED,
      error: 'This official coupon is not active yet'
    }
  }
  if (coupon.expiresAt && coupon.expiresAt <= now) {
    return {
      valid: false,
      errorCode: ErrorCode.COUPON_EXPIRED,
      error: 'This official coupon has expired'
    }
  }

  const packageScope = await getPackageCouponScope(params.packageId, client)
  if (!packageScope) {
    return {
      valid: false,
      errorCode: ErrorCode.NOT_FOUND,
      error: 'Package not found'
    }
  }
  if (!isCouponScopeMatched(coupon.scope, packageScope)) {
    return {
      valid: false,
      errorCode: ErrorCode.COUPON_SCOPE_MISMATCH,
      error: 'This official coupon does not apply to the selected package'
    }
  }

  if (coupon.totalUsageLimit !== null && coupon.usedCount >= coupon.totalUsageLimit) {
    return {
      valid: false,
      errorCode: ErrorCode.COUPON_EXHAUSTED,
      error: 'This official coupon has reached its total usage limit'
    }
  }

  const userUsageLimit = resolveUserUsageLimit(coupon)
  if (checkUserLimit && userUsageLimit !== null) {
    const userUsageCount = await client.officialCouponUsage.count({
      where: { couponId: coupon.id, userId: params.userId }
    })
    if (userUsageCount >= userUsageLimit) {
      return {
        valid: false,
        errorCode: ErrorCode.COUPON_USER_LIMIT_REACHED,
        error: 'You have reached the usage limit for this official coupon'
      }
    }
  }

  const remainingUses = coupon.totalUsageLimit === null
    ? null
    : Math.max(0, coupon.totalUsageLimit - coupon.usedCount)

  return {
    valid: true,
    coupon,
    code: coupon.code,
    name: coupon.name,
    remark: coupon.remark,
    discountRate: Number(coupon.discountRate),
    remainingUses
  }
}

/**
 * 在购买事务内预占一次优惠券使用次数
 *
 * 使用 advisory lock 序列化同一张券的并发使用，并配合条件更新保证：
 * - 全站总次数不会被并发突破
 * - 用户次数上限不会被并发突破
 *
 * 抛出的错误会中断整个购买事务，从而保证实例、扣款与使用记录一致回滚。
 *
 * @throws Error 校验失败时抛出 `COUPON_*` 错误码；无法获取锁时抛出 AdvisoryLockBusyError
 */
export async function reserveOfficialCouponUsage(params: {
  code: string
  packageId: number
  userId: number
  instanceId: number
  originalPrice: number
  discountAmount: number
  /** purchase=新购占次；renewal=续费占次（跳过每用户新购次数检查） */
  mode?: 'purchase' | 'renewal'
  tx: Prisma.TransactionClient
}): Promise<{ couponId: number; usageId: number }> {
  const { tx } = params
  const code = normalizeOfficialCouponCode(params.code)

  const coupon = await tx.officialCoupon.findUnique({ where: { code } })
  if (!coupon) {
    throw new Error(`${ErrorCode.COUPON_NOT_FOUND}: Official coupon not found`)
  }

  // 锁住这张券，避免同一张券的并发使用突破次数限制
  const locked = await tryAdvisoryTransactionLock(tx, OFFICIAL_COUPON_LOCK_NAMESPACE, coupon.id)
  if (!locked) {
    // 让上层的错误处理器按可重试冲突返回（RESOURCE_BUSY）
    const busyError = new Error(`Official coupon ${coupon.id} is being processed by another purchase`) as Error & { code?: string }
    busyError.code = 'ADVISORY_LOCK_BUSY'
    throw busyError
  }

  // 事务内重新校验，避免验证与扣款之间券状态被修改
  const validation = await validateOfficialCoupon({
    code,
    packageId: params.packageId,
    userId: params.userId,
    client: tx,
    checkUserLimit: params.mode !== 'renewal'
  })
  if (!validation.valid) {
    throw new Error(`${validation.errorCode}: ${validation.error}`)
  }

  // 条件更新保证总次数上限不被突破
  const updated = await tx.$executeRaw`
    UPDATE "official_coupons"
    SET "used_count" = "used_count" + 1,
        "updated_at" = NOW()
    WHERE "id" = ${coupon.id}
      AND "enabled" = true
      AND ("total_usage_limit" IS NULL OR "used_count" < "total_usage_limit")
  `

  if (updated === 0) {
    throw new Error(`${ErrorCode.COUPON_EXHAUSTED}: This official coupon has reached its total usage limit`)
  }

  const usage = await tx.officialCouponUsage.create({
    data: {
      couponId: coupon.id,
      userId: params.userId,
      instanceId: params.instanceId,
      type: params.mode === 'renewal' ? 'renewal' : 'purchase',
      originalPrice: new Prisma.Decimal(params.originalPrice),
      discountAmount: new Prisma.Decimal(params.discountAmount)
    }
  })

  return { couponId: coupon.id, usageId: usage.id }
}

/**
 * 查询实例购买时使用的官方优惠券（新购记录）
 *
 * 只有购买记录（type=purchase）才参与续期折扣判定，
 * 避免续费产生的使用记录被误当成"该实例的券"。
 */
export async function getInstancePurchaseCoupon(
  instanceId: number,
  client: DbClient = prisma
): Promise<{ coupon: OfficialCoupon; usageId: number } | null> {
  const usage = await client.officialCouponUsage.findFirst({
    where: { instanceId, type: 'purchase' },
    include: { coupon: true }
  })

  if (!usage) return null
  return { coupon: usage.coupon, usageId: usage.id }
}

/**
 * 统计某实例对该券已折价的次数（含首次购买与已折价的续费）
 */
export async function countDiscountedChargesForInstance(
  couponId: number,
  instanceId: number,
  client: DbClient = prisma
): Promise<number> {
  return client.officialCouponUsage.count({
    where: { couponId, instanceId }
  })
}

/**
 * 查询实例关联的官方优惠券使用记录
 */
export async function getOfficialCouponUsageByInstance(
  instanceId: number,
  client: DbClient = prisma
) {
  return client.officialCouponUsage.findFirst({
    where: { instanceId },
    include: { coupon: { select: { id: true, code: true, name: true, discountRate: true } } }
  })
}

/**
 * 释放一次优惠券使用（实例开通失败全额退款时调用）
 *
 * 删除使用记录并回退已使用次数，使优惠券可以再次使用。
 */
export async function releaseOfficialCouponUsageByInstance(
  instanceId: number,
  tx: Prisma.TransactionClient
): Promise<{ couponId: number; couponCode: string; discountAmount: number; userId: number } | null> {
  const usage = await tx.officialCouponUsage.findFirst({
    where: { instanceId },
    include: { coupon: { select: { id: true, code: true } } }
  })

  if (!usage) return null

  await tx.officialCouponUsage.delete({ where: { id: usage.id } })
  await tx.officialCoupon.updateMany({
    where: { id: usage.couponId, usedCount: { gt: 0 } },
    data: { usedCount: { decrement: 1 } }
  })

  return {
    couponId: usage.couponId,
    couponCode: usage.coupon.code,
    discountAmount: Number(usage.discountAmount),
    userId: usage.userId
  }
}

// ==================== 管理端操作 ====================

export interface OfficialCouponListFilters {
  page?: number
  pageSize?: number
  search?: string
  enabled?: boolean
  scope?: OfficialCouponScope
}

/**
 * 管理端优惠券列表
 */
export async function listOfficialCoupons(filters: OfficialCouponListFilters = {}) {
  const page = Math.max(1, filters.page || 1)
  const pageSize = Math.min(100, Math.max(1, filters.pageSize || 20))

  const where: Prisma.OfficialCouponWhereInput = {}
  if (filters.enabled !== undefined) where.enabled = filters.enabled
  if (filters.scope) where.scope = filters.scope
  if (filters.search) {
    const search = filters.search.trim()
    if (search) {
      where.OR = [
        { code: { contains: search, mode: 'insensitive' } },
        { name: { contains: search, mode: 'insensitive' } },
        { remark: { contains: search, mode: 'insensitive' } }
      ]
    }
  }

  const [items, total] = await Promise.all([
    prisma.officialCoupon.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      skip: (page - 1) * pageSize,
      take: pageSize
    }),
    prisma.officialCoupon.count({ where })
  ])

  return {
    items: items.map(serializeOfficialCoupon),
    total,
    page,
    pageSize,
    totalPages: Math.max(1, Math.ceil(total / pageSize))
  }
}

/**
 * 序列化优惠券（金额与折扣率转为数字，时间转为 ISO 字符串）
 */
export function serializeOfficialCoupon(coupon: OfficialCoupon) {
  return {
    id: coupon.id,
    code: coupon.code,
    name: coupon.name,
    remark: coupon.remark,
    discountRate: Number(coupon.discountRate),
    scope: coupon.scope,
    reusable: coupon.reusable,
    maxUsesPerUser: coupon.maxUsesPerUser,
    totalUsageLimit: coupon.totalUsageLimit,
    usedCount: coupon.usedCount,
    enabled: coupon.enabled,
    startsAt: coupon.startsAt ? coupon.startsAt.toISOString() : null,
    expiresAt: coupon.expiresAt ? coupon.expiresAt.toISOString() : null,
    renewalMode: coupon.renewalMode,
    discountedChargeLimit: coupon.discountedChargeLimit,
    createdById: coupon.createdById,
    createdAt: coupon.createdAt.toISOString(),
    updatedAt: coupon.updatedAt.toISOString()
  }
}

export async function getOfficialCouponById(id: number) {
  return prisma.officialCoupon.findUnique({ where: { id } })
}

/**
 * 创建官方优惠券
 *
 * @throws Error `COUPON_CODE_EXISTS` 代码已存在
 */
export async function createOfficialCoupon(data: {
  code?: string
  name: string
  remark?: string | null
  discountRate: number
  scope: OfficialCouponScope
  reusable: boolean
  maxUsesPerUser?: number | null
  totalUsageLimit?: number | null
  enabled: boolean
  startsAt?: Date | null
  expiresAt?: Date | null
  renewalMode?: OfficialCouponRenewalMode
  discountedChargeLimit?: number | null
  createdById: number
}) {
  const code = normalizeOfficialCouponCode(data.code && data.code.trim() ? data.code : generateOfficialCouponCode())

  const existing = await prisma.officialCoupon.findUnique({ where: { code }, select: { id: true } })
  if (existing) {
    throw new Error(`${ErrorCode.COUPON_CODE_EXISTS}: ${code}`)
  }

  const renewalMode = data.renewalMode ?? 'purchase_only'

  const coupon = await prisma.officialCoupon.create({
    data: {
      code,
      name: data.name,
      remark: data.remark ?? null,
      discountRate: new Prisma.Decimal(data.discountRate),
      scope: data.scope,
      reusable: data.reusable,
      // 不可重复使用时该字段无意义，统一留空避免误读
      maxUsesPerUser: data.reusable ? data.maxUsesPerUser ?? null : null,
      totalUsageLimit: data.totalUsageLimit ?? null,
      enabled: data.enabled,
      startsAt: data.startsAt ?? null,
      expiresAt: data.expiresAt ?? null,
      renewalMode,
      // 仅 limited 模式使用该字段，其余模式统一留空避免误读
      discountedChargeLimit: renewalMode === 'limited' ? data.discountedChargeLimit ?? null : null,
      createdById: data.createdById
    }
  })

  return serializeOfficialCoupon(coupon)
}

/**
 * 更新官方优惠券
 *
 * @throws Error `COUPON_CODE_EXISTS` 代码已存在
 */
export async function updateOfficialCoupon(
  id: number,
  data: {
    code?: string
    name?: string
    remark?: string | null
    discountRate?: number
    scope?: OfficialCouponScope
    reusable?: boolean
    maxUsesPerUser?: number | null
    totalUsageLimit?: number | null
    enabled?: boolean
    startsAt?: Date | null
    expiresAt?: Date | null
    renewalMode?: OfficialCouponRenewalMode
    discountedChargeLimit?: number | null
  }
) {
  const current = await prisma.officialCoupon.findUnique({ where: { id } })
  if (!current) return null

  const updateData: Prisma.OfficialCouponUpdateInput = {}

  if (data.code !== undefined) {
    const code = normalizeOfficialCouponCode(data.code)
    if (!code) {
      throw new Error(`${ErrorCode.COUPON_NOT_FOUND}: Coupon code is required`)
    }
    if (code !== current.code) {
      const existing = await prisma.officialCoupon.findUnique({ where: { code }, select: { id: true } })
      if (existing) {
        throw new Error(`${ErrorCode.COUPON_CODE_EXISTS}: ${code}`)
      }
    }
    updateData.code = code
  }

  if (data.name !== undefined) updateData.name = data.name
  if (data.remark !== undefined) updateData.remark = data.remark
  if (data.discountRate !== undefined) updateData.discountRate = new Prisma.Decimal(data.discountRate)
  if (data.scope !== undefined) updateData.scope = data.scope
  if (data.totalUsageLimit !== undefined) updateData.totalUsageLimit = data.totalUsageLimit
  if (data.enabled !== undefined) updateData.enabled = data.enabled
  if (data.startsAt !== undefined) updateData.startsAt = data.startsAt
  if (data.expiresAt !== undefined) updateData.expiresAt = data.expiresAt

  const nextReusable = data.reusable !== undefined ? data.reusable : current.reusable
  if (data.reusable !== undefined) updateData.reusable = data.reusable
  // 不可重复使用时清除每用户次数上限
  if (!nextReusable) {
    updateData.maxUsesPerUser = null
  } else if (data.maxUsesPerUser !== undefined) {
    updateData.maxUsesPerUser = data.maxUsesPerUser
  }

  const nextRenewalMode = data.renewalMode !== undefined ? data.renewalMode : current.renewalMode
  if (data.renewalMode !== undefined) updateData.renewalMode = data.renewalMode
  // 仅 limited 模式使用折价次数上限，其余模式统一留空避免误读
  if (nextRenewalMode !== 'limited') {
    updateData.discountedChargeLimit = null
  } else if (data.discountedChargeLimit !== undefined) {
    updateData.discountedChargeLimit = data.discountedChargeLimit
  }

  const coupon = await prisma.officialCoupon.update({ where: { id }, data: updateData })
  return serializeOfficialCoupon(coupon)
}

/**
 * 删除官方优惠券
 *
 * 已产生使用记录的优惠券禁止删除，避免破坏财务与审计数据。
 *
 * @returns 'not_found' | 'in_use' | 'deleted'
 */
export async function deleteOfficialCoupon(id: number): Promise<'not_found' | 'in_use' | 'deleted'> {
  return prisma.$transaction(async (tx) => {
    const coupon = await tx.officialCoupon.findUnique({ where: { id }, select: { id: true, usedCount: true } })
    if (!coupon) return 'not_found'

    const usageCount = await tx.officialCouponUsage.count({ where: { couponId: id } })
    if (coupon.usedCount > 0 || usageCount > 0) {
      return 'in_use'
    }

    await tx.officialCoupon.delete({ where: { id } })
    return 'deleted'
  })
}

/**
 * 管理端：优惠券使用记录
 */
export async function listOfficialCouponUsages(couponId: number, page = 1, pageSize = 20) {
  const safePage = Math.max(1, page)
  const safePageSize = Math.min(100, Math.max(1, pageSize))

  const [items, total] = await Promise.all([
    prisma.officialCouponUsage.findMany({
      where: { couponId },
      orderBy: { createdAt: 'desc' },
      skip: (safePage - 1) * safePageSize,
      take: safePageSize,
      include: {
        user: { select: { id: true, username: true, email: true } },
        instance: {
          select: {
            id: true,
            name: true,
            status: true,
            package: { select: { id: true, name: true } }
          }
        }
      }
    }),
    prisma.officialCouponUsage.count({ where: { couponId } })
  ])

  return {
    items: items.map(usage => ({
      id: usage.id,
      couponId: usage.couponId,
      userId: usage.userId,
      username: usage.user?.username || null,
      userEmail: usage.user?.email || null,
      instanceId: usage.instanceId,
      instanceName: usage.instance?.name || null,
      instanceStatus: usage.instance?.status || null,
      packageName: usage.instance?.package?.name || null,
      originalPrice: Number(usage.originalPrice),
      discountAmount: Number(usage.discountAmount),
      createdAt: usage.createdAt.toISOString()
    })),
    total,
    page: safePage,
    pageSize: safePageSize,
    totalPages: Math.max(1, Math.ceil(total / safePageSize))
  }
}
