/**
 * 流量统计 API 路由
 */

import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify'
import * as trafficDb from '../db/traffic.js'
import * as db from '../db/index.js'
import { prisma } from '../db/prisma.js'
import { createLog } from '../db/logs.js'
import { formatBytes } from '../services/traffic-notifier.js'
import {
    calculateInstanceTrafficStatus,
    calculateUserTrafficStatus,
    formatLocalDate,
    getTrafficPeriod
} from '../services/traffic-utils.js'
import { apiError, ErrorCode } from '../lib/errors.js'

/**
 * BigInt 序列化为字符串
 */
function serializeBigInt(value: bigint | null): string | null {
    return value === null ? null : value.toString()
}

/**
 * 计算百分比
 * 注意: 先转换为 Number 再计算,避免 BigInt 整数除法精度丢失
 * 例如: 160MB / 257GB 用 BigInt 整数除法会得到 0,而非 0.061%
 */
function calculatePercentage(used: bigint, limit: bigint | null): number {
    if (limit === null || limit === 0n) return 0
    // 先转换为浮点数再计算百分比,避免整数除法导致的精度丢失
    const percentage = (Number(used) / Number(limit)) * 100
    return Math.min(100, percentage)
}

function formatCurrency(amount: number): string {
    return `¥${amount.toFixed(2)}`
}

function getTrafficResetInfo(
    instance: {
        packagePlanId: number | null
        monthlyTrafficUsed: bigint
        trafficBillingMode?: 'package' | 'usage'
        packagePlan: { trafficResetEnabled: boolean; trafficResetPrice: unknown } | null
    } | null,
    options: { freeResetAllowed?: boolean } = {}
) {
    const plan = instance?.packagePlan
    const priceCents = plan ? Number(plan.trafficResetPrice) || 0 : 0

    if (instance?.trafficBillingMode === 'usage') {
        return {
            resetAllowed: false,
            resetPrice: 0,
            resetPriceFormatted: null,
            resetDisabledReason: 'USAGE_BILLING'
        }
    }

    if (options.freeResetAllowed) {
        return {
            resetAllowed: true,
            resetPrice: 0,
            resetPriceFormatted: formatCurrency(0),
            resetDisabledReason: instance && instance.monthlyTrafficUsed > 0n ? null : 'NO_USAGE'
        }
    }

    if (!plan || !instance?.packagePlanId) {
        return {
            resetAllowed: false,
            resetPrice: 0,
            resetPriceFormatted: null,
            resetDisabledReason: 'NO_PAID_PLAN'
        }
    }

    if (!plan.trafficResetEnabled) {
        return {
            resetAllowed: false,
            resetPrice: 0,
            resetPriceFormatted: null,
            resetDisabledReason: 'PLAN_DISABLED'
        }
    }

    return {
        resetAllowed: true,
        resetPrice: priceCents,
        resetPriceFormatted: formatCurrency(priceCents / 100),
        resetDisabledReason: instance.monthlyTrafficUsed > 0n ? null : 'NO_USAGE'
    }
}

export default async function trafficRoutes(fastify: FastifyInstance): Promise<void> {
    // ==================== 用户流量 API ====================

    /**
     * 获取当前用户的流量统计
     */
    fastify.get('/me/traffic', {
        onRequest: [fastify.authenticateUser]
    }, async (request: FastifyRequest, reply: FastifyReply) => {
        const userId = request.user.id

        const quota = await trafficDb.getUserTrafficQuota(userId)
        if (!quota) {
            return reply.code(404).send({ error: 'User quota not found' })
        }

        const effectiveLimit = quota.monthlyTrafficLimit !== null
            ? quota.monthlyTrafficLimit + quota.extraTrafficQuota
            : null

        return {
            monthlyUsed: serializeBigInt(quota.monthlyTrafficUsed),
            monthlyUsedFormatted: formatBytes(quota.monthlyTrafficUsed),
            monthlyLimit: serializeBigInt(effectiveLimit),
            monthlyLimitFormatted: effectiveLimit ? formatBytes(effectiveLimit) : null,
            extraQuota: serializeBigInt(quota.extraTrafficQuota),
            trafficStatus: quota.trafficStatus,
            percentage: calculatePercentage(quota.monthlyTrafficUsed, effectiveLimit)
        }
    })

    /**
     * 获取指定用户的流量统计（管理员）
     */
    fastify.get<{ Params: { userId: string } }>('/users/:userId/traffic', {
        onRequest: [fastify.authenticateAdmin]
    }, async (request: FastifyRequest<{ Params: { userId: string } }>, reply: FastifyReply) => {
        const userId = parseInt(request.params.userId, 10)
        if (isNaN(userId)) {
            return reply.code(400).send({ error: 'Invalid user ID' })
        }

        const quota = await trafficDb.getUserTrafficQuota(userId)
        if (!quota) {
            return reply.code(404).send({ error: 'User quota not found' })
        }

        const effectiveLimit = quota.monthlyTrafficLimit !== null
            ? quota.monthlyTrafficLimit + quota.extraTrafficQuota
            : null

        return {
            monthlyUsed: serializeBigInt(quota.monthlyTrafficUsed),
            monthlyUsedFormatted: formatBytes(quota.monthlyTrafficUsed),
            monthlyLimit: serializeBigInt(effectiveLimit),
            monthlyLimitFormatted: effectiveLimit ? formatBytes(effectiveLimit) : null,
            extraQuota: serializeBigInt(quota.extraTrafficQuota),
            trafficStatus: quota.trafficStatus,
            percentage: calculatePercentage(quota.monthlyTrafficUsed, effectiveLimit)
        }
    })

    /**
     * 更新用户流量限额（管理员）
     */
    fastify.put<{
        Params: { userId: string }
        Body: { monthlyLimit: string | null }
    }>('/users/:userId/traffic/limit', {
        onRequest: [fastify.authenticateAdmin]
    }, async (request: FastifyRequest<{
        Params: { userId: string }
        Body: { monthlyLimit: string | null }
    }>, reply: FastifyReply) => {
        const userId = parseInt(request.params.userId, 10)
        if (isNaN(userId)) {
            return reply.code(400).send({ error: 'Invalid user ID' })
        }

        const { monthlyLimit } = request.body
        const limit = monthlyLimit ? BigInt(monthlyLimit) : null

        await trafficDb.updateUserTrafficLimit(userId, limit)
        const quota = await trafficDb.getUserTrafficQuota(userId)
        if (quota) {
            const effectiveLimit = quota.monthlyTrafficLimit !== null
                ? quota.monthlyTrafficLimit + quota.extraTrafficQuota
                : null
            const status = calculateUserTrafficStatus(quota.monthlyTrafficUsed, effectiveLimit)
            await trafficDb.updateUserTrafficStatus(userId, status)
        }
        const { reconcileTrafficStateForUser } = await import('../services/traffic-scheduler.js')
        await reconcileTrafficStateForUser(userId)

        return { success: true }
    })

    // ==================== 实例流量 API ====================

    /**
     * 获取实例的流量统计
     */
    fastify.get<{ Params: { instanceId: string } }>('/instances/:instanceId/traffic', {
        onRequest: [fastify.authenticate]
    }, async (request: FastifyRequest<{ Params: { instanceId: string } }>, reply: FastifyReply) => {
        const instanceId = parseInt(request.params.instanceId, 10)
        if (isNaN(instanceId)) {
            return reply.code(400).send({ error: 'Invalid instance ID' })
        }

        const instance = await trafficDb.getInstanceTrafficInfo(instanceId)
        if (!instance) {
            return reply.code(404).send({ error: 'Instance not found' })
        }

        // 权限检查：管理员、实例所有者或宿主机所有者可以查看
        let host: Awaited<ReturnType<typeof db.getHostById>> = null
        // 1. 管理员有权限
        if (request.user.role === 'admin') {
            // 继续执行，稍后获取host信息
        } else if (instance.userId === request.user.id) {
            // 2. 实例所有者有权限
        } else {
            // 3. 检查是否是宿主机所有者
            if (instance.hostId) {
                host = await db.getHostById(instance.hostId)
                if (!host || host.user_id !== request.user.id) {
                    return reply.code(403).send({ error: 'Access denied' })
                }
            } else {
                return reply.code(403).send({ error: 'Access denied' })
            }
        }

        // 获取节点的流量重置日配置，用于计算周期
        if (!host && instance.hostId) {
            host = await db.getHostById(instance.hostId)
        }
        const trafficResetDay = host?.traffic_reset_day ?? 1
        const { periodStart, periodEnd } = getTrafficPeriod(trafficResetDay)
        const resetInfo = getTrafficResetInfo(instance, {
            freeResetAllowed: request.user.role === 'admin' || (!!host && host.user_id === request.user.id)
        })

        return {
            monthlyUsed: serializeBigInt(instance.monthlyTrafficUsed),
            monthlyUsedFormatted: formatBytes(instance.monthlyTrafficUsed),
            monthlyLimit: serializeBigInt(instance.monthlyTrafficLimit),
            monthlyLimitFormatted: instance.trafficBillingMode === 'usage'
                ? formatBytes(instance.monthlyTrafficLimit ?? 0n)
                : (instance.monthlyTrafficLimit ? formatBytes(instance.monthlyTrafficLimit) : null),
            trafficStatus: instance.trafficStatus,
            percentage: calculatePercentage(instance.monthlyTrafficUsed, instance.monthlyTrafficLimit),
            trafficResetDay,
            periodStart: formatLocalDate(periodStart),
            periodEnd: formatLocalDate(periodEnd),
            trafficBillingMode: instance.trafficBillingMode,
            trafficUnitPrice: Number(instance.trafficUnitPrice),
            includedTraffic: serializeBigInt(instance.monthlyTrafficLimit),
            overageTraffic: serializeBigInt(instance.monthlyTrafficUsed > (instance.monthlyTrafficLimit ?? 0n)
                ? instance.monthlyTrafficUsed - (instance.monthlyTrafficLimit ?? 0n)
                : 0n),
            settledTraffic: serializeBigInt(instance.trafficSettledBytes),
            settledTrafficCost: Number(instance.trafficSettledCost),
            pendingTraffic: serializeBigInt((instance.monthlyTrafficUsed > (instance.monthlyTrafficLimit ?? 0n)
                ? instance.monthlyTrafficUsed - (instance.monthlyTrafficLimit ?? 0n)
                : 0n) > instance.trafficSettledBytes
                ? (instance.monthlyTrafficUsed - (instance.monthlyTrafficLimit ?? 0n)) - instance.trafficSettledBytes
                : 0n),
            nextTrafficBillingAt: instance.nextTrafficBillingAt?.toISOString() ?? null,
            ...resetInfo
        }
    })

    /**
     * 获取实例的流量历史（按周期）
     */
    fastify.get<{
        Params: { instanceId: string }
        Querystring: { days?: string }
    }>('/instances/:instanceId/traffic/history', {
        onRequest: [fastify.authenticate]
    }, async (request: FastifyRequest<{
        Params: { instanceId: string }
        Querystring: { days?: string }
    }>, reply: FastifyReply) => {
        const instanceId = parseInt(request.params.instanceId, 10)
        if (isNaN(instanceId)) {
            return reply.code(400).send({ error: 'Invalid instance ID' })
        }

        const instance = await trafficDb.getInstanceTrafficInfo(instanceId)
        if (!instance) {
            return reply.code(404).send({ error: 'Instance not found' })
        }

        // 权限检查：管理员、实例所有者或宿主机所有者可以查看
        let host: Awaited<ReturnType<typeof db.getHostById>> = null
        // 1. 管理员有权限
        if (request.user.role === 'admin') {
            // 继续执行
        } else if (instance.userId === request.user.id) {
            // 2. 实例所有者有权限
        } else {
            // 3. 检查是否是宿主机所有者
            if (instance.hostId) {
                host = await db.getHostById(instance.hostId)
                if (!host || host.user_id !== request.user.id) {
                    return reply.code(403).send({ error: 'Access denied' })
                }
            } else {
                return reply.code(403).send({ error: 'Access denied' })
            }
        }

        // 获取节点的流量重置日配置，用于计算周期
        if (!host && instance.hostId) {
            host = await db.getHostById(instance.hostId)
        }
        const trafficResetDay = host?.traffic_reset_day ?? 1
        const { periodStart, periodEnd } = getTrafficPeriod(trafficResetDay)

        // 按周期获取历史数据
        const history = await trafficDb.getDailyTrafficByPeriod(instanceId, periodStart)

        return {
            trafficResetDay,
            periodStart: formatLocalDate(periodStart),
            periodEnd: formatLocalDate(periodEnd),
            data: history.map(record => ({
                date: formatLocalDate(record.date),
                rxTotal: serializeBigInt(record.rxTotal),
                txTotal: serializeBigInt(record.txTotal),
                rxFormatted: formatBytes(record.rxTotal),
                txFormatted: formatBytes(record.txTotal),
                total: serializeBigInt(record.rxTotal + record.txTotal),
                totalFormatted: formatBytes(record.rxTotal + record.txTotal)
            }))
        }
    })

    /**
     * 更新实例流量限额（管理员）
     */
    fastify.put<{
        Params: { instanceId: string }
        Body: { monthlyLimit: string | null }
    }>('/instances/:instanceId/traffic/limit', {
        onRequest: [fastify.authenticateAdmin]
    }, async (request: FastifyRequest<{
        Params: { instanceId: string }
        Body: { monthlyLimit: string | null }
    }>, reply: FastifyReply) => {
        const instanceId = parseInt(request.params.instanceId, 10)
        if (isNaN(instanceId)) {
            return reply.code(400).send({ error: 'Invalid instance ID' })
        }

        const { monthlyLimit } = request.body
        const limit = monthlyLimit ? BigInt(monthlyLimit) : null

        await trafficDb.updateInstanceTrafficLimit(instanceId, limit)
        const instance = await trafficDb.getInstanceTrafficInfo(instanceId)
        if (instance) {
            const status = calculateInstanceTrafficStatus(instance.monthlyTrafficUsed, instance.monthlyTrafficLimit)
            await trafficDb.updateInstanceTrafficStatus(instanceId, status)
        }
        const { reconcileTrafficStateForInstanceIds } = await import('../services/traffic-scheduler.js')
        await reconcileTrafficStateForInstanceIds([instanceId])

        return { success: true }
    })

    /**
     * 重置实例月度流量
     * 管理员或宿主机所有者免费重置，实例所有者按套餐配置付费重置。
     */
    fastify.post<{
        Params: { instanceId: string }
    }>('/instances/:instanceId/traffic/reset', {
        onRequest: [fastify.authenticate],
        config: { rateLimit: { max: 5, timeWindow: '1 minute' } }
    }, async (request: FastifyRequest<{
        Params: { instanceId: string }
    }>, reply: FastifyReply) => {
        const instanceId = parseInt(request.params.instanceId, 10)
        if (isNaN(instanceId)) {
            return reply.code(400).send({ error: 'Invalid instance ID' })
        }

        const instance = await trafficDb.getInstanceTrafficInfo(instanceId)
        if (!instance) {
            return reply.code(404).send({ error: 'Instance not found' })
        }

        const isAdmin = request.user.role === 'admin'
        let host: Awaited<ReturnType<typeof db.getHostById>> = null
        const isInstanceOwner = instance.userId === request.user.id
        let isHostOwner = false

        if (instance.hostId) {
            host = await db.getHostById(instance.hostId)
            isHostOwner = !!host && host.user_id === request.user.id
        }

        if (!isAdmin && !isHostOwner && !isInstanceOwner) {
            return reply.code(403).send(apiError(ErrorCode.FORBIDDEN))
        }

        // Usage-billed traffic is monetary consumption, not a resettable quota.
        if (instance.trafficBillingMode === 'usage') {
            return reply.code(400).send(apiError(ErrorCode.TRAFFIC_RESET_NOT_ALLOWED))
        }

        if (isAdmin || isHostOwner) {
            const resetResult = await trafficDb.resetInstanceMonthlyTraffic(instanceId)
            if (resetResult.count !== 1) {
                return reply.code(400).send(apiError(ErrorCode.TRAFFIC_RESET_NOT_ALLOWED))
            }
            try {
                const { reconcileTrafficStateForInstanceIds } = await import('../services/traffic-scheduler.js')
                await reconcileTrafficStateForInstanceIds([instanceId])
            } catch (error) {
                request.log.warn(error, 'Traffic reset completed, but immediate traffic state reconciliation failed')
            }

            try {
                await createLog(
                    request.user.id,
                    'instance',
                    'traffic.reset',
                    `Reset instance "${instance.name}" traffic without charge`,
                    'success'
                )
            } catch (error) {
                request.log.warn(error, 'Traffic reset completed, but audit log creation failed')
            }

            const updatedInstance = await trafficDb.getInstanceTrafficInfo(instanceId)
            return {
                success: true,
                message: 'Instance traffic reset completed',
                chargedAmount: 0,
                balanceAfter: null,
                traffic: updatedInstance
                    ? {
                        monthlyUsed: serializeBigInt(updatedInstance.monthlyTrafficUsed),
                        monthlyUsedFormatted: formatBytes(updatedInstance.monthlyTrafficUsed),
                        trafficStatus: updatedInstance.trafficStatus,
                        percentage: calculatePercentage(updatedInstance.monthlyTrafficUsed, updatedInstance.monthlyTrafficLimit),
                        ...getTrafficResetInfo(updatedInstance, { freeResetAllowed: true })
                    }
                    : null
            }
        }

        try {
            const result = await prisma.$transaction(async (tx) => {
                const freshInstance = await tx.instance.findUnique({
                    where: { id: instanceId },
                    select: {
                        id: true,
                        name: true,
                        userId: true,
                        packagePlanId: true,
                        monthlyTrafficLimit: true,
                        monthlyTrafficUsed: true,
                        trafficBillingMode: true,
                        trafficStatus: true,
                        status: true,
                        packagePlan: {
                            select: {
                                id: true,
                                trafficResetEnabled: true,
                                trafficResetPrice: true
                            }
                        }
                    }
                })

                if (!freshInstance) {
                    throw new Error('INSTANCE_NOT_FOUND')
                }
                if (freshInstance.userId !== request.user.id) {
                    throw new Error('FORBIDDEN')
                }
                if (freshInstance.status === 'deleted') {
                    throw new Error('INSTANCE_NOT_FOUND')
                }
                if (freshInstance.trafficBillingMode === 'usage') {
                    throw new Error('TRAFFIC_RESET_NOT_ALLOWED')
                }
                if (!freshInstance.packagePlanId || !freshInstance.packagePlan?.trafficResetEnabled) {
                    throw new Error('TRAFFIC_RESET_NOT_ALLOWED')
                }
                if (freshInstance.monthlyTrafficUsed <= 0n) {
                    throw new Error('TRAFFIC_RESET_NOT_NEEDED')
                }

                const priceCents = Number(freshInstance.packagePlan.trafficResetPrice) || 0
                const chargeAmount = Math.round(Math.max(0, priceCents)) / 100
                let balanceAfter: number | null = null

                const resetResult = await tx.instance.updateMany({
                    where: {
                        id: instanceId,
                        userId: request.user.id,
                        status: { not: 'deleted' },
                        trafficBillingMode: { not: 'usage' },
                        monthlyTrafficUsed: { gt: 0n }
                    },
                    data: {
                        monthlyTrafficUsed: 0n,
                        trafficStatus: 'NORMAL',
                        trafficSettledBytes: 0n,
                        trafficSettledCost: 0,
                        version: { increment: 1 }
                    }
                })

                if (resetResult.count !== 1) {
                    throw new Error('TRAFFIC_RESET_NOT_NEEDED')
                }

                if (chargeAmount > 0) {
                    const balanceUpdate = await tx.user.updateMany({
                        where: {
                            id: request.user.id,
                            balance: { gte: chargeAmount }
                        },
                        data: {
                            balance: { decrement: chargeAmount }
                        }
                    })

                    if (balanceUpdate.count !== 1) {
                        throw new Error('BALANCE_INSUFFICIENT')
                    }

                    const updatedUser = await tx.user.findUnique({
                        where: { id: request.user.id },
                        select: { balance: true }
                    })
                    if (!updatedUser) {
                        throw new Error('USER_NOT_FOUND')
                    }

                    balanceAfter = Number(updatedUser.balance)
                    const balanceBefore = Number((balanceAfter + chargeAmount).toFixed(2))

                    await tx.balanceLog.create({
                        data: {
                            userId: request.user.id,
                            type: 'consume',
                            amount: -chargeAmount,
                            balanceBefore,
                            balanceAfter,
                            instanceId,
                            remark: `重置实例 ${freshInstance.name} 本周期流量`
                        }
                    })
                } else {
                    const userBalance = await tx.user.findUnique({
                        where: { id: request.user.id },
                        select: { balance: true }
                    })
                    balanceAfter = userBalance ? Number(userBalance.balance) : null
                }

                const updatedInstance = await tx.instance.findUnique({
                    where: { id: instanceId },
                    select: {
                        id: true,
                        name: true,
                        packagePlanId: true,
                        monthlyTrafficLimit: true,
                        monthlyTrafficUsed: true,
                        trafficStatus: true,
                        packagePlan: {
                            select: {
                                id: true,
                                trafficResetEnabled: true,
                                trafficResetPrice: true
                            }
                        }
                    }
                })
                if (!updatedInstance) {
                    throw new Error('INSTANCE_NOT_FOUND')
                }

                return { updatedInstance, chargeAmount, balanceAfter }
            })

            try {
                const { reconcileTrafficStateForInstanceIds } = await import('../services/traffic-scheduler.js')
                await reconcileTrafficStateForInstanceIds([instanceId])
            } catch (error) {
                request.log.warn(error, 'Paid traffic reset completed, but immediate traffic state reconciliation failed')
            }

            try {
                await createLog(
                    request.user.id,
                    'instance',
                    'traffic.reset',
                    `Reset instance "${instance.name}" traffic with charge ${formatCurrency(result.chargeAmount)}`,
                    'success'
                )
            } catch (error) {
                request.log.warn(error, 'Paid traffic reset completed, but audit log creation failed')
            }

            return {
                success: true,
                message: 'Instance traffic reset completed',
                chargedAmount: result.chargeAmount,
                balanceAfter: result.balanceAfter,
                traffic: {
                    monthlyUsed: serializeBigInt(result.updatedInstance.monthlyTrafficUsed),
                    monthlyUsedFormatted: formatBytes(result.updatedInstance.monthlyTrafficUsed),
                    trafficStatus: result.updatedInstance.trafficStatus,
                    percentage: calculatePercentage(result.updatedInstance.monthlyTrafficUsed, result.updatedInstance.monthlyTrafficLimit),
                    ...getTrafficResetInfo({
                        packagePlanId: result.updatedInstance.packagePlanId,
                        monthlyTrafficUsed: result.updatedInstance.monthlyTrafficUsed,
                        packagePlan: result.updatedInstance.packagePlan
                    })
                }
            }
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error)
            if (message === 'INSTANCE_NOT_FOUND') {
                return reply.code(404).send({ error: 'Instance not found' })
            }
            if (message === 'FORBIDDEN') {
                return reply.code(403).send(apiError(ErrorCode.FORBIDDEN))
            }
            if (message === 'TRAFFIC_RESET_NOT_ALLOWED') {
                return reply.code(400).send(apiError(ErrorCode.TRAFFIC_RESET_NOT_ALLOWED))
            }
            if (message === 'TRAFFIC_RESET_NOT_NEEDED') {
                return reply.code(400).send(apiError(ErrorCode.TRAFFIC_RESET_NOT_NEEDED))
            }
            if (message === 'BALANCE_INSUFFICIENT') {
                return reply.code(400).send(apiError(ErrorCode.BALANCE_INSUFFICIENT))
            }
            request.log.error(error, 'Failed to reset instance traffic')
            return reply.code(500).send(apiError(ErrorCode.INTERNAL_ERROR))
        }
    })

    // ==================== 管理员操作 ======================================

    /**
     * 获取节点的流量统计（按周期）
     * 聚合该节点下所有实例的流量
     * 管理员或节点所有者可访问
     */
    fastify.get<{
        Params: { hostId: string }
    }>('/hosts/:hostId/traffic/history', {
        onRequest: [fastify.authenticate]
    }, async (request: FastifyRequest<{
        Params: { hostId: string }
    }>, reply: FastifyReply) => {
        const { user } = request as any
        const hostId = parseInt(request.params.hostId, 10)
        if (isNaN(hostId)) {
            return reply.code(400).send({ error: 'Invalid host ID' })
        }

        // 验证节点是否存在
        const host = await db.getHostById(hostId)
        if (!host) {
            return reply.code(404).send({ error: 'Host not found' })
        }

        // 权限检查：管理员或节点所有者
        if (user.role !== 'admin' && host.user_id !== user.id) {
            return reply.code(403).send(apiError(ErrorCode.FORBIDDEN))
        }

        // 根据节点的流量重置日计算周期
        const trafficResetDay = host.traffic_reset_day ?? 1
        const { periodStart, periodEnd } = getTrafficPeriod(trafficResetDay)

        // 获取周期内每日流量历史
        const history = await trafficDb.getHostDailyTraffic(hostId, trafficResetDay)
        
        // 获取流量汇总（基于实例的 monthlyTrafficUsed/monthlyTrafficLimit）
        const summary = await trafficDb.getHostTrafficSummary(hostId)

        return {
            trafficResetDay,
            periodStart: formatLocalDate(periodStart),
            periodEnd: formatLocalDate(periodEnd),
            data: history.map(record => ({
                date: formatLocalDate(record.date),
                rxTotal: serializeBigInt(record.rxTotal),
                txTotal: serializeBigInt(record.txTotal),
                rxFormatted: formatBytes(record.rxTotal),
                txFormatted: formatBytes(record.txTotal),
                total: serializeBigInt(record.rxTotal + record.txTotal),
                totalFormatted: formatBytes(record.rxTotal + record.txTotal)
            })),
            summary: {
                totalUsed: serializeBigInt(summary.totalUsed),
                totalUsedFormatted: formatBytes(summary.totalUsed),
                totalLimit: serializeBigInt(summary.totalLimit),
                totalLimitFormatted: formatBytes(summary.totalLimit)
            }
        }
    })

    /**
     * 手动触发流量采集（管理员，用于测试）
     */
    fastify.post('/traffic/collect', {
        onRequest: [fastify.authenticateAdmin]
    }, async (_request: FastifyRequest, _reply: FastifyReply) => {
        const { runTrafficJob } = await import('../services/traffic-scheduler.js')

        // 异步执行，不等待完成
        runTrafficJob().catch(console.error)

        return { success: true, message: 'Traffic collection job started' }
    })

    /**
     * 同步套餐流量限额到所有实例（管理员）
     * 将所有实例的流量限额更新为其所属套餐的流量限额
     */
    fastify.post('/traffic/sync-package-limits', {
        onRequest: [fastify.authenticateAdmin]
    }, async (_request: FastifyRequest, _reply: FastifyReply) => {
        const result = await trafficDb.syncPackageTrafficLimitsToInstances()
        if (result.instanceIds.length > 0) {
            try {
                const { reconcileTrafficStateForInstanceIds } = await import('../services/traffic-scheduler.js')
                await reconcileTrafficStateForInstanceIds(result.instanceIds)
            } catch (err) {
                _request.log.warn(err, 'Package traffic limits synced, immediate traffic state reconciliation failed')
            }
        }

        return {
            success: true,
            message: 'Package traffic limits synced to instances',
            updatedCount: result.count
        }
    })
}
