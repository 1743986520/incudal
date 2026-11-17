/**
 * 敏感操作邮件确认链接
 *
 * 流程：用户在面板发起敏感操作（禁用 2FA、修改密码、重装实例等）→
 * 生成一次性确认 token 并邮件发送链接（1 小时有效）→ 用户点击链接后
 * 由 /api/verification/confirm 校验 token 并执行对应操作。
 * 不需要确认的邮件直接忽略即可，不再使用验证码。
 */

import { prisma } from '../db/prisma.js'
import { OperationType } from '@prisma/client'
import crypto from 'crypto'
import { getSystemConfig } from '../db/system-config.js'
import { sendOperationConfirmEmail } from './mailer.js'

// 链接有效期（小时）
export const CONFIRM_EXPIRES_IN_HOURS = 1
// 同类型确认链接重发冷却（分钟），省邮件
const RESEND_COOLDOWN_MS = 2 * 60 * 1000

// 操作类型显示名称
const OPERATION_NAMES: Record<OperationType, { zh: string; en: string }> = {
    change_password: { zh: '修改密码', en: 'Change Password' },
    disable_2fa: { zh: '禁用双因素认证', en: 'Disable 2FA' },
    api_key: { zh: '创建 API Key', en: 'Create API Key' },
    change_email: { zh: '修改邮箱地址', en: 'Change Email' },
    delete_account: { zh: '删除账户', en: 'Delete Account' },
    delete_instance: { zh: '删除实例', en: 'Delete Instance' },
    reinstall_instance: { zh: '重装实例', en: 'Reinstall Instance' },
    recreate_instance: { zh: '重建实例', en: 'Recreate Instance' },
    transfer_instance: { zh: '转移实例', en: 'Transfer Instance' },
    delete_snapshot: { zh: '删除快照', en: 'Delete Snapshot' },
    delete_backup: { zh: '删除备份', en: 'Delete Backup' }
}

export function getOperationDisplayName(operationType: OperationType, lang: 'zh' | 'en' = 'zh'): string {
    return OPERATION_NAMES[operationType]?.[lang] ?? operationType
}

function hashToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex')
}

/**
 * 解析确认链接的站点根地址：SITE_URL 环境变量优先，其次后台 SEO 站点配置。
 */
export async function resolveConfirmBaseUrl(): Promise<string> {
    const envUrl = process.env.SITE_URL?.trim()
    if (envUrl) return envUrl.replace(/\/+$/, '')
    try {
        const configured = (await getSystemConfig('seo_site_url', false))?.trim()
        if (configured) return configured.replace(/\/+$/, '')
    } catch { /* 配置读取失败时退回默认值 */ }
    return 'https://di0.uk'
}

export interface RequestConfirmParams {
    userId: number
    operationType: OperationType
    resourceId?: number
    /** 确认链接被点击后执行操作所需的参数（如新密码哈希、重装镜像） */
    payload?: Record<string, unknown>
}

export interface RequestConfirmResult {
    success: boolean
    expiresInMinutes?: number
    error?: string
    errorCode?: string
}

/**
 * 为敏感操作生成确认链接并邮件发送。
 */
export async function requestOperationConfirm(params: RequestConfirmParams): Promise<RequestConfirmResult> {
    const user = await prisma.user.findUnique({
        where: { id: params.userId },
        select: { id: true, email: true, username: true }
    })

    if (!user) {
        return { success: false, error: 'User not found', errorCode: 'USER_NOT_FOUND' }
    }

    if (!user.email) {
        return { success: false, error: 'Email not configured', errorCode: 'EMAIL_NOT_CONFIGURED' }
    }

    // 清理过期记录
    await prisma.operationConfirm.deleteMany({
        where: { userId: params.userId, expiresAt: { lt: new Date() } }
    })

    // 重发冷却：同类型+同资源的未消费确认在冷却期内不重复发邮件
    const existing = await prisma.operationConfirm.findFirst({
        where: {
            userId: params.userId,
            operationType: params.operationType,
            resourceId: params.resourceId ?? null,
            consumedAt: null,
            expiresAt: { gt: new Date() }
        },
        orderBy: { createdAt: 'desc' }
    })

    if (existing && existing.createdAt.getTime() > Date.now() - RESEND_COOLDOWN_MS) {
        return {
            success: true,
            expiresInMinutes: CONFIRM_EXPIRES_IN_HOURS * 60,
            error: 'Confirmation email already sent, please wait'
        }
    }

    // 丢弃旧的未消费链接，只保留最新一封
    if (existing) {
        await prisma.operationConfirm.delete({ where: { id: existing.id } })
    }

    const token = crypto.randomBytes(32).toString('hex')
    const expiresAt = new Date(Date.now() + CONFIRM_EXPIRES_IN_HOURS * 60 * 60 * 1000)

    await prisma.operationConfirm.create({
        data: {
            userId: params.userId,
            operationType: params.operationType,
            resourceId: params.resourceId ?? null,
            tokenHash: hashToken(token),
            payload: (params.payload ?? undefined) as never,
            expiresAt
        }
    })

    const baseUrl = await resolveConfirmBaseUrl()
    const confirmUrl = `${baseUrl}/confirm-operation?token=${token}`
    const operationName = getOperationDisplayName(params.operationType, 'zh')

    const result = await sendOperationConfirmEmail(user.email, {
        username: user.username,
        operationName,
        confirmUrl,
        expiresInMinutes: CONFIRM_EXPIRES_IN_HOURS * 60
    })

    if (!result.success) {
        // 邮件发送失败时删除记录，允许用户立即重试
        await prisma.operationConfirm.deleteMany({
            where: { userId: params.userId, operationType: params.operationType, consumedAt: null }
        })
        return { success: false, error: result.error, errorCode: 'SEND_FAILED' }
    }

    return { success: true, expiresInMinutes: CONFIRM_EXPIRES_IN_HOURS * 60 }
}

export interface ConsumedConfirm {
    userId: number
    operationType: OperationType
    resourceId: number | null
    payload: Record<string, unknown>
}

/**
 * 清理已过期/已消费的确认记录（由定时任务周期调用）
 */
export async function cleanupExpiredOperationConfirms(): Promise<number> {
    const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000)
    const expired = await prisma.operationConfirm.deleteMany({
        where: { expiresAt: { lt: new Date() } }
    })
    const staleConsumed = await prisma.operationConfirm.deleteMany({
        where: { consumedAt: { lt: new Date(cutoff) } }
    })
    return expired.count + staleConsumed.count
}

/**
 * 原子消费确认链接：单次有效，过期即失效。
 */
export async function consumeOperationConfirm(token: string): Promise<ConsumedConfirm | null> {
    if (!token || typeof token !== 'string' || token.length > 128) {
        return null
    }

    const tokenHash = hashToken(token)
    const now = new Date()

    return prisma.$transaction(async (tx) => {
        const record = await tx.operationConfirm.findUnique({
            where: { tokenHash },
            select: { id: true, userId: true, operationType: true, resourceId: true, payload: true, expiresAt: true, consumedAt: true }
        })

        if (!record || record.consumedAt || record.expiresAt <= now) {
            return null
        }

        const updated = await tx.operationConfirm.updateMany({
            where: { id: record.id, consumedAt: null },
            data: { consumedAt: now }
        })

        if (updated.count !== 1) {
            return null
        }

        return {
            userId: record.userId,
            operationType: record.operationType,
            resourceId: record.resourceId,
            payload: (record.payload ?? {}) as Record<string, unknown>
        }
    })
}
