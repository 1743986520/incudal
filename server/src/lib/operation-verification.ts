/**
 * 敏感操作二次验证服务
 * 
 * 账号相关操作：通过邮件验证
 * 资源相关操作：通过用户绑定的通知渠道验证
 */

import { prisma } from '../db/prisma.js'
import { Prisma, OperationType, VerificationChannel } from '@prisma/client'
import { sendOperationVerificationEmail } from './mailer.js'
import { sendVerificationNotification } from './notifier.js'
import crypto from 'crypto'

// 操作类型分类
const ACCOUNT_OPERATIONS: OperationType[] = [
    'change_password',
    'disable_2fa',
    'change_email',
    'delete_account'
]

const RESOURCE_OPERATIONS: OperationType[] = [
    'delete_instance',
    'reinstall_instance',
    'recreate_instance',
    'transfer_instance',
    'delete_snapshot',
    'delete_backup'
]

// 验证码配置
const VERIFICATION_CONFIG = {
    codeLength: 6,
    expiresInMinutes: 10,
    maxAttempts: 5
} as const

// 当前 schema 没有失败次数列。将次数编码在验证码记录自身中，避免进程重启或
// 多副本部署后重置计数；该内部后缀不会被发送给用户。
const FAILED_ATTEMPTS_SUFFIX = ':attempts:'

function decodeVerificationCode(storedCode: string): { code: string; attempts: number } {
    const suffixIndex = storedCode.lastIndexOf(FAILED_ATTEMPTS_SUFFIX)
    if (suffixIndex === -1) {
        return { code: storedCode, attempts: 0 }
    }

    const attempts = Number(storedCode.slice(suffixIndex + FAILED_ATTEMPTS_SUFFIX.length))
    if (!Number.isInteger(attempts) || attempts < 0 || attempts > VERIFICATION_CONFIG.maxAttempts) {
        return { code: storedCode, attempts: 0 }
    }

    return {
        code: storedCode.slice(0, suffixIndex),
        attempts
    }
}

function encodeVerificationCode(code: string, attempts: number): string {
    return `${code}${FAILED_ATTEMPTS_SUFFIX}${attempts}`
}

// 操作类型显示名称（用于通知）
const OPERATION_NAMES: Record<OperationType, { zh: string; en: string }> = {
    change_password: { zh: '修改密码', en: 'Change Password' },
    disable_2fa: { zh: '禁用双因素认证', en: 'Disable 2FA' },
    change_email: { zh: '修改邮箱地址', en: 'Change Email' },
    delete_account: { zh: '删除账户', en: 'Delete Account' },
    delete_instance: { zh: '删除实例', en: 'Delete Instance' },
    reinstall_instance: { zh: '重装实例', en: 'Reinstall Instance' },
    recreate_instance: { zh: '重建实例', en: 'Recreate Instance' },
    transfer_instance: { zh: '转移实例', en: 'Transfer Instance' },
    delete_snapshot: { zh: '删除快照', en: 'Delete Snapshot' },
    delete_backup: { zh: '删除备份', en: 'Delete Backup' }
}

/**
 * 生成6位随机验证码
 */
function generateVerificationCode(): string {
    return crypto.randomInt(100000, 1000000).toString()
}

/**
 * 判断操作类型是否为账号相关操作
 */
export function isAccountOperation(operationType: OperationType): boolean {
    return ACCOUNT_OPERATIONS.includes(operationType)
}

/**
 * 判断操作类型是否为资源相关操作
 */
export function isResourceOperation(operationType: OperationType): boolean {
    return RESOURCE_OPERATIONS.includes(operationType)
}

/**
 * 获取操作名称
 */
export function getOperationName(operationType: OperationType, lang: 'zh' | 'en' = 'zh'): string {
    return OPERATION_NAMES[operationType]?.[lang] || operationType
}

/**
 * 获取用户的首选通知渠道
 */
async function getUserNotificationChannel(userId: number): Promise<{
    channel: VerificationChannel | null
    channelId: number | null
    target: string | null
}> {
    // 查找用户启用的第一个通知渠道
    const notificationChannel = await prisma.notificationChannel.findFirst({
        where: {
            userId,
            enabled: true
        },
        orderBy: { createdAt: 'asc' }
    })

    if (!notificationChannel) {
        return { channel: null, channelId: null, target: null }
    }

    // 解析渠道配置获取目标标识（用于显示）
    let target = ''
    const config = typeof notificationChannel.config === 'string'
        ? JSON.parse(notificationChannel.config)
        : notificationChannel.config

    switch (notificationChannel.type) {
        case 'telegram':
            target = `Telegram (${(config as { chatId?: string }).chatId?.substring(0, 6)}***)`
            break
        case 'discord':
            target = 'Discord Webhook'
            break
        case 'webhook':
            target = 'Webhook'
            break
        default:
            target = notificationChannel.type
    }

    return {
        channel: notificationChannel.type as VerificationChannel,
        channelId: notificationChannel.id,
        target
    }
}

export interface RequestVerificationResult {
    success: boolean
    channel?: VerificationChannel
    maskedTarget?: string
    expiresIn?: number
    error?: string
    errorCode?: string
}

/**
 * 请求二次验证码
 */
export async function requestOperationVerification(
    userId: number,
    operationType: OperationType,
    resourceId?: number,
    resourceType?: string
): Promise<RequestVerificationResult> {
    // 1. 获取用户信息
    const user = await prisma.user.findUnique({
        where: { id: userId },
        select: { id: true, email: true, username: true }
    })

    if (!user) {
        return { success: false, error: 'User not found', errorCode: 'USER_NOT_FOUND' }
    }

    // 2. 确定验证渠道
    let channel: VerificationChannel
    let maskedTarget: string

    if (isAccountOperation(operationType)) {
        // 账号操作：强制使用邮件
        if (!user.email) {
            return { success: false, error: 'Email not configured', errorCode: 'EMAIL_NOT_CONFIGURED' }
        }
        channel = 'email'
        // 遮蔽邮箱
        const [localPart, domain] = user.email.split('@')
        maskedTarget = `${localPart.substring(0, 2)}***@${domain}`
    } else {
        // 资源操作：使用用户绑定的通知渠道
        const notifyChannel = await getUserNotificationChannel(userId)
        if (!notifyChannel.channel) {
            // 没有绑定通知渠道，不需要二次验证
            return { 
                success: false, 
                error: 'No notification channel configured', 
                errorCode: 'NO_NOTIFICATION_CHANNEL' 
            }
        }
        channel = notifyChannel.channel
        maskedTarget = notifyChannel.target || channel
    }

    // 3. 清理过期的验证码
    await prisma.operationVerification.deleteMany({
        where: {
            userId,
            expiresAt: { lt: new Date() }
        }
    })

    // 4. 检查是否有未过期的同类型验证码（防止频繁请求）
    const existingVerification = await prisma.operationVerification.findFirst({
        where: {
            userId,
            operationType,
            resourceId: resourceId || null,
            verified: false,
            expiresAt: { gt: new Date() }
        }
    })

    if (existingVerification) {
        // 如果验证码创建时间在2分钟内，拒绝重新发送
        const twoMinutesAgo = new Date(Date.now() - 2 * 60 * 1000)
        if (existingVerification.createdAt > twoMinutesAgo) {
            const remainingSeconds = Math.ceil((existingVerification.expiresAt.getTime() - Date.now()) / 1000)
            return {
                success: true,
                channel,
                maskedTarget,
                expiresIn: remainingSeconds,
                error: 'Verification code already sent, please wait'
            }
        }
        // 删除旧的验证码
        await prisma.operationVerification.delete({ where: { id: existingVerification.id } })
    }

    // 5. 生成新验证码
    const code = generateVerificationCode()
    const expiresAt = new Date(Date.now() + VERIFICATION_CONFIG.expiresInMinutes * 60 * 1000)

    // 6. 存储验证码
    await prisma.operationVerification.create({
        data: {
            userId,
            operationType,
            code,
            channel,
            resourceId: resourceId || null,
            resourceType: resourceType || null,
            expiresAt
        }
    })

    // 7. 发送验证码
    const operationName = getOperationName(operationType, 'zh')

    if (channel === 'email') {
        // 发送邮件
        const result = await sendOperationVerificationEmail(user.email!, {
            username: user.username,
            operationName,
            code,
            expiresInMinutes: VERIFICATION_CONFIG.expiresInMinutes
        })
        if (!result.success) {
            // 删除刚创建的验证码
            await prisma.operationVerification.deleteMany({
                where: { userId, operationType, code }
            })
            return { success: false, error: result.error, errorCode: 'SEND_FAILED' }
        }
    } else {
        // 发送通知渠道消息
        const result = await sendVerificationNotification(userId, {
            operationName,
            code,
            expiresInMinutes: VERIFICATION_CONFIG.expiresInMinutes
        })
        if (!result.success) {
            await prisma.operationVerification.deleteMany({
                where: { userId, operationType, code }
            })
            return { success: false, error: result.error, errorCode: 'SEND_FAILED' }
        }
    }

    return {
        success: true,
        channel,
        maskedTarget,
        expiresIn: VERIFICATION_CONFIG.expiresInMinutes * 60
    }
}

export interface VerifyOperationResult {
    success: boolean
    verified: boolean
    error?: string
    errorCode?: string
}

/**
 * 验证二次验证码
 */
export async function verifyOperationCode(
    userId: number,
    operationType: OperationType,
    code: string,
    resourceId?: number
): Promise<VerifyOperationResult> {
    return prisma.$transaction(async (tx) => {
        const now = new Date()
        const invalidResult: VerifyOperationResult = {
            success: false,
            verified: false,
            error: 'Invalid or expired verification code',
            errorCode: 'INVALID_CODE'
        }

        const verification = await tx.operationVerification.findFirst({
            where: {
                userId,
                operationType,
                resourceId: resourceId || null,
                verified: false,
                expiresAt: { gt: now }
            },
            orderBy: { createdAt: 'desc' },
            select: { id: true, code: true, expiresAt: true }
        })

        if (!verification) {
            return invalidResult
        }

        // Prisma 的普通查询不会锁行；用 FOR UPDATE 串行化多副本下对同一验证码的计数。
        await tx.$queryRaw(Prisma.sql`
            SELECT id
            FROM "operation_verifications"
            WHERE id = ${verification.id} AND verified = false
            FOR UPDATE
        `)

        const lockedVerification = await tx.operationVerification.findUnique({
            where: { id: verification.id },
            select: { code: true, expiresAt: true, verified: true }
        })

        if (
            !lockedVerification
            || lockedVerification.verified
            || lockedVerification.expiresAt <= now
        ) {
            return invalidResult
        }

        const storedCode = decodeVerificationCode(lockedVerification.code)
        const attempts = storedCode.attempts

        // 达到上限后立即删除验证码；删除失败则保留计数并向上抛错，避免恢复为可猜测状态。
        if (attempts >= VERIFICATION_CONFIG.maxAttempts) {
            await tx.operationVerification.deleteMany({
                where: {
                    userId,
                    operationType,
                    resourceId: resourceId || null,
                    verified: false
                }
            })
            return invalidResult
        }

        if (storedCode.code !== code) {
            const nextAttempts = attempts + 1

            if (nextAttempts >= VERIFICATION_CONFIG.maxAttempts) {
                await tx.operationVerification.deleteMany({
                    where: {
                        userId,
                        operationType,
                        resourceId: resourceId || null,
                        verified: false
                    }
                })
            } else {
                await tx.operationVerification.update({
                    where: { id: verification.id },
                    data: { code: encodeVerificationCode(storedCode.code, nextAttempts) }
                })
            }

            return invalidResult
        }

        await tx.operationVerification.update({
            where: { id: verification.id },
            data: {
                verified: true,
                verifiedAt: now
            }
        })

        return { success: true, verified: true }
    })
}

/**
 * 检查操作是否已经通过二次验证
 * 验证在10分钟内有效
 */
export async function isOperationVerified(
    userId: number,
    operationType: OperationType,
    resourceId?: number
): Promise<boolean> {
    const tenMinutesAgo = new Date(Date.now() - 10 * 60 * 1000)
    
    const verification = await prisma.operationVerification.findFirst({
        where: {
            userId,
            operationType,
            resourceId: resourceId || null,
            verified: true,
            verifiedAt: { gt: tenMinutesAgo }
        }
    })

    return !!verification
}

/**
 * 清理已使用的验证记录（操作完成后调用）
 */
export async function consumeOperationVerification(
    userId: number,
    operationType: OperationType,
    resourceId?: number
): Promise<void> {
    await prisma.operationVerification.deleteMany({
        where: {
            userId,
            operationType,
            resourceId: resourceId || null,
            verified: true
        }
    })
}

/**
 * 原子领取一次已通过的二次验证。
 *
 * `isOperationVerified` 仅用于页面状态查询，不能作为敏感操作的授权闸门，
 * 因为多个并发请求可能同时读到同一条已验证记录。实际执行敏感操作前，
 * 必须调用此函数；成功后记录立即删除，失败请求不能继续执行操作。
 */
export async function claimOperationVerification(
    userId: number,
    operationType: OperationType,
    resourceId?: number
): Promise<boolean> {
    const tenMinutesAgo = new Date(Date.now() - 10 * 60 * 1000)

    return prisma.$transaction(async (tx) => {
        const verification = await tx.operationVerification.findFirst({
            where: {
                userId,
                operationType,
                resourceId: resourceId || null,
                verified: true,
                verifiedAt: { gt: tenMinutesAgo }
            },
            orderBy: { verifiedAt: 'asc' },
            select: { id: true }
        })

        if (!verification) {
            return false
        }

        const result = await tx.operationVerification.deleteMany({
            where: {
                id: verification.id,
                verified: true,
                verifiedAt: { gt: tenMinutesAgo }
            }
        })

        return result.count === 1
    })
}

/**
 * 按操作类型领取二次验证；没有配置通知渠道的资源操作沿用“不要求验证”的策略。
 */
export async function claimOperationVerificationIfRequired(
    userId: number,
    operationType: OperationType,
    resourceId?: number
): Promise<boolean> {
    if (isResourceOperation(operationType) && !(await isResourceVerificationRequired(userId))) {
        return true
    }

    return claimOperationVerification(userId, operationType, resourceId)
}

/**
 * 检查资源操作是否需要二次验证
 * 如果用户没有绑定通知渠道，则不需要二次验证
 */
export async function isResourceVerificationRequired(userId: number): Promise<boolean> {
    const channel = await getUserNotificationChannel(userId)
    return channel.channel !== null
}

/**
 * 清理过期的验证记录（定期调用）
 * 删除所有已过期的验证记录
 */
export async function cleanupExpiredVerifications(): Promise<number> {
    const result = await prisma.operationVerification.deleteMany({
        where: {
            expiresAt: { lt: new Date() }
        }
    })
    return result.count
}

/**
 * 导出操作类型常量供外部使用
 */
export { OperationType, VerificationChannel }
