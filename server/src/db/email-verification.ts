/**
 * Email verification code database operations
 */

import { prisma } from './prisma.js'
import crypto from 'crypto'
import { sharedDel, sharedIncrement } from '../lib/shared-state.js'

// Verification code expiration time in minutes
const CODE_EXPIRATION_MINUTES = 10

// Rate limit: max codes per email per hour
const MAX_CODES_PER_HOUR = 5

// 验证失败上限：超过后立即作废该邮箱的验证码，防止 6 位验证码被暴力尝试
const MAX_VERIFY_FAILURES = 5

// 验证失败计数的统计窗口
const VERIFY_FAILURE_WINDOW_MS = 60 * 60 * 1000

/**
 * Generate a cryptographically secure random 6-digit verification code
 */
export function generateVerificationCode(): string {
    // Use crypto.randomInt for secure random number generation
    const min = 100000
    const max = 999999
    return crypto.randomInt(min, max + 1).toString()
}

// 验证失败计数（按邮箱）。
// 计数走共享存储（审查项 P2-09）：多副本部署时按邮箱全局计数，
// 攻击者无法把尝试分散到不同副本来绕过失败上限。
const VERIFY_FAILURE_KEY_PREFIX = 'email-verify-failure:'

async function registerVerifyFailure(normalizedEmail: string): Promise<void> {
    const count = await sharedIncrement(`${VERIFY_FAILURE_KEY_PREFIX}${normalizedEmail}`, VERIFY_FAILURE_WINDOW_MS)

    if (count >= MAX_VERIFY_FAILURES) {
        // 立即作废该邮箱的所有验证码，让继续暴力尝试失去意义
        await sharedDel(`${VERIFY_FAILURE_KEY_PREFIX}${normalizedEmail}`)
        await prisma.emailVerificationCode.deleteMany({
            where: { email: normalizedEmail }
        }).catch(() => {})
    }
}

/**
 * Create a new email verification code
 */
export async function createVerificationCode(email: string): Promise<{ code: string; expiresAt: Date } | null> {
    const normalizedEmail = email.toLowerCase().trim()

    // Check rate limit
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000)
    const recentCount = await prisma.emailVerificationCode.count({
        where: {
            email: normalizedEmail,
            createdAt: { gte: oneHourAgo }
        }
    })

    if (recentCount >= MAX_CODES_PER_HOUR) {
        return null // Rate limited
    }

    // Delete any existing codes for this email
    await prisma.emailVerificationCode.deleteMany({
        where: { email: normalizedEmail }
    })

    // Generate new code
    const code = generateVerificationCode()
    const expiresAt = new Date(Date.now() + CODE_EXPIRATION_MINUTES * 60 * 1000)

    await prisma.emailVerificationCode.create({
        data: {
            email: normalizedEmail,
            code,
            expiresAt
        }
    })

    return { code, expiresAt }
}

/**
 * Verify an email verification code
 *
 * 使用 deleteMany 原子地“匹配并消费”验证码：并发验证同一验证码时只有一个请求
 * 能成功（count > 0），其余请求自然失败，不会出现先 find 后 delete 的竞态。
 * 失败计入按邮箱的计数，达到上限后立即作废该邮箱的验证码，防止暴力尝试。
 */
export async function verifyCode(email: string, code: string): Promise<boolean> {
    const normalizedEmail = email.toLowerCase().trim()

    if (!code || !/^\d{6}$/.test(code)) {
        return false
    }

    const result = await prisma.emailVerificationCode.deleteMany({
        where: {
            email: normalizedEmail,
            code,
            expiresAt: { gt: new Date() }
        }
    })

    if (result.count > 0) {
        await sharedDel(`${VERIFY_FAILURE_KEY_PREFIX}${normalizedEmail}`)
        return true
    }

    await registerVerifyFailure(normalizedEmail)
    return false
}

/**
 * Delete expired verification codes (cleanup job)
 */
export async function cleanupExpiredCodes(): Promise<number> {
    const result = await prisma.emailVerificationCode.deleteMany({
        where: {
            expiresAt: { lt: new Date() }
        }
    })
    return result.count
}

/**
 * Check if an email has a valid pending verification code
 */
export async function hasPendingCode(email: string): Promise<boolean> {
    const normalizedEmail = email.toLowerCase().trim()
    
    const count = await prisma.emailVerificationCode.count({
        where: {
            email: normalizedEmail,
            expiresAt: { gt: new Date() }
        }
    })

    return count > 0
}

