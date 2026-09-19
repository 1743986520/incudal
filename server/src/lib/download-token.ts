/**
 * 一次性下载 Token 管理
 * 用于备份导出等文件下载场景，避免 JWT 通过 URL 参数传递
 *
 * 安全特性：
 * 1. 短期有效（默认5分钟）
 * 2. 使用次数限制（默认1次，共享存储模式下仅支持单次使用）
 * 3. 绑定特定资源
 * 4. 绑定特定用户
 *
 * 存储走共享状态层（审查项 P2-09）：多副本部署时任一副本生成、任一副本消费，
 * 由 Redis（或单副本下的进程内存）保证"消费即删除"的原子性。
 */

import { nanoid } from 'nanoid'
import { sharedConsume, sharedDel, sharedSet } from './shared-state.js'

const TOKEN_KEY_PREFIX = 'download-token:'

export interface DownloadToken {
    userId: number
    resourceId: string
    resourceType: 'backup-export' | 'backup-download'
    expiresAt: number
    maxUsage: number
    createdAt: number
}

/**
 * 生成一次性下载 Token
 * @param userId 用户 ID
 * @param resourceId 资源标识（如 taskId）
 * @param resourceType 资源类型
 * @param expiresInSeconds 有效期（秒），默认5分钟
 * @param maxUsage 最大使用次数，共享存储模式下仅支持 1 次
 * @returns 生成的 token
 */
export async function generateDownloadToken(
    userId: number,
    resourceId: string,
    resourceType: 'backup-export' | 'backup-download',
    expiresInSeconds: number = 300,
    maxUsage: number = 1
): Promise<string> {
    // 使用 nanoid 生成安全随机 token
    const token = nanoid(32)
    const now = Date.now()

    await sharedSet(
        `${TOKEN_KEY_PREFIX}${token}`,
        JSON.stringify({
            userId,
            resourceId,
            resourceType,
            expiresAt: now + expiresInSeconds * 1000,
            maxUsage,
            createdAt: now
        } satisfies DownloadToken),
        expiresInSeconds * 1000
    )

    return token
}

export interface ConsumeResult {
    valid: boolean
    userId?: number
    resourceId?: string
    error?: string
}

/**
 * 消费（验证并使用）下载 Token
 *
 * 消费通过共享状态的"读取即删除"完成：并发请求中只有一个能拿到载荷，
 * 其余请求视为已使用，不存在先查后删的竞态。
 * @param token 下载 token
 * @param expectedResourceId 期望的资源 ID（可选，用于额外验证）
 * @param expectedResourceType 期望的资源类型（可选）
 * @returns 验证结果
 */
export async function consumeDownloadToken(
    token: string,
    expectedResourceId?: string,
    expectedResourceType?: 'backup-export' | 'backup-download'
): Promise<ConsumeResult> {
    const raw = await sharedConsume(`${TOKEN_KEY_PREFIX}${token}`)

    // Token 不存在或已使用
    if (!raw) {
        return { valid: false, error: 'Token not found or already used' }
    }

    let data: DownloadToken
    try {
        data = JSON.parse(raw) as DownloadToken
    } catch {
        return { valid: false, error: 'Token corrupted' }
    }

    // Token 已过期
    if (Date.now() > data.expiresAt) {
        return { valid: false, error: 'Token expired' }
    }

    // 资源 ID 不匹配
    if (expectedResourceId && data.resourceId !== expectedResourceId) {
        return { valid: false, error: 'Resource mismatch' }
    }

    // 资源类型不匹配
    if (expectedResourceType && data.resourceType !== expectedResourceType) {
        return { valid: false, error: 'Resource type mismatch' }
    }

    return {
        valid: true,
        userId: data.userId,
        resourceId: data.resourceId
    }
}

/**
 * 撤销下载 Token
 * @param token 下载 token
 */
export async function revokeDownloadToken(token: string): Promise<void> {
    await sharedDel(`${TOKEN_KEY_PREFIX}${token}`)
}
