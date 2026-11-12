/**
 * API Key：受限实例控制凭证
 *
 * - 完整密钥仅在邮件确认落地页显示一次，服务端只存 sha256 哈希
 * - 认证后强制以普通用户身份（role=user）访问，配合全局范围门卫
 *   （app.ts preHandler）把可执行操作限制在本人实例的
 *   开/关机、端口增删、更换 IPv6 与只读查询
 */

import { prisma } from '../db/prisma.js'
import crypto from 'crypto'

const KEY_PREFIX_TAG = 'incu_sk_'
const KEY_RANDOM_BYTES = 24
/** lastUsedAt/requestCount 更新节流（毫秒），避免高频请求打写放大 */
const USAGE_TOUCH_INTERVAL_MS = 60_000

export const API_KEY_HEADER = 'x-api-key'

export function hashApiKey(key: string): string {
    return crypto.createHash('sha256').update(key).digest('hex')
}

export function isValidApiKeyFormat(key: string): boolean {
    return new RegExp(`^${KEY_PREFIX_TAG}[0-9a-f]{${KEY_RANDOM_BYTES * 2}}$`).test(key)
}

/**
 * 从请求头提取 API Key（X-API-Key 或 Authorization: Bearer incu_sk_...）
 */
export function extractApiKey(headers: Record<string, unknown>): string | null {
    const headerValue = headers['x-api-key']
    if (typeof headerValue === 'string' && headerValue.trim()) {
        return headerValue.trim()
    }

    const authHeader = headers['authorization']
    if (typeof authHeader === 'string' && authHeader.startsWith('Bearer incu_sk_')) {
        return authHeader.slice('Bearer '.length).trim()
    }

    return null
}

/**
 * 校验 API Key 并返回所属用户（强制 user 角色）。失败返回 null。
 */
export async function authenticateApiKey(key: string): Promise<{
    userId: number
    keyId: number
    username: string
} | null> {
    if (!isValidApiKeyFormat(key)) return null

    const apiKey = await prisma.apiKey.findUnique({
        where: { keyHash: hashApiKey(key) },
        select: {
            id: true,
            status: true,
            lastUsedAt: true,
            user: { select: { id: true, username: true, status: true } }
        }
    })

    if (!apiKey || apiKey.status !== 'active') return null
    if (apiKey.user.status !== 'active') return null

    // 用量统计节流更新（fire-and-forget）
    if (!apiKey.lastUsedAt || Date.now() - apiKey.lastUsedAt.getTime() > USAGE_TOUCH_INTERVAL_MS) {
        prisma.apiKey.update({
            where: { id: apiKey.id },
            data: { lastUsedAt: new Date(), requestCount: { increment: 1 } }
        }).catch(() => { /* 统计失败不影响请求 */ })
    }

    return { userId: apiKey.user.id, keyId: apiKey.id, username: apiKey.user.username }
}

/**
 * 创建 API Key（由邮件确认链接触发）。返回完整密钥，仅此一次。
 */
export async function createApiKeyForUser(userId: number, name?: string): Promise<{
    key: string
    prefix: string
    id: number
}> {
    // 单用户活跃上限，防止确认邮件被重复消费时囤积
    const activeCount = await prisma.apiKey.count({ where: { userId, status: 'active' } })
    if (activeCount >= 10) {
        throw new Error('API_KEY_LIMIT_REACHED')
    }

    const key = KEY_PREFIX_TAG + crypto.randomBytes(KEY_RANDOM_BYTES).toString('hex')
    const created = await prisma.apiKey.create({
        data: {
            userId,
            name: name?.trim() || null,
            keyHash: hashApiKey(key),
            prefix: key.slice(0, KEY_PREFIX_TAG.length + 6)
        }
    })

    return { key, prefix: created.prefix, id: created.id }
}

export async function listApiKeys(userId: number) {
    return prisma.apiKey.findMany({
        where: { userId },
        orderBy: { createdAt: 'desc' },
        select: {
            id: true,
            name: true,
            prefix: true,
            status: true,
            lastUsedAt: true,
            requestCount: true,
            createdAt: true
        }
    })
}

export async function setApiKeyStatus(userId: number, keyId: number, status: 'active' | 'disabled'): Promise<boolean> {
    const result = await prisma.apiKey.updateMany({
        where: { id: keyId, userId },
        data: { status }
    })
    return result.count === 1
}

export async function deleteApiKey(userId: number, keyId: number): Promise<boolean> {
    const result = await prisma.apiKey.deleteMany({
        where: { id: keyId, userId }
    })
    return result.count === 1
}
