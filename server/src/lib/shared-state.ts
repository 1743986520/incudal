/**
 * 共享 KV 状态层（审查项 P2-09）
 *
 * 配置 REDIS_URL 时使用 Redis 承载跨副本共享状态；未配置时退回进程内存
 * （与历史行为一致，仅单副本语义）。提供三类原语：
 * - get/set/del：带 TTL 的缓存（认证缓存等）
 * - consume：原子"读取即删除"，用于一次性票据/验证（下载 token、终端票据）
 * - addOnce：key 不存在时才写入（SET NX），用于 OAuth nonce 防重放
 * - increment：窗口内自增计数（邮件验证失败计数）
 *
 * Redis 故障时的语义：
 * - 缓存读取按 miss 处理，回源数据库，不影响正确性
 * - consume/addOnce 失败一律视为"未命中/已占用"，fail closed，宁可让调用方重试
 */

import { getRedis } from './redis.js'

interface MemoryEntry {
    value: string
    expiresAt: number
}

// 无 Redis 时的进程内存后端。限制 key 数量，防止被无界增长拖垮内存。
const memoryStore = new Map<string, MemoryEntry>()
const MAX_MEMORY_KEYS = 50_000

function memGet(key: string): string | null {
    const entry = memoryStore.get(key)
    if (!entry) return null
    if (Date.now() > entry.expiresAt) {
        memoryStore.delete(key)
        return null
    }
    return entry.value
}

function memSet(key: string, value: string, ttlMs: number): void {
    if (memoryStore.size >= MAX_MEMORY_KEYS) {
        // 先清理过期条目，仍超限则按插入顺序淘汰最旧的
        const now = Date.now()
        for (const [k, entry] of memoryStore) {
            if (now > entry.expiresAt) memoryStore.delete(k)
            if (memoryStore.size < MAX_MEMORY_KEYS) break
        }
        while (memoryStore.size >= MAX_MEMORY_KEYS) {
            const oldest = memoryStore.keys().next().value
            if (oldest === undefined) break
            memoryStore.delete(oldest)
        }
    }
    memoryStore.set(key, { value, expiresAt: Date.now() + ttlMs })
}

export async function sharedGet(key: string): Promise<string | null> {
    const redis = getRedis()
    if (redis) {
        try {
            return await redis.get(key)
        } catch (err) {
            console.error('[shared-state] get failed, treating as miss:', err instanceof Error ? err.message : err)
            return null
        }
    }
    return memGet(key)
}

export async function sharedSet(key: string, value: string, ttlMs: number): Promise<void> {
    const redis = getRedis()
    if (redis) {
        try {
            await redis.set(key, value, 'PX', ttlMs)
            return
        } catch (err) {
            console.error('[shared-state] set failed:', err instanceof Error ? err.message : err)
            return
        }
    }
    memSet(key, value, ttlMs)
}

export async function sharedDel(key: string): Promise<void> {
    const redis = getRedis()
    if (redis) {
        try {
            await redis.del(key)
            return
        } catch (err) {
            console.error('[shared-state] del failed:', err instanceof Error ? err.message : err)
            return
        }
    }
    memoryStore.delete(key)
}

/** 删除所有以 prefix 开头的 key（用于按会话撤销票据、清除用户认证缓存） */
export async function sharedDelPrefix(prefix: string): Promise<void> {
    const redis = getRedis()
    if (redis) {
        try {
            let cursor = '0'
            do {
                const [next, keys] = await redis.scan(cursor, 'MATCH', `${prefix}*`, 'COUNT', 200)
                cursor = next
                if (keys.length > 0) {
                    await redis.del(...keys)
                }
            } while (cursor !== '0')
            return
        } catch (err) {
            console.error('[shared-state] delPrefix failed:', err instanceof Error ? err.message : err)
            return
        }
    }
    for (const key of [...memoryStore.keys()]) {
        if (key.startsWith(prefix)) memoryStore.delete(key)
    }
}

/** 列出所有以 prefix 开头的 key（SCAN / 内存遍历），用于按会话索引撤销票据 */
export async function sharedListKeys(prefix: string): Promise<string[]> {
    const redis = getRedis()
    if (redis) {
        try {
            const keys: string[] = []
            let cursor = '0'
            do {
                const [next, batch] = await redis.scan(cursor, 'MATCH', `${prefix}*`, 'COUNT', 200)
                cursor = next
                keys.push(...batch)
            } while (cursor !== '0')
            return keys
        } catch (err) {
            console.error('[shared-state] listKeys failed:', err instanceof Error ? err.message : err)
            return []
        }
    }
    return [...memoryStore.keys()].filter(key => key.startsWith(prefix))
}

/**
 * 原子消费：key 存在则返回其值并立即删除，否则返回 null。
 * 仅支持单次使用语义（当前所有调用方都是 maxUsage=1）。
 */
export async function sharedConsume(key: string): Promise<string | null> {
    const redis = getRedis()
    if (redis) {
        try {
            // GETDEL 需要 Redis >= 6.2（docker-compose 使用 redis:7）
            return await redis.getdel(key)
        } catch (err) {
            console.error('[shared-state] consume failed, failing closed:', err instanceof Error ? err.message : err)
            return null
        }
    }
    const value = memGet(key)
    if (value === null) return null
    memoryStore.delete(key)
    return value
}

/**
 * 一次性写入：key 不存在时写入并返回 true，已存在返回 false。
 * 用于 nonce 防重放：并发重放请求中只有一个能成功。
 */
export async function sharedAddOnce(key: string, ttlMs: number): Promise<boolean> {
    const redis = getRedis()
    if (redis) {
        try {
            const result = await redis.set(key, '1', 'PX', ttlMs, 'NX')
            return result === 'OK'
        } catch (err) {
            console.error('[shared-state] addOnce failed, failing closed:', err instanceof Error ? err.message : err)
            return false
        }
    }
    if (memGet(key) !== null) return false
    memSet(key, '1', ttlMs)
    return true
}

/**
 * 窗口内自增计数：首次自增时设置过期时间，返回自增后的计数。
 * 用于验证失败次数等限流计数。
 */
export async function sharedIncrement(key: string, windowMs: number): Promise<number> {
    const redis = getRedis()
    if (redis) {
        try {
            const count = await redis.incr(key)
            if (count === 1) {
                await redis.pexpire(key, windowMs)
            }
            return count
        } catch (err) {
            console.error('[shared-state] increment failed:', err instanceof Error ? err.message : err)
            // 失败时按"计数不可用"处理，调用方退化为不限制
            return 0
        }
    }
    const existing = memoryStore.get(key)
    const now = Date.now()
    if (!existing || now > existing.expiresAt) {
        memSet(key, '1', windowMs)
        return 1
    }
    const count = Number(existing.value) + 1
    existing.value = String(count)
    return count
}
