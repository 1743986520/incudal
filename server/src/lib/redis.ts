/**
 * Redis 共享存储客户端（审查项 P2-09）
 *
 * 多副本部署时，认证缓存、一次性票据/nonce 与限流状态必须落在共享存储中。
 * 通过 REDIS_URL 启用（docker-compose 已为 panel 容器注入该变量）；
 * 未配置时调用方退化为进程内存，单副本部署行为不变。
 */

import Redis from 'ioredis'

let client: Redis | null | undefined

export function getRedis(): Redis | null {
    if (client !== undefined) return client

    const url = process.env.REDIS_URL?.trim()
    if (!url) {
        client = null
        return null
    }

    client = new Redis(url, {
        // 断线期间的命令在队列中等待重连，而不是立刻抛错；
        // 配合 maxRetriesPerRequest 限制单条命令的最大重试次数。
        maxRetriesPerRequest: 2,
        connectTimeout: 5000,
        retryStrategy: (times) => Math.min(500 * times, 5000)
    })
    client.on('error', (err) => {
        console.error('[Redis] client error:', err.message)
    })

    return client
}
