/**
 * 认证装饰器插件
 * 包含认证查询缓存、Token 验证和管理员权限检查
 */

import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { prisma } from '../db/prisma.js'
import { isAccessTokenInvalidated } from '../lib/security.js'
import { sharedDel, sharedDelPrefix, sharedGet, sharedSet } from '../lib/shared-state.js'

// ==================== 认证查询短时缓存 ====================
// 为认证查询添加 30 秒 TTL 缓存，减少每次请求的数据库查询。
// 缓存走共享状态层（审查项 P2-09）：配置 REDIS_URL 的多副本部署中，
// 用户封禁/角色变更通过 clearAuthCache 清除共享缓存，各副本即时生效；
// 未配置 Redis 时退化为进程内存，行为与历史版本一致。

const AUTH_CACHE_TTL_MS = 30_000 // 30 秒

const AUTH_USER_CACHE_PREFIX = 'auth-cache:user:'
const AUTH_TOKEN_INVALIDATION_PREFIX = 'auth-cache:tinv:'

interface AuthUserInfo {
  username: string
  role: string
  status: string
}

/**
 * 清除指定用户的认证缓存（用户状态变更时调用），多副本部署下作用于共享存储。
 *
 * 必须在状态/令牌失效变更提交到数据库之后再调用并 await：
 * 若先清理后提交，其他副本的请求可能在清理与提交之间把旧的"有效"结果
 * 重新写入缓存，令牌撤销后仍可继续使用最长一个缓存 TTL。
 */
export async function clearAuthCache(userId: number): Promise<void> {
  await sharedDel(`${AUTH_USER_CACHE_PREFIX}${userId}`)
  await sharedDelPrefix(`${AUTH_TOKEN_INVALIDATION_PREFIX}${userId}:`)
}

// ==================== 认证辅助函数 ====================

async function ensureActiveAccessToken(
  request: FastifyRequest,
  reply: FastifyReply
): Promise<boolean> {
  const user = request.user as { id?: number; username?: string; role?: string; status?: string; sid?: string; iat?: number }

  if (!user?.id || !user.iat) {
    reply.code(401).send({ error: 'Unauthorized', code: 'UNAUTHORIZED' })
    return false
  }

  // 使用缓存的 token 失效检查结果
  const invalidationKey = `${AUTH_TOKEN_INVALIDATION_PREFIX}${user.id}:${user.iat}:${user.sid ?? ''}`
  const cachedInvalidated = await sharedGet(invalidationKey)
  let invalidated: boolean
  if (cachedInvalidated !== null) {
    invalidated = cachedInvalidated === '1'
  } else {
    invalidated = await isAccessTokenInvalidated(user.id, user.iat, user.sid)
    await sharedSet(invalidationKey, invalidated ? '1' : '0', AUTH_CACHE_TTL_MS)
  }

  if (invalidated) {
    reply.code(401).send({ error: 'Session expired', code: 'SESSION_INVALIDATED' })
    return false
  }

  // 使用缓存的用户信息
  const userKey = `${AUTH_USER_CACHE_PREFIX}${user.id}`
  const cachedUserInfoRaw = await sharedGet(userKey)
  if (cachedUserInfoRaw) {
    try {
      const cachedUserInfo = JSON.parse(cachedUserInfoRaw) as AuthUserInfo
      if (cachedUserInfo.status !== 'active') {
        reply.code(401).send({ error: 'Account banned', code: 'ACCOUNT_BANNED' })
        return false
      }
      user.username = cachedUserInfo.username
      user.role = cachedUserInfo.role
      user.status = cachedUserInfo.status
      return true
    } catch {
      // 缓存数据损坏时按 miss 处理，回源数据库
    }
  }

  const currentUser = await prisma.user.findUnique({
    where: { id: user.id },
    select: {
      username: true,
      role: true,
      status: true
    }
  })

  if (!currentUser) {
    reply.code(401).send({ error: 'Unauthorized', code: 'UNAUTHORIZED' })
    return false
  }

  // 缓存用户信息
  await sharedSet(userKey, JSON.stringify(currentUser), AUTH_CACHE_TTL_MS)

  if (currentUser.status !== 'active') {
    reply.code(401).send({ error: 'Account banned', code: 'ACCOUNT_BANNED' })
    return false
  }

  user.username = currentUser.username
  user.role = currentUser.role
  user.status = currentUser.status

  return true
}

async function ensureCurrentAdmin(
  request: FastifyRequest,
  reply: FastifyReply
): Promise<boolean> {
  const currentUser = request.user as { id?: number; role?: string; status?: string }
  if (!currentUser?.id || currentUser.role !== 'admin' || currentUser.status !== 'active') {
    reply.code(403).send({ error: 'Admin privileges required', code: 'ADMIN_REQUIRED' })
    return false
  }

  return true
}

// ==================== Fastify 装饰器注册 ====================

/**
 * 注册认证装饰器到 Fastify 实例
 */
export async function registerAuthDecorators(fastify: FastifyInstance): Promise<void> {
  fastify.decorate('authenticate', async function (request: FastifyRequest, reply: FastifyReply) {
    try {
      await request.jwtVerify()
      if (!(await ensureActiveAccessToken(request, reply))) {
        return
      }
    } catch (err) {
      reply.code(401).send({ error: 'Unauthorized' })
    }
  })

  // 管理员权限检查 (作为 preHandler 使用)
  fastify.decorate('requireAdmin', async function (request: FastifyRequest, reply: FastifyReply) {
    // 必须先通过 authenticate，确保 request.user 存在
    if (!request.user) {
      return reply.code(401).send({ error: 'Unauthorized', code: 'UNAUTHORIZED' })
    }
    if (!(await ensureCurrentAdmin(request, reply))) {
      return
    }
  })

  // 组合认证+管理员检查的便捷 preHandler（简化版）
  fastify.decorate('authenticateAdmin', async function (request: FastifyRequest, reply: FastifyReply) {
    try {
      await request.jwtVerify()
      if (!(await ensureActiveAccessToken(request, reply))) {
        return
      }
      if (!(await ensureCurrentAdmin(request, reply))) {
        return
      }
    } catch (err) {
      return reply.code(401).send({ error: 'Unauthorized' })
    }
  })

  // 组合认证+普通用户检查（禁止管理员访问）（简化版）
  fastify.decorate('authenticateUser', async function (request: FastifyRequest, reply: FastifyReply) {
    try {
      await request.jwtVerify()
      if (!(await ensureActiveAccessToken(request, reply))) {
        return
      }
      const user = request.user as { id: number; role?: string }
      // 禁止管理员访问普通用户专属功能
      if (user.role === 'admin') {
        return reply.code(403).send({ error: 'This feature is for regular users only', code: 'USER_ONLY' })
      }
    } catch (err) {
      return reply.code(401).send({ error: 'Unauthorized' })
    }
  })
}
