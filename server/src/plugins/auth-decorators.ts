/**
 * 认证装饰器插件
 * 包含实时账户状态查询、Token 验证和管理员权限检查
 */

import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { prisma } from '../db/prisma.js'
import { isAccessTokenInvalidated } from '../lib/security.js'
import { sharedDel, sharedDelPrefix } from '../lib/shared-state.js'

// Authorization must use current database state. A request that started before
// cache eviction can otherwise repopulate stale roles or token validity after
// a ban/demotion. Keep eviction for compatibility with old replicas/callers.
const AUTH_USER_CACHE_PREFIX = 'auth-cache:user:'
const AUTH_TOKEN_INVALIDATION_PREFIX = 'auth-cache:tinv:'

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

  const invalidated = await isAccessTokenInvalidated(user.id, user.iat, user.sid)

  if (invalidated) {
    reply.code(401).send({ error: 'Session expired', code: 'SESSION_INVALIDATED' })
    return false
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
