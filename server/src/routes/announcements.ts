/**
 * 公告/通知历史记录路由
 */

import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify'
import * as announcementsDb from '../db/announcements.js'
import { parsePagination } from '../db/pagination.js'
import { apiError, ErrorCode } from '../lib/errors.js'

export default async function announcementsRoutes(fastify: FastifyInstance) {
  // 所有路由都需要认证
  fastify.addHook('onRequest', fastify.authenticate)

  /**
   * 获取公告历史列表（管理员）
   * GET /api/announcements
   */
  fastify.get<{
    Querystring: {
      page?: string
      pageSize?: string
      type?: string
    }
  }>('/', async (request: FastifyRequest<{
    Querystring: {
      page?: string
      pageSize?: string
      type?: string
    }
  }>, reply: FastifyReply) => {
    // 检查管理员权限
    if (request.user.role !== 'admin') {
      return reply.code(403).send(apiError(ErrorCode.FORBIDDEN))
    }

    const { type } = request.query

    const result = await announcementsDb.getAnnouncementList({
      ...parsePagination(request.query),
      type: type as any,
    })

    return result
  })

  /**
   * 获取宿主机所有者的公告历史
   * GET /api/announcements/my
   */
  fastify.get<{
    Querystring: {
      page?: string
      pageSize?: string
      hostId?: string
    }
  }>('/my', async (request: FastifyRequest<{
    Querystring: {
      page?: string
      pageSize?: string
      hostId?: string
    }
  }>) => {
    const { hostId } = request.query

    const result = await announcementsDb.getHostOwnerAnnouncementList(
      request.user.id,
      {
        ...parsePagination(request.query),
        hostId: hostId ? parseInt(hostId, 10) : undefined,
      }
    )

    return result
  })

  /**
   * 获取公告详情
   * GET /api/announcements/:id
   */
  fastify.get<{
    Params: { id: string }
  }>('/:id', async (request: FastifyRequest<{
    Params: { id: string }
  }>, reply: FastifyReply) => {
    const { id } = request.params
    const announcementId = Number(id)

    if (isNaN(announcementId)) {
      return reply.code(400).send(apiError(ErrorCode.INVALID_ID))
    }

    const announcement = await announcementsDb.getAnnouncementById(announcementId)

    if (!announcement) {
      return reply.code(404).send({ error: 'ANNOUNCEMENT_NOT_FOUND', message: 'Announcement not found' })
    }

    // 检查权限：管理员可以查看所有，宿主机所有者只能查看自己发送的
    if (request.user.role !== 'admin' && announcement.senderId !== request.user.id) {
      return reply.code(403).send(apiError(ErrorCode.FORBIDDEN))
    }

    return announcement
  })
}
