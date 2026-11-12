/**
 * API Key 管理路由
 *
 * 创建走邮件确认链接（requestOperationConfirm），确认落地后由
 * verification.ts 的 api_key 分支真正生成密钥并一次性返回。
 */

import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify'
import { requestOperationConfirm } from '../lib/operation-confirm.js'
import { listApiKeys, setApiKeyStatus, deleteApiKey } from '../lib/api-keys.js'

export default async function apiKeyRoutes(fastify: FastifyInstance) {
    /**
     * 请求创建 API Key（发送邮件确认链接）
     * POST /api/api-keys/request
     */
    fastify.post<{
        Body: { name?: string }
    }>(
        '/request',
        {
            onRequest: [fastify.authenticate],
            config: { rateLimit: { max: 3, timeWindow: '1 minute' } },
            schema: {
                body: {
                    type: 'object',
                    properties: {
                        name: { type: 'string', maxLength: 64 }
                    }
                }
            }
        },
        async (request: FastifyRequest<{ Body: { name?: string } }>, reply: FastifyReply) => {
            const result = await requestOperationConfirm({
                userId: request.user.id,
                operationType: 'api_key',
                payload: { name: request.body.name }
            })

            if (!result.success) {
                request.log.error({ error: result.error }, 'Failed to send API key confirm email')
                return reply.code(502).send({
                    error: '确认邮件发送失败，请稍后重试',
                    code: 'CONFIRM_EMAIL_SEND_FAILED'
                })
            }

            return {
                success: true,
                message: '确认邮件已发送，请点击邮件中的链接创建 API Key（1 小时内有效）',
                confirmEmailSent: true
            }
        }
    )

    /**
     * 列出当前用户的 API Key（只含前缀，完整密钥永不回显）
     * GET /api/api-keys
     */
    fastify.get('/', {
        onRequest: [fastify.authenticate]
    }, async (request: FastifyRequest, _reply: FastifyReply) => {
        const keys = await listApiKeys(request.user.id)
        return {
            keys: keys.map(k => ({
                id: k.id,
                name: k.name,
                prefix: k.prefix,
                status: k.status,
                lastUsedAt: k.lastUsedAt?.toISOString() ?? null,
                requestCount: k.requestCount,
                createdAt: k.createdAt.toISOString()
            }))
        }
    })

    /**
     * 启用/停用 API Key
     * PATCH /api/api-keys/:id/status
     */
    fastify.patch<{
        Params: { id: string }
        Body: { status: 'active' | 'disabled' }
    }>(
        '/:id/status',
        {
            onRequest: [fastify.authenticate],
            schema: {
                body: {
                    type: 'object',
                    required: ['status'],
                    properties: {
                        status: { type: 'string', enum: ['active', 'disabled'] }
                    }
                }
            }
        },
        async (request: FastifyRequest<{ Params: { id: string }; Body: { status: 'active' | 'disabled' } }>, reply: FastifyReply) => {
            const keyId = Number(request.params.id)
            if (!Number.isInteger(keyId) || keyId <= 0) {
                return reply.code(400).send({ error: 'Invalid key ID' })
            }

            const updated = await setApiKeyStatus(request.user.id, keyId, request.body.status)
            if (!updated) {
                return reply.code(404).send({ error: 'API Key 不存在' })
            }

            return { success: true, message: request.body.status === 'active' ? '已启用' : '已停用' }
        }
    )

    /**
     * 删除 API Key
     * DELETE /api/api-keys/:id
     */
    fastify.delete<{
        Params: { id: string }
    }>(
        '/:id',
        {
            onRequest: [fastify.authenticate]
        },
        async (request: FastifyRequest<{ Params: { id: string } }>, reply: FastifyReply) => {
            const keyId = Number(request.params.id)
            if (!Number.isInteger(keyId) || keyId <= 0) {
                return reply.code(400).send({ error: 'Invalid key ID' })
            }

            const deleted = await deleteApiKey(request.user.id, keyId)
            if (!deleted) {
                return reply.code(404).send({ error: 'API Key 不存在' })
            }

            return { success: true, message: 'API Key 已删除' }
        }
    )
}
