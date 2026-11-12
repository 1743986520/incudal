/**
 * 敏感操作邮件确认路由
 *
 * 面板内发起敏感操作 → 服务端邮件发送确认链接（1 小时有效，单次使用）→
 * 用户点击链接打开 /confirm-operation 页面 → 该页面调用 POST /confirm →
 * 服务端校验 token 并执行对应操作。无需登录态，token 即授权凭证。
 */

import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify'
import { consumeOperationConfirm } from '../lib/operation-confirm.js'
import { createApiKeyForUser } from '../lib/api-keys.js'
import { createLog } from '../db/logs.js'
import * as db from '../db/index.js'
import { createInstanceTask, InstanceTaskConflictError } from '../db/instance-tasks.js'
import { updateUserPasswordAndInvalidateSessions } from '../lib/security.js'
import { clearAuthCache } from '../plugins/auth-decorators.js'
import { closeUserSessions } from '../lib/terminal-proxy.js'

function readPayloadString(payload: Record<string, unknown>, key: string): string | undefined {
    const value = payload[key]
    return typeof value === 'string' && value.length > 0 ? value : undefined
}

function readPayloadNumber(payload: Record<string, unknown>, key: string): number | undefined {
    const value = payload[key]
    return typeof value === 'number' && Number.isInteger(value) ? value : undefined
}

function readPayloadNumberArray(payload: Record<string, unknown>, key: string): number[] | undefined {
    const value = payload[key]
    return Array.isArray(value) && value.every(v => typeof v === 'number' && Number.isInteger(v))
        ? (value as number[])
        : undefined
}

export default async function verificationRoutes(fastify: FastifyInstance) {
    /**
     * 确认链接落地端点：校验 token 并执行对应敏感操作。
     * 不要求登录——邮件链接本身即授权凭证（一次性、1 小时有效、sha256 落库）。
     * POST /api/verification/confirm
     */
    fastify.post<{
        Body: { token: string }
    }>(
        '/confirm',
        {
            config: { rateLimit: { max: 10, timeWindow: '1 minute' } },
            schema: {
                body: {
                    type: 'object',
                    required: ['token'],
                    properties: {
                        token: { type: 'string', minLength: 16, maxLength: 128 }
                    }
                }
            }
        },
        async (request: FastifyRequest<{ Body: { token: string } }>, reply: FastifyReply) => {
            const { token } = request.body

            const confirm = await consumeOperationConfirm(token)
            if (!confirm) {
                return reply.code(400).send({
                    error: '确认链接无效或已过期',
                    code: 'INVALID_CONFIRM_TOKEN'
                })
            }

            const payload = confirm.payload ?? {}

            switch (confirm.operationType) {
                case 'api_key': {
                    // 创建 API Key：完整密钥仅在本次响应中返回一次
                    const name = readPayloadString(payload, 'name')
                    let created
                    try {
                        created = await createApiKeyForUser(confirm.userId, name)
                    } catch (error) {
                        if (error instanceof Error && error.message === 'API_KEY_LIMIT_REACHED') {
                            return reply.code(409).send({
                                error: '活跃 API Key 数量已达上限（10 个），请先删除或停用部分密钥',
                                code: 'API_KEY_LIMIT_REACHED'
                            })
                        }
                        throw error
                    }
                    await createLog(confirm.userId, 'security', 'apikey.create', `API key created via email confirm link (prefix: ${created.prefix})`, 'success')
                    return {
                        success: true,
                        message: 'API Key 已创建。完整密钥仅此一次显示，请立即妥善保存。',
                        apiKey: { key: created.key, prefix: created.prefix }
                    }
                }

                case 'disable_2fa': {
                    // 与面板内禁用逻辑保持一致：清除全部 2FA 数据（含恢复码）
                    await db.disable2FAComplete(confirm.userId)
                    await createLog(confirm.userId, 'security', '2fa.disable', 'Disabled two-factor authentication via email confirm link', 'success')
                    const { sendNotification } = await import('../lib/notifier.js')
                    await sendNotification(confirm.userId, '2fa_disabled', { instanceName: '' }).catch(() => {})
                    return { success: true, message: '双因素认证（2FA）已禁用' }
                }

                case 'change_password': {
                    const passwordHash = readPayloadString(payload, 'passwordHash')
                    if (!passwordHash) {
                        return reply.code(400).send({ error: '确认记录缺少待执行参数', code: 'INVALID_CONFIRM_PAYLOAD' })
                    }
                    // 密码更新、会话撤销与 Access Token 失效原子完成
                    await updateUserPasswordAndInvalidateSessions(confirm.userId, { passwordHash })
                    closeUserSessions(confirm.userId, 'Password updated via email confirm link')
                    await clearAuthCache(confirm.userId)
                    await createLog(confirm.userId, 'personal', 'user.update', 'Password changed via email confirm link', 'success')
                    return { success: true, message: '密码已更新，请使用新密码登录' }
                }

                case 'reinstall_instance':
                case 'recreate_instance': {
                    const instanceId = confirm.resourceId
                    if (!instanceId) {
                        return reply.code(400).send({ error: '确认记录缺少实例信息', code: 'INVALID_CONFIRM_PAYLOAD' })
                    }

                    const instance = await db.getInstanceById(instanceId)
                    if (!instance || instance.user_id !== confirm.userId) {
                        return reply.code(404).send({ error: '实例不存在', code: 'INSTANCE_NOT_FOUND' })
                    }
                    if (instance.status === 'deleted') {
                        return reply.code(409).send({ error: '实例已删除', code: 'INSTANCE_STATE_INVALID' })
                    }

                    const imageAlias = readPayloadString(payload, 'imageAlias') || readPayloadString(payload, 'image')
                    if (!imageAlias) {
                        return reply.code(400).send({ error: '确认记录缺少镜像参数', code: 'INVALID_CONFIRM_PAYLOAD' })
                    }

                    const sshKeyId = readPayloadNumber(payload, 'sshKeyId')
                    if (sshKeyId) {
                        const keyRecord = await db.getSSHKeyById(sshKeyId)
                        if (!keyRecord || keyRecord.user_id !== confirm.userId) {
                            return reply.code(400).send({ error: 'SSH 密钥不存在或无权使用', code: 'SSH_KEY_NOT_OWNED' })
                        }
                    }

                    const taskType = confirm.operationType === 'reinstall_instance' ? 'rebuild' : 'recreate'
                    const taskData: Parameters<typeof createInstanceTask>[0] = {
                        instanceId,
                        hostId: instance.host_id,
                        userId: confirm.userId,
                        taskType,
                        imageAlias,
                        sshKeyId,
                        customInitCommandIds: readPayloadNumberArray(payload, 'customInitCommandIds')
                    } as Parameters<typeof createInstanceTask>[0]

                    try {
                        const task = await createInstanceTask(taskData)
                        await createLog(confirm.userId, 'instance', `instance.${taskType}`, `Queued ${taskType} task for instance "${instance.name}" via email confirm link`, 'success', { instanceId })
                        return { success: true, message: '操作已确认，任务已加入队列', taskId: task.id }
                    } catch (error) {
                        if (error instanceof InstanceTaskConflictError) {
                            return reply.code(409).send({
                                error: '实例有正在进行的任务',
                                code: 'TASK_IN_PROGRESS'
                            })
                        }
                        throw error
                    }
                }

                default:
                    // 其他操作类型（change_email 走新邮箱验证码；delete_account/transfer 等未开放链接确认）
                    return reply.code(400).send({
                        error: '该操作类型不支持链接确认',
                        code: 'UNSUPPORTED_OPERATION'
                    })
            }
        }
    )
}
