/**
 * 统一权限检查模块
 *
 * 将分散在各路由中的权限检查逻辑集中管理
 * 提供一致的权限验证接口
 *
 * 权限规则：
 * 1. 管理员 (admin): 拥有宿主机所有者的权限，可以查看和管理所有资源
 * 2. 实例所有者: 可以操作自己创建的实例
 * 3. 节点所有者: 可以管理其节点上的所有实例（有限制）
 * 4. 好友: 可以查看好友分享的资源
 *
 * AUTH004: 节点所有者/管理员权限边界明确定义
 *
 * 节点所有者/管理员可以：
 * - 启动/停止/重启节点上的实例
 * - 查看节点上所有实例的状态
 * - 创建/恢复节点上实例的快照
 * - 强制停止实例（维护场景）
 * - 查看实例日志和资源使用情况
 * - 删除节点上其他用户的实例（维护/清理场景）
 *
 * 节点所有者/管理员不可以：
 * - 转移其他用户的实例所有权
 * - 修改其他用户实例的配额
 * - 下载其他用户的备份
 * - 访问其他用户实例的敏感数据（如SSH密钥）
 */

import * as db from '../db/index.js'
import type { FastifyReply } from 'fastify'
import { apiError, ErrorCode } from './errors.js'

/**
 * 用户信息类型
 */
export interface AuthUser {
    id: number
    role: 'admin' | 'user'
    username?: string
}

/**
 * 权限检查结果
 */
export interface PermissionResult {
    allowed: boolean
    reason?: string
    /** 权限类型：owner-所有者, hostOwner-节点所有者, admin-管理员 */
    permissionType?: 'owner' | 'hostOwner' | 'admin' | 'friend'
}

// ==================== 实例权限检查 ====================

/**
 * 检查用户对实例的操作权限
 *
 * 权限规则：
 * 1. 管理员拥有宿主机所有者的权限，可以操作所有实例
 * 2. 实例所有者可以操作自己创建的实例
 * 3. 节点所有者可以操作其节点上的所有实例
 *
 * @param user 当前用户
 * @param instance 实例信息（需包含 user_id 和 host_id）
 * @returns 权限检查结果
 */
export async function checkInstancePermission(
    user: AuthUser,
    instance: { user_id: number; host_id: number }
): Promise<PermissionResult> {
    // 1. 管理员拥有宿主机所有者的权限
    if (user.role === 'admin') {
        return { allowed: true, permissionType: 'admin' }
    }

    // 2. 实例所有者有权限
    if (instance.user_id === user.id) {
        return { allowed: true, permissionType: 'owner' }
    }

    // 3. 检查是否是节点所有者
    const host = await db.getHostById(instance.host_id)
    if (host && host.user_id === user.id) {
        return { allowed: true, permissionType: 'hostOwner' }
    }

    return { allowed: false, reason: 'No permission to operate this instance' }
}

/** 仅允许实例所有者或管理员执行敏感/破坏性实例操作。 */
export function checkInstanceOwnerOrAdminPermission(
    user: AuthUser,
    instance: { user_id: number }
): PermissionResult {
    if (user.role === 'admin') {
        return { allowed: true, permissionType: 'admin' }
    }

    if (instance.user_id === user.id) {
        return { allowed: true, permissionType: 'owner' }
    }

    return {
        allowed: false,
        reason: 'This operation is only allowed for the instance owner or an administrator'
    }
}

/**
 * 验证实例查看权限并自动发送错误响应
 */
export async function requireInstanceViewPermission(
    user: AuthUser,
    instance: { user_id: number; host_id: number },
    reply: FastifyReply
): Promise<boolean> {
    const result = await checkInstancePermission(user, instance)
    if (!result.allowed) {
        reply.code(403).send(apiError(ErrorCode.FORBIDDEN))
        return false
    }
    return true
}

/**
 * 获取实例并验证权限
 * 便捷方法，用于路由处理器中：实例不存在时发送 404，无权限时发送 403
 *
 * @returns 实例对象，如果不存在或无权限返回 null
 */
export async function getInstanceWithPermission(
    user: AuthUser,
    instanceId: number,
    reply: FastifyReply
): Promise<Awaited<ReturnType<typeof db.getInstanceById>> | null> {
    const instance = await db.getInstanceById(instanceId)
    if (!instance) {
        reply.code(404).send(apiError(ErrorCode.INSTANCE_NOT_FOUND))
        return null
    }

    const result = await checkInstancePermission(user, instance)
    if (!result.allowed) {
        reply.code(403).send(apiError(ErrorCode.FORBIDDEN))
        return null
    }

    return instance
}
