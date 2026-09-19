/**
 * 存储池缺失拦截的通知与审计
 *
 * 每次拦截都写入操作日志（含来源），供统计与排查；
 * 邮件按"同一用户 + 同一节点"在冷却窗口内只发送一封，避免重复点击造成邮件轰炸。
 * 邮件发送失败只记录日志，不影响拦截结果。
 */

import { createLog } from '../db/logs.js'
import { findUserById } from '../db/users.js'
import { sharedAddOnce } from './shared-state.js'
import { sendStoragePoolMissingEmail } from './mailer.js'

const NOTIFY_COOLDOWN_MS = 30 * 60 * 1000
const NOTIFY_COOLDOWN_KEY_PREFIX = 'storage-pool-notify:'
const LOG_ACTION = 'storage_pool.missing'

export interface StoragePoolMissingContext {
  userId: number
  hostId: number
  hostName: string
  /** 操作来源，如 instance.create / admin.create / hosting.create / retry-provision / task.rebuild */
  source: string
  instanceId?: number
}

/**
 * 记录一次存储池缺失拦截；若超出冷却窗口则向操作用户发送提醒邮件。
 * 应以 fire-and-forget 方式调用，任何异常都不允许影响主流程的拦截结果。
 */
export async function notifyStoragePoolMissing(ctx: StoragePoolMissingContext): Promise<void> {
  try {
    await createLog(
      ctx.userId,
      'instance',
      LOG_ACTION,
      `拦截实例创建：节点 "${ctx.hostName}" 尚未创建可用的系统盘存储池 (hostId=${ctx.hostId}, source=${ctx.source})`,
      'failed',
      ctx.instanceId !== undefined ? { instanceId: ctx.instanceId } : {}
    )

    // 冷却窗口走共享状态（SET NX）：同一用户+同一节点在窗口内只发送一封邮件，
    // 并发请求中也只有一个能抢占到发送资格（多副本部署下同样生效）。
    const shouldNotify = await sharedAddOnce(`${NOTIFY_COOLDOWN_KEY_PREFIX}${ctx.userId}:${ctx.hostId}`, NOTIFY_COOLDOWN_MS)
    if (!shouldNotify) {
      return
    }

    const user = await findUserById(ctx.userId)
    if (!user?.email) {
      return
    }

    const result = await sendStoragePoolMissingEmail(user.email, {
      username: user.username,
      hostName: ctx.hostName,
      action: ctx.source
    })

    if (!result.success) {
      console.warn(`[StoragePoolNotify] 邮件发送失败 (userId=${ctx.userId}, hostId=${ctx.hostId}):`, result.error)
    }
  } catch (err) {
    console.warn('[StoragePoolNotify] 通知流程异常（不影响拦截结果）:', err)
  }
}
