/**
 * 调度器启动模块
 * 集中管理所有后台调度器和定时清理任务
 */

export async function startSchedulers(): Promise<void> {
  // 启动流量调度器
  const { startTrafficScheduler } = await import('../services/traffic-scheduler.js')
  startTrafficScheduler()

  const { startTrafficBillingScheduler } = await import('../services/traffic-billing-scheduler.js')
  startTrafficBillingScheduler()

  const { startHourlyBillingScheduler } = await import('../services/hourly-billing-scheduler.js')
  startHourlyBillingScheduler()

  // 启动自动快照/备份调度器
  const { startAutoPolicyScheduler } = await import('../services/auto-policy-scheduler.js')
  startAutoPolicyScheduler()

  // 启动计费调度器（自动续费、到期封停、到期删除、到期提醒）
  const { startBillingScheduler } = await import('../services/billing-scheduler.js')
  startBillingScheduler()

  // 启动托管余额调度器（解冻）
  const { startHostingScheduler } = await import('../services/hosting-scheduler.js')
  startHostingScheduler()

  // 启动实例状态同步调度器
  const { startStatusScheduler } = await import('../services/status-scheduler.js')
  startStatusScheduler()

  // 主动探测 Incus 节点健康状态，连续失败自动离线、恢复后自动上线
  const { startHostHealthMonitor } = await import('../services/host-health-monitor.js')
  startHostHealthMonitor()

  // 启动实例操作任务调度器
  const { cleanupStaleTasks: cleanupStaleInstanceTasks, startInstanceTaskWorker } = await import('../workers/instanceTaskWorker.js')
  await cleanupStaleInstanceTasks()
  startInstanceTaskWorker()
  console.log('⚙️ 实例操作任务调度器已启动')

  // 启动宿主机通知邮件队列 Worker
  const {
    cleanupStaleHostNotificationEmailTasks,
    startHostNotificationEmailWorker
  } = await import('../workers/hostNotificationEmailWorker.js')
  const staleHostNotificationEmailTasks = await cleanupStaleHostNotificationEmailTasks()
  if (staleHostNotificationEmailTasks > 0) {
    console.log(`📧 重新入队了 ${staleHostNotificationEmailTasks} 个宿主机通知邮件任务`)
  }
  startHostNotificationEmailWorker()
  console.log('📧 宿主机通知邮件队列已启动')

  // 启动终端会话清理任务
  const { startSessionCleanup } = await import('../lib/terminal-proxy.js')
  startSessionCleanup()
  console.log('🖥️ 终端会话清理任务已启动')

  // 清理卡住的转移 processing 状态
  const { cleanupStaleTransfers, cleanupTimeoutTransfers } = await import('../db/transfers.js')
  const staleTransfers = await cleanupStaleTransfers()
  if (staleTransfers > 0) {
    console.log(`🔄 清理了 ${staleTransfers} 个卡住的转移请求`)
  }
  // 定期检查超时的 processing 状态（每5分钟）
  setInterval(async () => {
    try {
      const count = await cleanupTimeoutTransfers()
      if (count > 0) {
        console.log(`🔄 清理了 ${count} 个超时的转移请求`)
      }
    } catch (err) {
      console.error('转移超时清理失败:', err)
    }
  }, 5 * 60 * 1000) // 5分钟

  // 启动创建超时清理任务（清理10分钟仍处于创建中的实例）
  const db = await import('../db/index.js')
  const { getStuckCreatingInstances, getHostById } = db
  const { createLog } = await import('../db/logs.js')
  const { cleanupAndSettleFailedProvision } = await import('./provisioning-cleanup.js')
  const CREATE_TIMEOUT_MS = 10 * 60 * 1000 // 10分钟
  const CREATE_TIMEOUT_CHECK_INTERVAL = 2 * 60 * 1000 // 每2分钟检查一次

  const runCreateTimeoutCleanup = async () => {
    try {
      const stuckInstances = await getStuckCreatingInstances(CREATE_TIMEOUT_MS)

      for (const instance of stuckInstances) {
        console.log(`[CreateTimeout] 清理超时创建实例: ${instance.name} (ID: ${instance.id})`)

        const host = await getHostById(instance.host_id)
        if (!host) {
          console.error(`[CreateTimeout] 实例 ${instance.name} 的宿主机不存在，保留扣款与资源预占`)
          continue
        }

        // 先认领清理状态并确认 Incus 返回 404，再执行退款和资源回滚。
        // 清理失败时保留 creating + cleanup_pending，下一轮继续重试。
        const cleanup = await cleanupAndSettleFailedProvision({
          instanceId: instance.id,
          instanceName: instance.incus_id,
          host,
          reason: '创建超过 10 分钟未完成',
          resourceRollback: {
            hostId: instance.host_id,
            cpu: instance.cpu,
            memory: instance.memory,
            disk: instance.disk,
            portCount: ['nat', 'nat_ipv6', 'nat_ipv6_nat', 'ipv6_nat', 'ipv6_only'].includes(instance.network_mode)
              ? (instance.port_limit || 0)
              : 0
          },
          reclaimPendingBefore: new Date(Date.now() - CREATE_TIMEOUT_MS)
        })

        if (!cleanup.claimed) {
          if (cleanup.error) {
            console.error(`[CreateTimeout] 实例 ${instance.name} 无法认领清理，暂不退款:`, cleanup.error)
          } else {
            console.log(`[CreateTimeout] 实例 ${instance.name} 已被其他流程处理，跳过`)
          }
          continue
        }

        if (!cleanup.cleaned) {
          console.error(`[CreateTimeout] 实例 ${instance.name} 清理状态未确认，保留扣款与资源预占:`, cleanup.error)
          continue
        }

        const settlement = cleanup.settlement
        if (!settlement?.claimed) {
          console.error(`[CreateTimeout] 实例 ${instance.name} 已确认清理，但数据库结算尚未完成:`, cleanup.error)
          continue
        }

        if (settlement.refundAmount > 0) {
          console.log(`[CreateTimeout] 实例 ${instance.name} 已自动退款 ¥${settlement.refundAmount.toFixed(2)}`)
        }
        console.log(`[CreateTimeout] 实例 ${instance.name} 资源已回滚`)

        // 发送用户通知
        try {
          const { sendNotification } = await import('../lib/notifier.js')
          await sendNotification(instance.user_id, 'instance_create_timeout', {
            instanceName: instance.name,
            hostName: host?.name || undefined
          })
        } catch (notifyErr) {
          console.error(`[CreateTimeout] 发送通知失败:`, notifyErr)
        }

        // 记录日志
        await createLog(
          instance.user_id,
          'instance',
          'instance.create_timeout',
          `Instance "${instance.name}" creation timed out after 10 minutes`,
          'failed',
          { instanceId: instance.id }
        )
      }

      if (stuckInstances.length > 0) {
        console.log(`[CreateTimeout] 清理了 ${stuckInstances.length} 个超时创建实例`)
      }
    } catch (err) {
      console.error('[CreateTimeout] 清理失败:', err)
    }
  }
  setInterval(runCreateTimeoutCleanup, CREATE_TIMEOUT_CHECK_INTERVAL)
  runCreateTimeoutCleanup()
  console.log('⏱️ 创建超时清理任务已启动（10分钟超时）')

  // 删除流程的外部 Incus 操作与账务交易无法放在同一个数据库事务中。
  // 如果远端已删除但退款事务失败，保留 deletion_billing_pending 并由此任务
  // 重试；结算函数本身以退款 billing record / UserDestroyRecord 保证幂等。
  const runDeletionBillingRecovery = async () => {
    const { prisma } = await import('../db/prisma.js')
    const { ensureInstanceDeleted, getIncusClient } = await import('../lib/incus/index.js')
    const { closeHourlyBilling } = await import('./hourly-billing-scheduler.js')
    const pendingInstances = await prisma.instance.findMany({
      where: {
        status: 'deleted',
        deletionBillingPending: true
      },
      select: {
        id: true,
        incusId: true,
        name: true,
        userId: true,
        hostId: true,
        cpu: true,
        memory: true,
        disk: true,
        networkMode: true,
        portLimit: true,
        billingPrice: true,
        billingCycle: true,
        expiresAt: true,
        packagePlanId: true,
        deletionBillingMode: true,
        deletionRefundableValue: true,
        deletionFeeWaiver: true
      },
      orderBy: { updatedAt: 'asc' },
      take: 100
    })

    for (const instance of pendingInstances) {
      try {
        const host = await getHostById(instance.hostId)
        if (!host || host.status !== 'online') {
          console.warn(`[DeletionRecovery] 实例 ${instance.id} 的宿主机不可用，暂不结算退款`)
          continue
        }

        const client = await getIncusClient(host)
        await ensureInstanceDeleted(client, instance.incusId)
        await prisma.instance.updateMany({
          where: { id: instance.id, status: 'deleted', deletionBillingPending: true },
          data: { deletionRemoteDeleted: true }
        })

        if (instance.deletionBillingMode === 'hourly_close') {
          await closeHourlyBilling(instance.id)
          await db.completeHourlyDeletionBilling(instance.id)
          console.log(`[DeletionRecovery] 实例 ${instance.id} 已完成按小时计费关闭与预付款释放`)
          continue
        }

        const instanceBilling = {
          id: instance.id,
          userId: instance.userId,
          hostId: instance.hostId,
          name: instance.name
        }

        if (instance.deletionBillingMode === 'user_destroy') {
          let refundableValue = instance.deletionRefundableValue === null
            ? 0
            : Number(instance.deletionRefundableValue)
          if (instance.deletionRefundableValue === null) {
            const quote = await db.calculateInstanceRemainingRefundQuote({
              id: instance.id,
              billingPrice: instance.billingPrice,
              billingCycle: instance.billingCycle,
              expiresAt: instance.expiresAt,
              packagePlanId: instance.packagePlanId
            })
            refundableValue = quote.refundableValue
          }
          const settlement = await db.settleUserDestroyBilling({
            requestUserId: instance.userId,
            instance: instanceBilling,
            refundableValue,
            feeWaiver: instance.deletionFeeWaiver
          })
          console.log(`[DeletionRecovery] 实例 ${instance.id} 已完成用户退款结算 ¥${settlement.refundAmount.toFixed(2)}`)
        } else if (instance.deletionBillingMode === 'privileged_delete') {
          const refundAmount = await db.settlePrivilegedDeletionBilling({
            instance: instanceBilling,
            requestedRefundAmount: Number(instance.deletionRefundableValue || 0),
            remark: `删除实例退款重试：${instance.name}`
          })
          console.log(`[DeletionRecovery] 实例 ${instance.id} 已完成管理端退款结算 ¥${refundAmount.toFixed(2)}`)
        } else {
          console.error(`[DeletionRecovery] 实例 ${instance.id} 的删除结算模式无效，保留待处理状态`)
        }
      } catch (error) {
        console.error(`[DeletionRecovery] 实例 ${instance.id} 删除/退款结算仍未完成:`, error)
      }
    }
  }

  void runDeletionBillingRecovery()
  setInterval(() => {
    void runDeletionBillingRecovery()
  }, CREATE_TIMEOUT_CHECK_INTERVAL)
  console.log('💰 删除退款结算恢复任务已启动（每2分钟）')

  // 启动实例任务清理定时任务（清理7天前的已完成任务）
  const { cleanupOldTasks } = await import('../db/instance-tasks.js')
  const runInstanceTaskCleanup = async () => {
    try {
      const deleted = await cleanupOldTasks()
      if (deleted > 0) {
        console.log(`⚙️ 实例任务清理完成，删除 ${deleted} 条过期任务`)
      }
    } catch (err) {
      console.error('实例任务清理失败:', err)
    }
  }
  setInterval(runInstanceTaskCleanup, 24 * 60 * 60 * 1000)
  runInstanceTaskCleanup()

  // 启动站内信清理定时任务（30 天前的消息）
  const { cleanupOldMessages } = await import('../db/inbox.js')
  const runInboxCleanup = async () => {
    try {
      const deleted = await cleanupOldMessages(30)
      if (deleted > 0) {
        console.log(`📨 站内信清理完成，删除 ${deleted} 条过期消息`)
      }
    } catch (err) {
      console.error('站内信清理失败:', err)
    }
  }
  setInterval(runInboxCleanup, 24 * 60 * 60 * 1000)
  runInboxCleanup()

  // 启动系统健康监控
  const { startSystemMonitor } = await import('../services/system-monitor.js')
  startSystemMonitor()

  // 启动工单自动关闭调度器
  const { startTicketAutoCloseScheduler } = await import('../services/ticket-auto-close-scheduler.js')
  startTicketAutoCloseScheduler()

  // 启动节点连接地址监控
  const { startHostAddressMonitor } = await import('../services/host-address-monitor.js')
  startHostAddressMonitor()
}

/**
 * 停止调度器（优雅关闭时调用）
 */
export async function stopSchedulers(): Promise<void> {
  const { stopSessionCleanup } = await import('../lib/terminal-proxy.js')
  stopSessionCleanup()

  const { stopHostNotificationEmailWorker } = await import('../workers/hostNotificationEmailWorker.js')
  stopHostNotificationEmailWorker()

  // 关闭所有活跃终端会话
  const { closeAllSessions } = await import('../lib/terminal-proxy.js')
  const closedSessions = closeAllSessions('Server shutdown')
  if (closedSessions > 0) {
    console.log(`🖥️ 关闭了 ${closedSessions} 个终端会话`)
  }
}
