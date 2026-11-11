import { prisma } from '../db/prisma.js'
import * as db from '../db/index.js'
import { ensureInstanceDeleted, getIncusClient } from '../lib/incus/index.js'
import { withInstanceRemoteOperationLock } from './instance-remote-operation-lock.js'
import { throwIfRemoteOperationAborted } from './remote-operation-abort.js'
import type { Prisma } from '@prisma/client'

export const deletionBillingRecoveryWhere: Prisma.InstanceWhereInput = {
  status: 'deleted', deletionBillingPending: true,
  retiredTombstone: { is: null }
}

type Host = NonNullable<Awaited<ReturnType<typeof db.getHostById>>>
export interface DeletionBillingRecoveryRemote {
  ensureDeleted(host: Host, incusId: string): Promise<void>
}
const defaultRemote: DeletionBillingRecoveryRemote = {
  async ensureDeleted(host, incusId) {
    await ensureInstanceDeleted(await getIncusClient(host), incusId)
  }
}

/** Legacy `deleted` claims predate the durable deleting state. Serialize the
 * complete remote/settlement sequence with new destroy requests and re-read
 * the row under the session lock; never act on the scheduler's stale list. */
export async function recoverDeletionBilling(instanceId: number, remote: DeletionBillingRecoveryRemote = defaultRemote): Promise<'busy' | 'skipped' | 'settled'> {
  const locked = await withInstanceRemoteOperationLock(instanceId, async () => {
    const instance = await prisma.instance.findUnique({ where: { id: instanceId }, select: {
      id: true, incusId: true, name: true, userId: true, hostId: true,
      billingPrice: true, billingCycle: true, expiresAt: true, packagePlanId: true,
      status: true, billingMode: true, trafficBillingMode: true, deletionBillingPending: true, deletionBillingMode: true, deletionRemoteDeleted: true,
      deletionRefundableValue: true, deletionFeeWaiver: true
    } })
    if (!instance || instance.status !== 'deleted' || !instance.deletionBillingPending) return 'skipped' as const
    // The retirement writer acquires the same 4112 lock. Never connect to a
    // retired host or settle automatically after logical retirement.
    if (await prisma.retiredInstanceTombstone.findUnique({ where: { instanceId }, select: { instanceId: true } })) return 'skipped' as const
    // Historical claims do not prove the final running interval or traffic.
    // Never infer those facts from an old status or a confirmed absence.
    if (instance.billingMode === 'hourly' || instance.trafficBillingMode === 'usage'
      || instance.deletionBillingMode === 'hourly_close' || instance.deletionBillingMode === 'user_destroy') return 'skipped' as const
    if (instance.deletionBillingMode !== 'privileged_delete') return 'skipped' as const
    if (!instance.deletionRemoteDeleted) {
      const host = await db.getHostById(instance.hostId)
      if (!host || host.status !== 'online') return 'skipped' as const
      await remote.ensureDeleted(host, instance.incusId)
      throwIfRemoteOperationAborted()
      const marked = await prisma.instance.updateMany({
        where: { id: instance.id, status: 'deleted', deletionBillingPending: true,
          deletionBillingMode: instance.deletionBillingMode, hostId: instance.hostId, userId: instance.userId, incusId: instance.incusId },
        data: { deletionRemoteDeleted: true }
      })
      if (marked.count !== 1) return 'skipped' as const
    }
    throwIfRemoteOperationAborted()

    if (instance.deletionBillingMode === 'privileged_delete') {
      await db.settlePrivilegedDeletionBilling({
        instance: { id: instance.id, userId: instance.userId, hostId: instance.hostId, name: instance.name },
        requestedRefundAmount: Number(instance.deletionRefundableValue || 0),
        remark: `删除实例退款重试：${instance.name}`
      })
    } else throw new Error('Invalid deletion billing mode')
    return 'settled' as const
  })
  return locked.acquired ? locked.value : 'busy'
}
