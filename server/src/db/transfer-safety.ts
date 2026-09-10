import type { Prisma } from '@prisma/client'
import { Decimal } from '@prisma/client/runtime/client'
import {
  INSTANCE_OPERATION_LOCK_NAMESPACE,
  USER_BALANCE_LOCK_NAMESPACE,
  advisoryTransactionLock
} from './advisory-locks.js'

type TransferExecutionData = {
  transferId: number
  instanceId: number
  fromUserId: number
  toUserId: number
  newInstanceName: string
  newIncusId: string
  oldIncusId: string
  instanceVersion: number
  claimToken: string
}

export type CleanupSnapshot = {
  proxySiteIds: number[]
  portMappingIds: number[]
  snapshotIds: number[]
  backupIds: number[]
  snapshotPolicyIds: number[]
  backupPolicyIds: number[]
}

export async function assertCurrentInstanceOwner(tx: Prisma.TransactionClient, instanceId: number, fromUserId: number): Promise<void> {
  const instance = await tx.instance.findFirst({ where: { id: instanceId, userId: fromUserId }, select: { id: true } })
  if (!instance) throw new Error('TRANSFER_INSTANCE_OWNER_CHANGED')
}

export async function debitTransferFee(tx: Prisma.TransactionClient, data: {
  transferId: number
  userId: number
  instanceId: number
  instanceName: string
  fee: Decimal
}): Promise<void> {
  await advisoryTransactionLock(tx, USER_BALANCE_LOCK_NAMESPACE, data.userId)
  const user = await tx.user.findUnique({ where: { id: data.userId }, select: { balance: true } })
  if (!user) throw new Error('USER_NOT_FOUND')
  if (user.balance.lessThan(data.fee)) throw new Error('INSUFFICIENT_BALANCE')
  const balanceAfter = user.balance.minus(data.fee)
  await tx.user.update({ where: { id: data.userId }, data: { balance: { decrement: data.fee } } })
  await tx.balanceLog.create({ data: {
    userId: data.userId, type: 'transfer_fee', amount: data.fee.negated(),
    balanceBefore: user.balance, balanceAfter, instanceId: data.instanceId,
    transferId: data.transferId, remark: `转移实例 "${data.instanceName}" 手续费`
  } })
}

export async function claimTransferTransaction(tx: Prisma.TransactionClient, data: {
  transferId: number
  instanceId: number
  actorUserId: number
  actorRole: 'sender' | 'receiver'
  claimToken: string
  newIncusId: string
  leaseUntil: Date
}): Promise<{ oldIncusId: string; instanceVersion: number; cleanupSnapshot: CleanupSnapshot }> {
  await advisoryTransactionLock(tx, INSTANCE_OPERATION_LOCK_NAMESPACE, data.instanceId)
  const taskCount = await tx.instanceTask.count({ where: { instanceId: data.instanceId, status: { in: ['PENDING', 'PROCESSING'] } } })
  if (taskCount > 0) throw new Error('TRANSFER_INSTANCE_TASK_ACTIVE')
  const instance = await tx.instance.findFirst({ where: { id: data.instanceId, status: { not: 'deleted' } }, select: { id: true, incusId: true, version: true } })
  if (!instance) throw new Error('TRANSFER_INSTANCE_OWNER_CHANGED')
  const [proxySites, portMappings, snapshots, backups, snapshotPolicies, backupPolicies] = await Promise.all([
    tx.proxySite.findMany({ where: { instanceId: data.instanceId }, select: { id: true } }),
    tx.portMapping.findMany({ where: { instanceId: data.instanceId }, select: { id: true } }),
    tx.snapshot.findMany({ where: { instanceId: data.instanceId }, select: { id: true } }),
    tx.backup.findMany({ where: { instanceId: data.instanceId }, select: { id: true } }),
    tx.snapshotPolicy.findMany({ where: { instanceId: data.instanceId }, select: { id: true } }),
    tx.backupPolicy.findMany({ where: { instanceId: data.instanceId }, select: { id: true } })
  ])
  const cleanupSnapshot: CleanupSnapshot = {
    proxySiteIds: proxySites.map(x => x.id), portMappingIds: portMappings.map(x => x.id),
    snapshotIds: snapshots.map(x => x.id), backupIds: backups.map(x => x.id),
    snapshotPolicyIds: snapshotPolicies.map(x => x.id), backupPolicyIds: backupPolicies.map(x => x.id)
  }
  const actorWhere = data.actorRole === 'receiver' ? { toUserId: data.actorUserId } : { fromUserId: data.actorUserId }
  const result = await tx.instanceTransfer.updateMany({
    where: { id: data.transferId, instanceId: data.instanceId, status: 'pending', ...actorWhere },
    data: { status: 'processing', claimToken: data.claimToken, claimExpiresAt: data.leaseUntil, phase: 'claimed', oldIncusId: instance.incusId, newIncusId: data.newIncusId, instanceVersion: instance.version, cleanupSnapshot }
  })
  if (result.count !== 1) throw new Error('TRANSFER_NOT_PENDING')
  return { oldIncusId: instance.incusId, instanceVersion: instance.version, cleanupSnapshot }
}

export async function markTransferPhase(client: Pick<Prisma.TransactionClient, 'instanceTransfer'>, transferId: number, claimToken: string, phase: string): Promise<boolean> {
  const result = await client.instanceTransfer.updateMany({ where: { id: transferId, status: 'processing', claimToken }, data: { phase } })
  return result.count === 1
}

export async function rollbackProcessingTransfer(client: Pick<Prisma.TransactionClient, 'instanceTransfer'>, transferId: number, claimToken: string): Promise<boolean> {
  const result = await client.instanceTransfer.updateMany({
    where: { id: transferId, status: 'processing', claimToken },
    data: { status: 'pending', claimToken: null, claimExpiresAt: null, phase: null, oldIncusId: null, newIncusId: null, instanceVersion: null, cleanupSnapshot: undefined }
  })
  return result.count === 1
}

export async function settleTransferWithRefund(tx: Prisma.TransactionClient, data: {
  transferId: number
  actorUserId: number
  outcome: 'rejected' | 'cancelled'
  reason?: string
}): Promise<boolean> {
  const actor = data.outcome === 'rejected' ? { toUserId: data.actorUserId } : { fromUserId: data.actorUserId }
  const transfer = await tx.instanceTransfer.findFirst({ where: { id: data.transferId, status: 'pending', ...actor }, include: { instance: { select: { name: true } } } })
  if (!transfer) return false
  if (transfer.fee?.greaterThan(0) && !transfer.refundedAt) {
    await advisoryTransactionLock(tx, USER_BALANCE_LOCK_NAMESPACE, transfer.fromUserId)
    const user = await tx.user.findUnique({ where: { id: transfer.fromUserId }, select: { balance: true } })
    if (!user) throw new Error('USER_NOT_FOUND')
    const after = user.balance.plus(transfer.fee)
    await tx.user.update({ where: { id: transfer.fromUserId }, data: { balance: { increment: transfer.fee } } })
    await tx.balanceLog.create({ data: { userId: transfer.fromUserId, type: 'transfer_refund', amount: transfer.fee, balanceBefore: user.balance, balanceAfter: after, instanceId: transfer.instanceId, transferId: transfer.id, remark: `${data.outcome === 'rejected' ? '拒绝' : '取消'}转移实例 "${transfer.instance.name}"，退还手续费` } })
  }
  const now = new Date()
  const result = await tx.instanceTransfer.updateMany({ where: { id: transfer.id, status: 'pending', ...actor }, data: data.outcome === 'rejected'
    ? { status: 'rejected', rejectedAt: now, rejectReason: data.reason ?? null, refundedAt: transfer.fee?.greaterThan(0) ? now : undefined }
    : { status: 'cancelled', cancelledAt: now, refundedAt: transfer.fee?.greaterThan(0) ? now : undefined }
  })
  if (result.count !== 1) throw new Error('TRANSFER_NOT_PENDING')
  return true
}

export async function executeTransferTransaction(tx: Prisma.TransactionClient, data: TransferExecutionData): Promise<void> {
  await advisoryTransactionLock(tx, INSTANCE_OPERATION_LOCK_NAMESPACE, data.instanceId)
  const transfer = await tx.instanceTransfer.findFirst({
    where: { id: data.transferId, status: 'processing', claimToken: data.claimToken, instanceId: data.instanceId, fromUserId: data.fromUserId, toUserId: data.toUserId, oldIncusId: data.oldIncusId, newIncusId: data.newIncusId, instanceVersion: data.instanceVersion },
    select: { id: true, fee: true, fromUserId: true }
  })
  if (!transfer) throw new Error('TRANSFER_EXECUTION_CONFLICT')
  const instanceResult = await tx.instance.updateMany({
    where: { id: data.instanceId, userId: data.fromUserId, incusId: data.oldIncusId, version: data.instanceVersion },
    data: { userId: data.toUserId, name: data.newInstanceName, incusId: data.newIncusId, displayOrder: 0, version: { increment: 1 } }
  })
  if (instanceResult.count !== 1) throw new Error('TRANSFER_INSTANCE_OWNER_CHANGED')
  const now = new Date()
  const transferResult = await tx.instanceTransfer.updateMany({ where: { id: data.transferId, status: 'processing', claimToken: data.claimToken }, data: { status: 'accepted', acceptedAt: now, phase: 'completed', claimExpiresAt: null } })
  if (transferResult.count !== 1) throw new Error('TRANSFER_EXECUTION_CONFLICT')
  if (transfer.fee?.greaterThan(0)) await tx.instanceBillingRecord.create({ data: { transferId: data.transferId, instanceId: data.instanceId, userId: transfer.fromUserId, type: 'transfer_fee', amount: transfer.fee, months: 0, periodStart: now, periodEnd: now, remark: '转移实例手续费' } })
}

export function shouldSuppressMissingIncusDeletion(transfer: { status: string; claimToken: string | null; phase: string | null; claimExpiresAt: Date | null } | null): boolean {
  return Boolean(transfer?.status === 'processing' && transfer.claimToken && ['claimed', 'renaming', 'renamed'].includes(transfer.phase || '') && transfer.claimExpiresAt && transfer.claimExpiresAt > new Date())
}
