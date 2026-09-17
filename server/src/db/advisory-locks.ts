import { Prisma } from '@prisma/client'

export const HOST_TASK_CLAIM_LOCK_NAMESPACE = 4101
export const HOST_NOTIFICATION_EMAIL_LOCK_NAMESPACE = 4102
export const HOST_NOTIFICATION_EMAIL_LOCK_KEY = 1
export const TRANSFER_CREATE_LOCK_NAMESPACE = 4103
export const REDEEM_CODE_LOCK_NAMESPACE = 4104
export const HOSTING_BALANCE_LOG_LOCK_NAMESPACE = 4105
export const INSTANCE_OPERATION_LOCK_NAMESPACE = 4106
export const USER_DESTROY_BILLING_LOCK_NAMESPACE = 4107
export const USER_ADMIN_ROLE_LOCK_NAMESPACE = 4108
export const USER_CREATE_EMAIL_LOCK_NAMESPACE = 4109
export const USER_BALANCE_LOCK_NAMESPACE = 4110
export const OFFICIAL_COUPON_LOCK_NAMESPACE = 4111

/**
 * Blocking pg_advisory_xact_lock calls consume one pool connection per waiter.
 * Under a hot key that can exhaust the entire application pool and prevent the
 * lock owner from finishing. Callers must fail/retry the whole transaction
 * instead of queueing while holding a connection.
 */
export class AdvisoryLockBusyError extends Error {
  readonly code = 'ADVISORY_LOCK_BUSY'

  constructor(namespace: number, key: number) {
    super(`Advisory transaction lock is busy (${namespace}:${key})`)
    this.name = 'AdvisoryLockBusyError'
  }
}

export async function tryAdvisoryTransactionLock(
  tx: Prisma.TransactionClient,
  namespace: number,
  key: number
): Promise<boolean> {
  const result = await tx.$queryRaw<Array<{ locked: boolean }>>(Prisma.sql`
    SELECT pg_try_advisory_xact_lock(${namespace}, ${key}) AS locked
  `)

  return result[0]?.locked === true
}

export async function advisoryTransactionLock(
  tx: Prisma.TransactionClient,
  namespace: number,
  key: number
): Promise<void> {
  const locked = await tryAdvisoryTransactionLock(tx, namespace, key)
  if (!locked) throw new AdvisoryLockBusyError(namespace, key)
}
