import { createHash } from 'node:crypto'
import { Pool } from 'pg'
import { runWithRemoteOperationAbortSignal } from './remote-operation-abort.js'

// Pending deletion and remote mutations take instance lock 4112 first. Proxy
// operations then take a domain lock (4113), including across instances.
const INSTANCE_REMOTE_OPERATION_LOCK_NAMESPACE = 4112
const DOMAIN_REMOTE_OPERATION_LOCK_NAMESPACE = 4113
const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 4, connectionTimeoutMillis: 5000, idleTimeoutMillis: 30000, allowExitOnIdle: true })

type LockResult<T> = { acquired: false } | { acquired: true; value: T }
type LockKey = readonly [namespace: number, key: number]

function domainLockKey(domain: string): number {
  // Legacy Caddy IDs replaced dots with dashes. Distinct domains which
  // collide under that old mapping must also serialize on the same lock.
  const legacyIdentity = domain.trim().toLowerCase().replace(/\./g, '-')
  return createHash('sha256').update(legacyIdentity).digest().readInt32BE(0)
}

async function withSessionLocks<T>(keys: readonly LockKey[], operation: () => Promise<T>): Promise<LockResult<T>> {
  const connection = await pool.connect()
  const held: LockKey[] = []
  let failed = false
  const controller = new AbortController()
  const onError = () => {
    failed = true
    controller.abort(new Error('Remote-operation lock connection failed'))
  }
  connection.on('error', onError)
  connection.on('end', onError)
  try {
    for (const key of keys) {
      const result = await connection.query<{ locked: boolean }>('SELECT pg_try_advisory_lock($1, $2) AS locked', [...key])
      if (result.rows[0]?.locked !== true) return { acquired: false }
      held.push(key)
    }
    const value = await runWithRemoteOperationAbortSignal(controller.signal, operation)
    if (failed) throw new Error('Remote-operation lock connection failed')
    return { acquired: true, value }
  } finally {
    connection.removeListener('error', onError)
    connection.removeListener('end', onError)
    if (!failed) {
      for (const key of held.reverse()) {
        try { await connection.query('SELECT pg_advisory_unlock($1, $2)', [...key]) }
        catch { failed = true; break }
      }
    }
    connection.release(failed)
  }
}

export async function withInstanceRemoteOperationLock<T>(instanceId: number, operation: () => Promise<T>): Promise<LockResult<T>> {
  return withSessionLocks([[INSTANCE_REMOTE_OPERATION_LOCK_NAMESPACE, instanceId]], operation)
}

export async function withInstanceAndDomainRemoteOperationLock<T>(instanceId: number, domain: string, operation: () => Promise<T>): Promise<LockResult<T>> {
  return withSessionLocks([
    [INSTANCE_REMOTE_OPERATION_LOCK_NAMESPACE, instanceId],
    [DOMAIN_REMOTE_OPERATION_LOCK_NAMESPACE, domainLockKey(domain)]
  ], operation)
}

// Used only when the caller already holds the instance lock (pending worker).
export async function withDomainRemoteOperationLock<T>(domain: string, operation: () => Promise<T>): Promise<LockResult<T>> {
  return withSessionLocks([[DOMAIN_REMOTE_OPERATION_LOCK_NAMESPACE, domainLockKey(domain)]], operation)
}
