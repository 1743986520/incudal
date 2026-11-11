/**
 * System-operator, explicitly approved offline-node pending-deletion batch.
 * Default: read-only preview. --apply=<preview digest> performs one atomic
 * transaction; neither mode prints credentials or customer identities.
 *
 * Example: node operator-queue-offline-batch.mjs --country=my --hosts=2 --instances=9
 *          node operator-queue-offline-batch.mjs --country=my --hosts=2 --instances=9 --apply=<digest>
 * DATABASE_URL is read from the environment, never from command arguments.
 */
import { createHash } from 'node:crypto'
import pg from 'pg'

const rawArgs = process.argv.slice(2)
const dryRunFlag = rawArgs.includes('--dry-run')
const pairs = rawArgs.filter(arg => arg !== '--dry-run').map(arg => {
  const match = /^--(country|hosts|instances|apply)=([^=]+)$/.exec(arg)
  if (!match) throw new Error('Invalid argument')
  return [match[1], match[2]]
})
const args = Object.fromEntries(pairs)
if (new Set(pairs.map(([key]) => key)).size !== pairs.length || (dryRunFlag && args.apply !== undefined)) throw new Error('Conflicting arguments')
const country = args.country?.toLowerCase()
const hostCount = Number(args.hosts), instanceCount = Number(args.instances)
if (!/^[a-z]{2}$/.test(country ?? '') || !Number.isSafeInteger(hostCount) || hostCount < 1 || hostCount > 100
  || !Number.isSafeInteger(instanceCount) || instanceCount < 1 || instanceCount > 500
  || (args.apply !== undefined && !/^[a-f0-9]{64}$/.test(args.apply))) throw new Error('Invalid scope or preview digest')
if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required')
const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL, max: 1, connectionTimeoutMillis: 5000 })
const db = await pool.connect()
const applying = args.apply !== undefined
const action = 'instance.operator_approved_pending_delete'
let committed = false

async function snapshot(lockRows = false) {
  const hosts = await db.query(`SELECT id FROM hosts WHERE lower(country_code) = $1 AND status = 'offline' ORDER BY id${lockRows ? ' FOR UPDATE' : ''}`, [country])
  if (hosts.rowCount !== hostCount) throw new Error('Host scope changed; no instances were queued')
  const ids = hosts.rows.map(row => row.id)
  const rows = await db.query(`SELECT i.id, i.host_id, i.user_id, i.incus_id, i.version, i.status::text AS status,
    i.package_plan_id, i.billing_mode::text AS billing_mode, i.traffic_billing_mode::text AS traffic_billing_mode,
    i.provisioning_cleanup_pending, i.deletion_billing_pending, h.user_id AS host_owner_id
    FROM instances i JOIN hosts h ON h.id = i.host_id
    WHERE i.host_id = ANY($1::int[]) AND i.status <> 'deleted' ORDER BY i.id${lockRows ? ' FOR UPDATE OF i' : ''}`, [ids])
  if (rows.rowCount !== instanceCount || rows.rows.some(row => row.status !== 'running' || row.billing_mode !== 'package'
    || row.traffic_billing_mode !== 'package' || row.provisioning_cleanup_pending || row.deletion_billing_pending)) {
    throw new Error('Instance scope or billing state changed; no instances were queued')
  }
  const digest = createHash('sha256').update(JSON.stringify({ country, hosts: ids, instances: rows.rows })).digest('hex')
  return { rows: rows.rows, digest }
}

try {
  await db.query(applying ? 'BEGIN' : 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY')
  await db.query("SET LOCAL statement_timeout = '10s'")
  await db.query("SET LOCAL lock_timeout = '3s'")
  if (applying) {
    // Same digest identifies exactly one previously committed atomic batch.
    const existing = await db.query('SELECT count(DISTINCT instance_id)::int AS count FROM logs WHERE action = $1 AND content = $2', [action, JSON.stringify({ scopeDigest: args.apply, country, hostCount, instanceCount })])
    if (existing.rows[0].count === instanceCount) {
      await db.query('ROLLBACK')
      console.log(JSON.stringify({ result: 'already_applied', hostCount, instanceCount }))
      committed = true
    } else if (existing.rows[0].count !== 0) throw new Error('Partial prior audit detected; manual review required')
  }
  if (!committed) {
    const initial = await snapshot()
    if (!applying) {
      await db.query('ROLLBACK')
      console.log(JSON.stringify({ result: 'dry_run', hostCount, instanceCount, digest: initial.digest }))
      committed = true
    } else {
      if (initial.digest !== args.apply) throw new Error('Preview digest changed; no instances were queued')
      // Match the panel's 4106 transaction lock and 4112 remote-operation lock.
      for (const row of initial.rows) {
        for (const namespace of [4112, 4106]) {
          const result = await db.query('SELECT pg_try_advisory_xact_lock($1, $2) AS locked', [namespace, row.id])
          if (!result.rows[0].locked) throw new Error('Instance operation is in progress; no instances were queued')
        }
      }
      const locked = await snapshot(true)
      if (locked.digest !== args.apply) throw new Error('Locked scope changed; no instances were queued')
      for (const row of locked.rows) {
        const active = await db.query(`SELECT EXISTS(SELECT 1 FROM instance_tasks WHERE instance_id = $1 AND status IN ('PENDING','PROCESSING')) OR
          EXISTS(SELECT 1 FROM restore_tasks WHERE instance_id = $1 AND status IN ('PENDING','PROCESSING')) OR
          EXISTS(SELECT 1 FROM backup_upload_tasks WHERE instance_id = $1 AND status IN ('PENDING','PROCESSING')) OR
          EXISTS(SELECT 1 FROM instance_transfers WHERE instance_id = $1 AND status IN ('pending','processing')) AS busy`, [row.id])
        if (active.rows[0].busy) throw new Error('An instance has an active task or transfer; no instances were queued')
        const needsRefund = row.package_plan_id !== null && row.user_id !== row.host_owner_id
        const changed = await db.query(`UPDATE instances SET status = 'deleting', version = version + 1, updated_at = now(),
          deletion_original_status = 'running', deletion_requested_at = now(), deletion_last_attempt_at = NULL, deletion_requested_by_id = NULL,
          deletion_reason = NULL, deletion_remote_deleted = false, deletion_billing_pending = $2,
          deletion_billing_mode = $3, deletion_refundable_value = NULL, deletion_fee_waiver = false
          WHERE id = $1 AND version = $4 AND status = 'running'`, [row.id, needsRefund, needsRefund ? 'privileged_delete' : null, row.version])
        if (changed.rowCount !== 1) throw new Error('Instance state changed; no instances were queued')
        await db.query(`INSERT INTO logs (user_id, instance_id, module, action, content, result, created_at)
          VALUES (NULL, $1, 'instance', $2, $3, 'success', now())`, [row.id, action, JSON.stringify({ scopeDigest: args.apply, country, hostCount, instanceCount })])
      }
      await db.query('COMMIT')
      committed = true
      console.log(JSON.stringify({ result: 'queued', hostCount, instanceCount }))
    }
  }
} catch (error) {
  if (!committed) await db.query('ROLLBACK').catch(() => {})
  console.error(error instanceof Error ? error.message : 'Batch failed')
  process.exitCode = 1
} finally {
  db.release()
  await pool.end()
}
