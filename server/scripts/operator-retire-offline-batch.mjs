/**
 * Logically close a previously approved offline-host deletion batch. This is
 * not evidence that any remote VM or data was erased. It releases instance
 * quota and the active-instance IPv4/IPv6 uniqueness constraints. Host
 * counters, port mappings, and pending billing are retained for reconciliation.
 *
 * Read-only by default: --country=xx --hosts=2 --instances=9 --source=<digest>
 * Apply a previously verified snapshot: add --apply=<preview digest>.
 * DATABASE_URL is read only from the environment.
 */
import { createHash } from 'node:crypto'
import pg from 'pg'

const rawArgs = process.argv.slice(2)
const dryRunFlag = rawArgs.includes('--dry-run')
const pairs = rawArgs.filter(arg => arg !== '--dry-run').map(arg => {
  const match = /^--(country|hosts|instances|source|apply)=([^=]+)$/.exec(arg)
  if (!match) throw new Error('Invalid argument')
  return [match[1], match[2]]
})
const args = Object.fromEntries(pairs)
if (new Set(pairs.map(([key]) => key)).size !== pairs.length || (dryRunFlag && args.apply !== undefined)) throw new Error('Conflicting arguments')
const country = args.country?.toLowerCase()
const hostCount = Number(args.hosts), instanceCount = Number(args.instances)
const isDigest = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value)
if (!/^[a-z]{2}$/.test(country ?? '') || !Number.isSafeInteger(hostCount) || hostCount < 1 || hostCount > 100
  || !Number.isSafeInteger(instanceCount) || instanceCount < 1 || instanceCount > 500
  || !isDigest(args.source) || (args.apply !== undefined && !isDigest(args.apply))) throw new Error('Invalid scope or digest')
if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required')
const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL, max: 1, connectionTimeoutMillis: 5000 })
const db = await pool.connect()
const applying = args.apply !== undefined
const sourceAction = 'instance.operator_approved_pending_delete'
const retireAction = 'instance.operator_retired_host_deleted'
const sourceContent = JSON.stringify({ scopeDigest: args.source, country, hostCount, instanceCount })
let committed = false

async function originalIds() {
  const audits = await db.query("SELECT instance_id FROM logs WHERE action = $1 AND result = 'success' AND content = $2 ORDER BY instance_id", [sourceAction, sourceContent])
  const ids = audits.rows.map(row => row.instance_id)
  if (ids.length !== instanceCount || new Set(ids).size !== instanceCount || ids.some(id => id === null)) {
    throw new Error('Original approved batch audit is missing or ambiguous; no instances were deleted')
  }
  return ids
}

async function snapshot(ids, lockRows = false) {
  const hosts = await db.query(`SELECT h.id, h.status::text AS status, lower(h.country_code) AS country
    FROM hosts h WHERE h.id IN (SELECT DISTINCT host_id FROM instances WHERE id = ANY($1::int[]))
    ORDER BY h.id${lockRows ? ' FOR UPDATE' : ''}`, [ids])
  if (hosts.rowCount !== hostCount || hosts.rows.some(row => row.status !== 'offline' || row.country !== country)) {
    throw new Error('Host scope or availability changed; no instances were deleted')
  }
  const instances = await db.query(`SELECT id, host_id, user_id, incus_id, version, status::text AS status,
    billing_mode::text AS billing_mode, traffic_billing_mode::text AS traffic_billing_mode,
    deletion_billing_pending, deletion_remote_deleted, deletion_billing_mode, deletion_refundable_value,
    deletion_requested_at, deletion_original_status::text AS deletion_original_status, ipv4, ipv6
    FROM instances WHERE id = ANY($1::int[]) ORDER BY id${lockRows ? ' FOR UPDATE' : ''}`, [ids])
  if (instances.rowCount !== instanceCount || instances.rows.some(row => row.status !== 'deleting' || row.deletion_remote_deleted
    || row.billing_mode !== 'package' || row.traffic_billing_mode !== 'package'
    || (row.deletion_billing_pending ? row.deletion_billing_mode !== 'privileged_delete' : row.deletion_billing_mode !== null))) {
    throw new Error('Instance scope or deletion/billing state changed; no instances were deleted')
  }
  const ips = await db.query('SELECT count(*)::int AS count FROM ip_addresses WHERE instance_id = ANY($1::int[])', [ids])
  if (ips.rows[0].count !== 0) throw new Error('Instance IP reservation records exist; manual review required')
  const digest = createHash('sha256').update(JSON.stringify({ country, source: args.source, hosts: hosts.rows, instances: instances.rows })).digest('hex')
  return { instances: instances.rows, digest }
}

async function alreadyApplied(ids) {
  const result = await db.query("SELECT instance_id, content FROM logs WHERE action = $1 AND result = 'success' AND instance_id = ANY($2::int[]) ORDER BY instance_id", [retireAction, ids])
  if (result.rowCount === 0) return false
  if (result.rowCount !== instanceCount || new Set(result.rows.map(row => row.instance_id)).size !== instanceCount) throw new Error('Partial retirement audit; manual review required')
  for (const row of result.rows) {
    let content
    try { content = JSON.parse(row.content) } catch { throw new Error('Invalid retirement audit; manual review required') }
    if (content.sourceDigest !== args.source || content.retirementDigest !== args.apply || content.country !== country
      || content.hostCount !== hostCount || content.instanceCount !== instanceCount) throw new Error('Conflicting retirement audit; manual review required')
  }
  const state = await db.query(`SELECT count(*)::int AS count FROM instances WHERE id = ANY($1::int[])
    AND status = 'deleted' AND deletion_remote_deleted = false
    AND (NOT deletion_billing_pending OR deletion_billing_mode = 'manual_retired_host')`, [ids])
  if (state.rows[0].count !== instanceCount) throw new Error('Retirement state changed; manual review required')
  const tombstones = await db.query(`SELECT count(*)::int AS count FROM retired_instance_tombstones t
    JOIN instances i ON i.id = t.instance_id AND i.host_id = t.host_id
    WHERE t.instance_id = ANY($1::int[]) AND t.source_digest = $2 AND t.retirement_digest = $3
      AND t.remote_deletion_confirmed = false`, [ids, args.source, args.apply])
  if (tombstones.rows[0].count !== instanceCount) throw new Error('Retirement tombstones are missing or inconsistent; manual review required')
  return true
}

try {
  await db.query(applying ? 'BEGIN' : 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY')
  await db.query("SET LOCAL statement_timeout = '10s'")
  await db.query("SET LOCAL lock_timeout = '3s'")
  const ids = await originalIds()
  if (applying && await alreadyApplied(ids)) {
    await db.query('ROLLBACK')
    console.log(JSON.stringify({ result: 'already_applied', hostCount, instanceCount }))
    committed = true
  } else {
    const initial = await snapshot(ids)
    if (!applying) {
      await db.query('ROLLBACK')
      console.log(JSON.stringify({ result: 'dry_run', hostCount, instanceCount, digest: initial.digest }))
      committed = true
    } else {
      if (initial.digest !== args.apply) throw new Error('Preview digest changed; no instances were deleted')
      for (const id of ids) {
        for (const namespace of [4112, 4106]) {
          const lock = await db.query('SELECT pg_try_advisory_xact_lock($1, $2) AS locked', [namespace, id])
          if (!lock.rows[0].locked) throw new Error('Instance operation is in progress; no instances were deleted')
        }
      }
      const locked = await snapshot(ids, true)
      if (locked.digest !== args.apply) throw new Error('Locked scope changed; no instances were deleted')
      if (await alreadyApplied(ids)) throw new Error('Retirement was concurrently applied; retry to verify')
      for (const row of locked.instances) {
        const busy = await db.query(`SELECT EXISTS(SELECT 1 FROM instance_tasks WHERE instance_id = $1 AND status IN ('PENDING','PROCESSING')) OR
          EXISTS(SELECT 1 FROM restore_tasks WHERE instance_id = $1 AND status IN ('PENDING','PROCESSING')) OR
          EXISTS(SELECT 1 FROM backup_upload_tasks WHERE instance_id = $1 AND status IN ('PENDING','PROCESSING')) OR
          EXISTS(SELECT 1 FROM instance_transfers WHERE instance_id = $1 AND status IN ('pending','processing')) AS busy`, [row.id])
        if (busy.rows[0].busy) throw new Error('An instance has an active task or transfer; no instances were deleted')
        await db.query(`INSERT INTO retired_instance_tombstones
          (instance_id, host_id, source_digest, retirement_digest, original_billing_mode, remote_deletion_confirmed)
          VALUES ($1, $2, $3, $4, $5, false)`, [row.id, row.host_id, args.source, args.apply, row.deletion_billing_mode])
        const changed = await db.query(`UPDATE instances SET status = 'deleted', version = version + 1, updated_at = now(),
          deletion_billing_mode = CASE WHEN deletion_billing_pending THEN 'manual_retired_host' ELSE deletion_billing_mode END
          WHERE id = $1 AND version = $2 AND status = 'deleting' AND deletion_remote_deleted = false`, [row.id, row.version])
        if (changed.rowCount !== 1) throw new Error('Instance state changed; no instances were deleted')
        const content = JSON.stringify({ sourceDigest: args.source, retirementDigest: args.apply, country, hostCount, instanceCount,
          originalVersion: row.version, originalBillingMode: row.deletion_billing_mode, originalRefundableValue: row.deletion_refundable_value,
          remoteDeletionConfirmed: false, accountingPending: row.deletion_billing_pending })
        await db.query(`INSERT INTO logs (user_id, instance_id, module, action, content, result, created_at)
          VALUES (NULL, $1, 'instance', $2, $3, 'success', now())`, [row.id, retireAction, content])
      }
      await db.query('COMMIT')
      committed = true
      console.log(JSON.stringify({ result: 'deleted', hostCount, instanceCount }))
    }
  }
} catch (error) {
  if (!committed) await db.query('ROLLBACK').catch(() => {})
  console.error(error instanceof Error ? error.message : 'Retirement failed')
  process.exitCode = 1
} finally {
  db.release()
  await pool.end()
}
