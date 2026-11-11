/**
 * Archive an explicitly approved operator-queued offline batch from normal
 * lists without changing deletion, accounting, address or resource state.
 * Defaults to a read-only preview. DATABASE_URL is read from the environment.
 *
 * node operator-archive-offline-batch.mjs --country=my --hosts=2 --instances=9 --source=<queue digest>
 * node operator-archive-offline-batch.mjs --country=my --hosts=2 --instances=9 --source=<queue digest> --apply=<preview digest>
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
const archiveAction = 'instance.operator_archived_pending_delete'
const sourceContent = JSON.stringify({ scopeDigest: args.source, country, hostCount, instanceCount })
let committed = false

async function targets(lockRows = false) {
  const audits = await db.query('SELECT instance_id FROM logs WHERE action = $1 AND content = $2 ORDER BY instance_id', [sourceAction, sourceContent])
  const ids = audits.rows.map(row => row.instance_id)
  if (ids.length !== instanceCount || new Set(ids).size !== instanceCount || ids.some(id => id === null)) {
    throw new Error('Original approved batch audit is missing or ambiguous; no instances were archived')
  }
  const hosts = await db.query(`SELECT h.id, h.status::text AS status, lower(h.country_code) AS country
    FROM hosts h WHERE h.id IN (SELECT DISTINCT host_id FROM instances WHERE id = ANY($1::int[]))
    ORDER BY h.id${lockRows ? ' FOR UPDATE' : ''}`, [ids])
  if (hosts.rowCount !== hostCount || hosts.rows.some(row => row.status !== 'offline' || row.country !== country)) {
    throw new Error('Host scope or availability changed; no instances were archived')
  }
  const instances = await db.query(`SELECT id, host_id, user_id, incus_id, version, status::text AS status,
    billing_mode::text AS billing_mode, traffic_billing_mode::text AS traffic_billing_mode,
    deletion_billing_pending, deletion_remote_deleted, deletion_requested_at
    FROM instances WHERE id = ANY($1::int[]) ORDER BY id${lockRows ? ' FOR UPDATE' : ''}`, [ids])
  if (instances.rowCount !== instanceCount || instances.rows.some(row => row.status !== 'deleting' || row.deletion_remote_deleted)) {
    throw new Error('Instance scope or deletion state changed; no instances were archived')
  }
  const digest = createHash('sha256').update(JSON.stringify({ country, source: args.source, hosts: hosts.rows, instances: instances.rows })).digest('hex')
  return { ids, digest }
}

async function existingArchive(ids) {
  const result = await db.query('SELECT instance_id, content FROM logs WHERE action = $1 AND instance_id = ANY($2::int[]) ORDER BY instance_id', [archiveAction, ids])
  if (result.rowCount === 0) return false
  const expected = JSON.stringify({ sourceDigest: args.source, archiveDigest: args.apply, country, hostCount, instanceCount })
  if (result.rowCount !== instanceCount || new Set(result.rows.map(row => row.instance_id)).size !== instanceCount
    || result.rows.some(row => row.content !== expected)) throw new Error('Partial or conflicting archive audit; manual review required')
  return true
}

try {
  await db.query(applying ? 'BEGIN' : 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY')
  await db.query("SET LOCAL statement_timeout = '10s'")
  await db.query("SET LOCAL lock_timeout = '3s'")
  const initial = await targets()
  if (!applying) {
    await db.query('ROLLBACK')
    console.log(JSON.stringify({ result: 'dry_run', hostCount, instanceCount, digest: initial.digest }))
    committed = true
  } else if (await existingArchive(initial.ids)) {
    await db.query('ROLLBACK')
    console.log(JSON.stringify({ result: 'already_applied', hostCount, instanceCount }))
    committed = true
  } else {
    if (initial.digest !== args.apply) throw new Error('Preview digest changed; no instances were archived')
    // The same ordered locks used by deletion and remote instance operations.
    for (const id of initial.ids) {
      for (const namespace of [4112, 4106]) {
        const result = await db.query('SELECT pg_try_advisory_xact_lock($1, $2) AS locked', [namespace, id])
        if (!result.rows[0].locked) throw new Error('Instance operation is in progress; no instances were archived')
      }
    }
    const locked = await targets(true)
    if (locked.digest !== args.apply) throw new Error('Locked scope changed; no instances were archived')
    if (await existingArchive(locked.ids)) throw new Error('Archive was concurrently applied; retry to verify')
    const content = JSON.stringify({ sourceDigest: args.source, archiveDigest: args.apply, country, hostCount, instanceCount })
    for (const id of locked.ids) {
      await db.query(`INSERT INTO logs (user_id, instance_id, module, action, content, result, created_at)
        VALUES (NULL, $1, 'instance', $2, $3, 'success', now())`, [id, archiveAction, content])
    }
    await db.query('COMMIT')
    committed = true
    console.log(JSON.stringify({ result: 'archived', hostCount, instanceCount }))
  }
} catch (error) {
  if (!committed) await db.query('ROLLBACK').catch(() => {})
  console.error(error instanceof Error ? error.message : 'Archive failed')
  process.exitCode = 1
} finally {
  db.release()
  await pool.end()
}
