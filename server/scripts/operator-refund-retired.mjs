/** Refund explicitly retired, already-authorised instances. Dry-run by default.
 * The database, never this script's arguments, supplies all monetary values.
 * Intended for administrator-owned hosts with complete, unmigrated billing
 * histories and no earlier refunds; ambiguous cases remain pending.
 */
import { createHash } from 'node:crypto'
import pg from 'pg'

const params = new Map()
for (const arg of process.argv.slice(2)) {
  const match = /^--(source|count|apply)=([^=]+)$/.exec(arg)
  if (!match || params.has(match[1])) throw new Error('Invalid argument')
  params.set(match[1], match[2])
}
const source = params.get('source'), apply = params.get('apply'), count = Number(params.get('count'))
if (!/^[a-f0-9]{64}$/.test(source ?? '') || !Number.isSafeInteger(count) || count < 1 || count > 100
  || (apply !== undefined && !/^[a-f0-9]{64}$/.test(apply))) throw new Error('Invalid scope or digest')
if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required')
const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL, max: 1, connectionTimeoutMillis: 5000 })
const db = await pool.connect()
let committed = false

async function snapshot() {
  const result = await db.query(`SELECT i.id, i.user_id, i.host_id, i.version, i.status::text,
    i.deletion_requested_at, i.expires_at, i.deletion_billing_pending, i.deletion_billing_mode,
    i.deletion_remote_deleted, t.retirement_digest, t.original_billing_mode, u.role::text AS host_owner_role,
    (SELECT count(*)::int FROM hosting_balance_logs hl WHERE hl.related_id=i.id AND hl.type='income') AS hosting_income_count,
    (SELECT count(*)::int FROM instance_billing_records r WHERE r.instance_id=i.id AND r.type='refund') AS refund_count,
    (SELECT count(*)::int FROM instance_transfers x WHERE x.instance_id=i.id AND x.status='accepted') AS transfer_count,
    (SELECT count(*)::int FROM inbox_messages m WHERE m.user_id=i.user_id AND m.event_type='instance_migrated'
      AND m.data->>'instanceId'=i.id::text) AS migration_count,
    (SELECT count(*)::int FROM instance_billing_records b WHERE b.instance_id=i.id
      AND b.type IN ('newPurchase','renew','upgrade') AND b.amount>0 AND
      (b.user_id<>i.user_id OR b.period_end<=b.period_start)) AS invalid_count,
    (SELECT count(*)::int FROM instance_billing_records b WHERE b.instance_id=i.id
      AND b.type IN ('newPurchase','renew','upgrade') AND b.amount>0) AS paid_count,
    (SELECT round(COALESCE(sum(CASE WHEN i.expires_at<=i.deletion_requested_at THEN 0 ELSE b.amount *
      greatest(0::numeric,least(1::numeric,extract(epoch from (b.period_end-i.deletion_requested_at))::numeric /
      NULLIF(extract(epoch from (b.period_end-b.period_start))::numeric,0))) END),0),2)::text
      FROM instance_billing_records b WHERE b.instance_id=i.id AND b.type IN ('newPurchase','renew','upgrade') AND b.amount>0) AS refund_amount,
    (SELECT md5(COALESCE(string_agg(row_to_json(b)::text, '|' ORDER BY b.id),'')) FROM instance_billing_records b WHERE b.instance_id=i.id) AS billing_digest
    FROM instances i JOIN retired_instance_tombstones t ON t.instance_id=i.id AND t.host_id=i.host_id
    JOIN hosts h ON h.id=i.host_id JOIN users u ON u.id=h.user_id
    WHERE t.source_digest=$1 AND i.deletion_billing_pending ORDER BY i.id`, [source])
  if (result.rowCount !== count || result.rows.some(r => r.status !== 'deleted' || r.deletion_remote_deleted
    || r.deletion_billing_mode !== 'manual_retired_host' || r.original_billing_mode !== 'privileged_delete'
    || r.host_owner_role !== 'admin' || r.hosting_income_count || r.refund_count || r.transfer_count || r.migration_count
    || r.invalid_count || !r.paid_count || !r.deletion_requested_at || !r.expires_at)) throw new Error('Billing evidence or scope requires manual review')
  return { rows: result.rows, digest: createHash('sha256').update(JSON.stringify(result.rows)).digest('hex') }
}

try {
  await db.query(apply ? 'BEGIN' : 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY')
  await db.query("SET LOCAL statement_timeout = '10s'")
  await db.query("SET LOCAL lock_timeout = '3s'")
  const first = await snapshot()
  if (!apply) {
    await db.query('ROLLBACK')
    committed = true
    console.log(JSON.stringify({ result: 'dry_run', count, digest: first.digest, total: first.rows.reduce((n, r) => n + BigInt(r.refund_amount.replace('.', '')), 0n).toString() }))
  } else {
    if (first.digest !== apply) throw new Error('Billing snapshot changed')
    for (const row of first.rows) for (const namespace of [4112, 4106]) {
      const lock = await db.query('SELECT pg_try_advisory_xact_lock($1,$2) AS ok', [namespace, row.id])
      if (!lock.rows[0].ok) throw new Error('Instance operation is in progress')
    }
    for (const id of [...new Set(first.rows.map(r => r.user_id))].sort((a, b) => a - b)) {
      const lock = await db.query('SELECT pg_try_advisory_xact_lock(4110,$1) AS ok', [id])
      if (!lock.rows[0].ok) throw new Error('User balance operation is in progress')
    }
    await db.query('SELECT id FROM instances WHERE id = ANY($1::int[]) ORDER BY id FOR UPDATE', [first.rows.map(r => r.id)])
    const locked = await snapshot()
    if (locked.digest !== apply) throw new Error('Locked billing snapshot changed')
    for (const row of locked.rows) {
      if (row.refund_amount !== '0.00') {
        const before = await db.query('SELECT balance FROM users WHERE id=$1 FOR UPDATE', [row.user_id])
        if (before.rowCount !== 1) throw new Error('User missing')
        const after = await db.query('UPDATE users SET balance=balance+$2::numeric WHERE id=$1 RETURNING balance', [row.user_id, row.refund_amount])
        const log = await db.query(`INSERT INTO balance_logs (user_id,type,amount,balance_before,balance_after,instance_id,remark,created_at)
          VALUES ($1,'refund',$2,$3,$4,$5,'retired host prorated refund',now()) RETURNING id`, [row.user_id, row.refund_amount, before.rows[0].balance, after.rows[0].balance, row.id])
        await db.query(`INSERT INTO instance_billing_records (instance_id,user_id,type,amount,months,period_start,period_end,balance_log_id,remark,created_at)
          VALUES ($1,$2,'refund',-$3::numeric,0,now(),now(),$4,'retired host prorated refund',now())`, [row.id, row.user_id, row.refund_amount, log.rows[0].id])
      }
      const updated = await db.query(`UPDATE instances SET deletion_billing_pending=false, deletion_billing_mode=NULL, updated_at=now()
        WHERE id=$1 AND deletion_billing_pending=true AND deletion_billing_mode='manual_retired_host' AND deletion_remote_deleted=false`, [row.id])
      if (updated.rowCount !== 1) throw new Error('Billing state changed')
      await db.query(`INSERT INTO logs (user_id,instance_id,module,action,content,result,created_at)
        VALUES (NULL,$1,'instance','instance.retired_prorated_refund',$2,'success',now())`, [row.id, JSON.stringify({ sourceDigest: source, snapshotDigest: apply, amount: row.refund_amount })])
    }
    await db.query('COMMIT')
    committed = true
    console.log(JSON.stringify({ result: 'refunded', count }))
  }
} catch (error) {
  if (!committed) await db.query('ROLLBACK').catch(() => {})
  console.error(error instanceof Error ? error.message : 'Refund failed')
  process.exitCode = 1
} finally {
  db.release()
  await pool.end()
}
