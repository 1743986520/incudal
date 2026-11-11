import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { fileURLToPath } from 'node:url'
import pg from 'pg'

// Only the separately created local disposable database may be used.
const url = process.env.DATABASE_URL ?? ''
const parsed = new URL(url)
if (!['postgres:', 'postgresql:'].includes(parsed.protocol) || parsed.pathname !== '/incudal_deletion_test'
  || !['localhost', '127.0.0.1', '::1'].includes(parsed.hostname)
  || process.env.INSTANCE_DELETION_TEST_ALLOW !== '1' || process.env.INSTANCE_DELETION_TEST_DATABASE_URL !== url) {
  throw new Error('Requires the dedicated local deletion test database')
}
const run = promisify(execFile)
const script = fileURLToPath(new URL('./operator-archive-offline-batch.mjs', import.meta.url))
const schema = `archive_fixture_${process.pid}_${Date.now()}`
const admin = new pg.Client({ connectionString: url })
await admin.connect()
await admin.query(`CREATE SCHEMA ${schema}`)
await admin.query(`CREATE TABLE ${schema}.hosts (id int PRIMARY KEY, status text NOT NULL, country_code text NOT NULL, cpu_used int NOT NULL)`)
await admin.query(`CREATE TABLE ${schema}.instances (id int PRIMARY KEY, host_id int NOT NULL, user_id int NOT NULL, incus_id text NOT NULL, version int NOT NULL,
  status text NOT NULL, billing_mode text NOT NULL, traffic_billing_mode text NOT NULL, deletion_billing_pending bool NOT NULL,
  deletion_remote_deleted bool NOT NULL, deletion_requested_at timestamptz NOT NULL, ipv4 text)`)
await admin.query(`CREATE TABLE ${schema}.logs (id serial PRIMARY KEY, user_id int, instance_id int, module text, action text, content text, result text, created_at timestamptz)`)
await admin.query(`CREATE TABLE ${schema}.users (id int PRIMARY KEY, balance int NOT NULL)`)
await admin.query(`CREATE TABLE ${schema}.ip_addresses (instance_id int, address text)`)
await admin.query(`CREATE TABLE ${schema}.port_mappings (instance_id int, port int)`)
await admin.query(`INSERT INTO ${schema}.hosts VALUES (1,'offline','my',10),(2,'offline','my',10),(3,'online','us',20)`)
await admin.query(`INSERT INTO ${schema}.instances SELECT n, 1 + (n % 2), n, 'test-' || n, 1, 'deleting', 'package', 'package', n > 1, false, now(), '192.0.2.' || n FROM generate_series(1,9) n`)
await admin.query(`INSERT INTO ${schema}.instances VALUES (10,3,1,'other',1,'running','package','package',false,false,now(),'192.0.2.10')`)
await admin.query(`INSERT INTO ${schema}.users SELECT n,100 FROM generate_series(1,9) n`)
await admin.query(`INSERT INTO ${schema}.ip_addresses SELECT n,'192.0.2.' || n FROM generate_series(1,9) n`)
await admin.query(`INSERT INTO ${schema}.port_mappings SELECT n,10000+n FROM generate_series(1,9) n`)
const source = 'a'.repeat(64)
const sourceContent = JSON.stringify({ scopeDigest: source, country: 'my', hostCount: 2, instanceCount: 9 })
await admin.query(`INSERT INTO ${schema}.logs (instance_id,action,content) SELECT n,$1,$2 FROM generate_series(1,9) n`, ['instance.operator_approved_pending_delete', sourceContent])
const scopedUrl = new URL(url)
scopedUrl.searchParams.set('options', `-c search_path=${schema}`)
const env = { ...process.env, DATABASE_URL: scopedUrl.toString() }
const scope = ['--country=my', '--hosts=2', '--instances=9', `--source=${source}`]
const invoke = async (...args) => JSON.parse((await run(process.execPath, [script, ...scope, ...args], { env })).stdout.trim())
const countArchive = async () => Number((await admin.query(`SELECT count(*) FROM ${schema}.logs WHERE action='instance.operator_archived_pending_delete'`)).rows[0].count)
try {
  const before = await invoke('--dry-run')
  assert.equal(before.result, 'dry_run')
  assert.equal(await countArchive(), 0)
  await admin.query(`UPDATE ${schema}.hosts SET status='online' WHERE id=1`)
  await assert.rejects(invoke('--dry-run'), /Host scope or availability changed/)
  await admin.query(`UPDATE ${schema}.hosts SET status='offline' WHERE id=1`)
  await admin.query(`UPDATE ${schema}.instances SET deletion_remote_deleted=true WHERE id=1`)
  await assert.rejects(invoke('--dry-run'), /Instance scope or deletion state changed/)
  await admin.query(`UPDATE ${schema}.instances SET deletion_remote_deleted=false WHERE id=1`)
  await admin.query(`UPDATE ${schema}.logs SET content='mismatch' WHERE instance_id=9 AND action='instance.operator_approved_pending_delete'`)
  await assert.rejects(invoke('--dry-run'), /Original approved batch audit is missing or ambiguous/)
  await admin.query(`UPDATE ${schema}.logs SET content=$1 WHERE instance_id=9 AND action='instance.operator_approved_pending_delete'`, [sourceContent])
  await admin.query(`UPDATE ${schema}.instances SET version=version+1 WHERE id=1`)
  await assert.rejects(invoke(`--apply=${before.digest}`), /Preview digest changed/)
  await admin.query(`UPDATE ${schema}.instances SET version=version-1 WHERE id=1`)
  const preview = await invoke()
  await admin.query('SELECT pg_advisory_lock(4112,1)')
  await assert.rejects(invoke(`--apply=${preview.digest}`), /operation is in progress/)
  await admin.query('SELECT pg_advisory_unlock(4112,1)')
  assert.equal(await countArchive(), 0)
  // Force a failure at the last insert: every earlier marker must roll back.
  await admin.query(`ALTER TABLE ${schema}.logs ADD CONSTRAINT reject_last CHECK (action <> 'instance.operator_archived_pending_delete' OR instance_id <> 9)`)
  await assert.rejects(invoke(`--apply=${preview.digest}`))
  assert.equal(await countArchive(), 0)
  await admin.query(`ALTER TABLE ${schema}.logs DROP CONSTRAINT reject_last`)
  const results = await Promise.allSettled([invoke(`--apply=${preview.digest}`), invoke(`--apply=${preview.digest}`)])
  assert.equal(results.filter(x => x.status === 'fulfilled' && x.value.result === 'archived').length, 1)
  assert.equal((await invoke(`--apply=${preview.digest}`)).result, 'already_applied')
  assert.equal(await countArchive(), 9)
  const unchanged = await admin.query(`SELECT
    (SELECT count(*) FROM ${schema}.instances WHERE id <= 9 AND status='deleting' AND NOT deletion_remote_deleted) AS pending,
    (SELECT count(*) FROM ${schema}.instances WHERE id=10 AND status='running') AS other,
    (SELECT count(*) FROM ${schema}.users WHERE balance=100) AS balances,
    (SELECT count(*) FROM ${schema}.ip_addresses) AS ips,
    (SELECT count(*) FROM ${schema}.port_mappings) AS ports,
    (SELECT count(*) FROM ${schema}.hosts WHERE id IN (1,2) AND cpu_used=10) AS hosts`)
  assert.deepEqual(unchanged.rows[0], { pending: '9', other: '1', balances: '9', ips: '9', ports: '9', hosts: '2' })
  console.log('operator archive PostgreSQL integration tests passed')
} finally {
  await admin.end()
}
