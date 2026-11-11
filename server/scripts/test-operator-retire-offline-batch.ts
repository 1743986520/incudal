import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { fileURLToPath } from 'node:url'
import pg from 'pg'

const url = process.env.DATABASE_URL ?? ''
let valid = false
try {
  const u = new URL(url)
  valid = ['postgres:', 'postgresql:'].includes(u.protocol) && u.pathname === '/incudal_deletion_test'
    && ['localhost', '127.0.0.1', '::1'].includes(u.hostname)
} catch { /* invalid URL */ }
if (!valid || process.env.INSTANCE_DELETION_TEST_ALLOW !== '1' || url !== process.env.INSTANCE_DELETION_TEST_DATABASE_URL) throw new Error('Requires the dedicated local deletion test database')
const { prisma } = await import('../src/db/prisma.js')
const run = promisify(execFile)
const queueScript = fileURLToPath(new URL('./operator-queue-offline-batch.mjs', import.meta.url))
const script = fileURLToPath(new URL('./operator-retire-offline-batch.mjs', import.meta.url))
const existingCountries = new Set((await prisma.host.findMany({ select: { countryCode: true }, distinct: ['countryCode'] })).map(host => host.countryCode.toLowerCase()))
const country = [...'zyxwvutsrqponmlkjihgfedcba'].flatMap(a => [...'zyxwvutsrqponmlkjihgfedcba'].map(b => a + b)).find(code => !existingCountries.has(code))
if (!country) throw new Error('No unused local fixture country code')
const scope = [`--country=${country}`, '--hosts=2', '--instances=9']
const invoke = async (path: string, args: string[]) => JSON.parse((await run(process.execPath, [path, ...scope, ...args], { env: process.env })).stdout.trim())
const tag = `${Date.now()}_${Math.floor(Math.random() * 100000)}`
const ipv6tag = (Date.now() % 65535).toString(16)
const owner = await prisma.user.create({ data: { username: `retire_owner_${tag}`, passwordHash: 'test-only' } })
const pkg = await prisma.package.create({ data: { userId: owner.id, name: `retire_pkg_${tag}`, cpuMax: 100, memoryMax: 1024, diskMax: 2048 } })
const plan = await prisma.packagePlan.create({ data: { packageId: pkg.id, name: 'test', cpu: 10, memory: 128, disk: 512, portLimit: 2, snapshotLimit: 1, backupLimit: 1, siteLimit: 1, trafficLimit: 1000n, price: 100 } })
const hosts = await Promise.all(Array.from({ length: 2 }, (_, index) => prisma.host.create({ data: { userId: owner.id, name: `retire_${tag}_${index}`, countryCode: country, url: 'https://127.0.0.1:1', status: 'offline', cpuUsed: 50, memoryUsed: 640, diskUsed: 2560, natPortsUsedCount: 10 } })))
const otherHost = await prisma.host.create({ data: { userId: owner.id, name: `retire_other_${tag}`, countryCode: 'us', url: 'https://127.0.0.1:1', status: 'offline' } })
const instances = []
for (let i = 0; i < 9; i++) {
  const user = await prisma.user.create({ data: { username: `retire_user_${tag}_${i}`, passwordHash: 'test-only', balance: 10 } })
  const host = hosts[i % 2]!
  const instance = await prisma.instance.create({ data: { userId: user.id, hostId: host.id, incusId: `retire_${tag}_${i}`, name: `retire_${tag}_${i}`, image: 'test', status: 'running', cpu: 10, memory: 128, disk: 512, portLimit: 2, packageId: pkg.id, packagePlanId: i ? plan.id : null, ipv4: `10.248.0.${i + 1}`, ipv6: `2001:db8:${ipv6tag}:${i}::1` } })
  await prisma.portMapping.create({ data: { instanceId: instance.id, hostId: host.id, publicPort: 10000 + i, privatePort: 22 } })
  instances.push(instance)
}
const ids = instances.map(i => i.id)
const outside = await prisma.instance.create({ data: { userId: instances[0]!.userId, hostId: otherHost.id, incusId: `retire_outside_${tag}`, name: `retire_outside_${tag}`, image: 'test', status: 'running', cpu: 1, memory: 64, disk: 64 } })
const logCount = async () => prisma.log.count({ where: { action: 'instance.operator_retired_host_deleted', instanceId: { in: ids } } })
const locker = new pg.Client({ connectionString: url })
await locker.connect()
try {
  const source = await invoke(queueScript, ['--dry-run'])
  assert.equal((await invoke(queueScript, [`--apply=${source.digest}`])).result, 'queued')
  const sourceArg = `--source=${source.digest}`
  const preview = await invoke(script, [sourceArg, '--dry-run'])
  assert.equal(preview.result, 'dry_run')
  assert.equal(await logCount(), 0)
  const sourceLog = await prisma.log.findFirstOrThrow({ where: { instanceId: ids[8], action: 'instance.operator_approved_pending_delete' } })
  await prisma.log.update({ where: { id: sourceLog.id }, data: { result: 'failed' } })
  await assert.rejects(invoke(script, [sourceArg, `--apply=${preview.digest}`]), /Original approved batch audit is missing or ambiguous/)
  await prisma.log.update({ where: { id: sourceLog.id }, data: { result: 'success' } })
  await prisma.log.update({ where: { id: sourceLog.id }, data: { content: 'mismatch' } })
  await assert.rejects(invoke(script, [sourceArg, `--apply=${preview.digest}`]), /Original approved batch audit is missing or ambiguous/)
  await prisma.log.update({ where: { id: sourceLog.id }, data: { content: sourceLog.content } })
  await prisma.host.update({ where: { id: hosts[0]!.id }, data: { status: 'online' } })
  await assert.rejects(invoke(script, [sourceArg, `--apply=${preview.digest}`]), /Host scope or availability changed/)
  await prisma.host.update({ where: { id: hosts[0]!.id }, data: { status: 'offline' } })
  await prisma.instance.update({ where: { id: ids[0]! }, data: { deletionRemoteDeleted: true } })
  await assert.rejects(invoke(script, [sourceArg, `--apply=${preview.digest}`]), /Instance scope or deletion\/billing state changed/)
  await prisma.instance.update({ where: { id: ids[0]! }, data: { deletionRemoteDeleted: false } })
  const ip = await prisma.ipAddress.create({ data: { instanceId: ids[0]!, hostId: hosts[0]!.id, address: `10.247.0.1`, type: 'inet4' } })
  await assert.rejects(invoke(script, [sourceArg, `--apply=${preview.digest}`]), /IP reservation records exist/)
  await prisma.ipAddress.delete({ where: { id: ip.id } })
  await prisma.instance.update({ where: { id: ids[0]! }, data: { version: { increment: 1 } } })
  await assert.rejects(invoke(script, [sourceArg, `--apply=${preview.digest}`]), /Preview digest changed/)
  await prisma.instance.update({ where: { id: ids[0]! }, data: { version: { decrement: 1 } } })
  await locker.query('SELECT pg_advisory_lock(4112,$1)', [ids[0]])
  await assert.rejects(invoke(script, [sourceArg, `--apply=${preview.digest}`]), /operation is in progress/)
  await locker.query('SELECT pg_advisory_unlock(4112,$1)', [ids[0]])
  const last = instances[8]!
  const task = await prisma.instanceTask.create({ data: { instanceId: last.id, hostId: last.hostId, userId: last.userId, taskType: 'stop', status: 'PENDING' } })
  await assert.rejects(invoke(script, [sourceArg, `--apply=${preview.digest}`]), /active task or transfer/)
  assert.equal(await prisma.instance.count({ where: { id: { in: ids }, status: 'deleting' } }), 9)
  assert.equal(await logCount(), 0)
  assert.equal(Number((await locker.query('SELECT count(*) FROM retired_instance_tombstones WHERE instance_id = ANY($1::int[])', [ids])).rows[0].count), 0)
  await prisma.instanceTask.update({ where: { id: task.id }, data: { status: 'FAILED' } })
  const calls = await Promise.allSettled([invoke(script, [sourceArg, `--apply=${preview.digest}`]), invoke(script, [sourceArg, `--apply=${preview.digest}`])])
  assert.equal(calls.filter(call => call.status === 'fulfilled' && call.value.result === 'deleted').length, 1)
  assert.equal((await invoke(script, [sourceArg, `--apply=${preview.digest}`])).result, 'already_applied')
  const retireLog = await prisma.log.findFirstOrThrow({ where: { instanceId: ids[8], action: 'instance.operator_retired_host_deleted' } })
  await prisma.log.update({ where: { id: retireLog.id }, data: { result: 'failed' } })
  await assert.rejects(invoke(script, [sourceArg, `--apply=${preview.digest}`]), /Partial retirement audit/)
  await prisma.log.update({ where: { id: retireLog.id }, data: { result: 'success' } })
  assert.equal(await prisma.instance.count({ where: { id: { in: ids }, status: 'deleted', deletionRemoteDeleted: false } }), 9)
  assert.equal(await prisma.instance.count({ where: { id: { in: ids }, status: 'deleted', deletionBillingPending: true, deletionBillingMode: 'manual_retired_host' } }), 8)
  assert.equal(await prisma.portMapping.count({ where: { instanceId: { in: ids } } }), 9)
  assert.equal(await logCount(), 9)
  assert.equal(Number((await locker.query('SELECT count(*) FROM retired_instance_tombstones WHERE instance_id = ANY($1::int[]) AND remote_deletion_confirmed=false', [ids])).rows[0].count), 9)
  await assert.rejects(locker.query('DELETE FROM instances WHERE id=$1', [ids[0]]), /retired_instance_tombstones/)
  await assert.rejects(locker.query('DELETE FROM hosts WHERE id=$1', [hosts[0]!.id]), /retired_instance_tombstones|foreign key/)
  assert.equal((await prisma.instance.findUniqueOrThrow({ where: { id: outside.id } })).status, 'running')
  for (const item of instances) {
    const row = await prisma.instance.findUniqueOrThrow({ where: { id: item.id } })
    assert.equal(row.ipv4, item.ipv4)
    assert.equal(row.ipv6, item.ipv6)
    assert.equal(Number((await prisma.user.findUniqueOrThrow({ where: { id: item.userId } })).balance), 10)
    assert.equal(await prisma.instanceBillingRecord.count({ where: { instanceId: item.id, type: 'refund' } }), 0)
    assert.equal(await prisma.instance.count({ where: { id: item.id, status: { not: 'deleted' } } }), 0)
    assert.equal(await prisma.instance.count({ where: { ipv6: item.ipv6, status: { not: 'deleted' } } }), 0, 'deleted instances no longer reserve IPv6')
  }
  for (const host of hosts) {
    const row = await prisma.host.findUniqueOrThrow({ where: { id: host.id } })
    assert.deepEqual([row.cpuUsed, row.memoryUsed, row.diskUsed, row.natPortsUsedCount], [50, 640, 2560, 10])
  }
  // Even if a retired host is later marked online, legacy recovery must skip
  // this billing mode before attempting remote deletion or issuing a refund.
  const { recoverDeletionBilling } = await import('../src/services/deletion-billing-recovery.js')
  await prisma.host.updateMany({ where: { id: { in: hosts.map(host => host.id) } }, data: { status: 'online' } })
  let remoteCalls = 0
  for (const item of instances.slice(1)) {
    assert.equal(await recoverDeletionBilling(item.id, { async ensureDeleted() { remoteCalls++ } }), 'skipped')
  }
  assert.equal(remoteCalls, 0)
  for (const item of instances) assert.equal(Number((await prisma.user.findUniqueOrThrow({ where: { id: item.userId } })).balance), 10)
  console.log('operator retired-host deletion PostgreSQL integration tests passed')
} finally {
  await locker.end()
  await prisma.$disconnect()
}
process.exit(0)
