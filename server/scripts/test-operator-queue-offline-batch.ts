import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { fileURLToPath } from 'node:url'

const url = process.env.DATABASE_URL ?? ''
let valid = false
try {
  const u = new URL(url), p = u.hostname.split('.').map(Number)
  const ipv4 = p.length === 4 && p.every(n => Number.isInteger(n) && n >= 0 && n <= 255)
  valid = ['postgres:', 'postgresql:'].includes(u.protocol) && u.pathname === '/incudal_deletion_test' && (u.hostname === 'localhost' || (ipv4 && (p[0] === 127 || p[0] === 10 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168))))
} catch { /* invalid URL */ }
if (!valid || process.env.INSTANCE_DELETION_TEST_ALLOW !== '1' || url !== process.env.INSTANCE_DELETION_TEST_DATABASE_URL) throw new Error('Requires the dedicated local deletion test database')
const { prisma } = await import('../src/db/prisma.js')
const { cleanOldLogs } = await import('../src/db/logs.js')
const run = promisify(execFile)
const script = fileURLToPath(new URL('./operator-queue-offline-batch.mjs', import.meta.url))
const existingCountries = new Set((await prisma.host.findMany({ select: { countryCode: true }, distinct: ['countryCode'] })).map(host => host.countryCode.toLowerCase()))
const country = [...'zyxwvutsrqponmlkjihgfedcba'].flatMap(a => [...'zyxwvutsrqponmlkjihgfedcba'].map(b => a + b)).find(code => !existingCountries.has(code))
if (!country) throw new Error('No unused local fixture country code')
const scope = [`--country=${country}`, '--hosts=2', '--instances=9']
async function invoke(...args: string[]) {
  const result = await run(process.execPath, [script, ...scope, ...args], { env: process.env })
  return JSON.parse(result.stdout.trim())
}
const tag = `${Date.now()}_${Math.floor(Math.random() * 100000)}`
const owner = await prisma.user.create({ data: { username: `operator_owner_${tag}`, passwordHash: 'test-only' } })
const pkg = await prisma.package.create({ data: { userId: owner.id, name: `operator_pkg_${tag}`, cpuMax: 100, memoryMax: 1024, diskMax: 2048 } })
const plan = await prisma.packagePlan.create({ data: { packageId: pkg.id, name: 'test', cpu: 10, memory: 128, disk: 512, portLimit: 2, snapshotLimit: 1, backupLimit: 1, siteLimit: 1, trafficLimit: 1000n, price: 100 } })
const hosts = await Promise.all(Array.from({ length: 2 }, (_, index) => prisma.host.create({ data: { userId: owner.id, name: `operator_${tag}_${index}`, countryCode: country, url: 'https://127.0.0.1:1', status: 'offline', cpuUsed: 50, memoryUsed: 640, diskUsed: 2560, natPortsUsedCount: 10 } })))
const otherHost = await prisma.host.create({ data: { userId: owner.id, name: `operator_other_${tag}`, countryCode: 'us', url: 'https://127.0.0.1:1', status: 'offline' } })
const instances = []
for (let i = 0; i < 9; i++) {
  const user = await prisma.user.create({ data: { username: `operator_user_${tag}_${i}`, passwordHash: 'test-only', balance: 10 } })
  const host = hosts[i % 2]!
  const instance = await prisma.instance.create({ data: { userId: user.id, hostId: host.id, incusId: `operator_${tag}_${i}`, name: `operator_${tag}_${i}`, image: 'test', status: 'running', cpu: 10, memory: 128, disk: 512, portLimit: 2, packageId: pkg.id, packagePlanId: i ? plan.id : null } })
  await prisma.ipAddress.create({ data: { instanceId: instance.id, hostId: host.id, address: `10.249.0.${i + 1}`, type: 'inet4', isPrimary: true, isCustom: false } })
  instances.push(instance)
}
const outside = await prisma.instance.create({ data: { userId: instances[0]!.userId, hostId: otherHost.id, incusId: `operator_outside_${tag}`, name: `operator_outside_${tag}`, image: 'test', status: 'running', cpu: 1, memory: 64, disk: 64 } })
try {
  const before = await invoke('--dry-run')
  assert.equal(before.result, 'dry_run')
  assert.equal(before.instanceCount, 9)
  assert.equal(await prisma.instance.count({ where: { id: { in: instances.map(i => i.id) }, status: 'running' } }), 9)
  await prisma.instance.update({ where: { id: instances[0]!.id }, data: { version: { increment: 1 } } })
  await assert.rejects(invoke(`--apply=${before.digest}`), /Preview digest changed/)
  const preview = await invoke()
  const last = instances[8]!
  const task = await prisma.instanceTask.create({ data: { instanceId: last.id, hostId: last.hostId, userId: last.userId, taskType: 'stop', status: 'PENDING' } })
  await assert.rejects(invoke(`--apply=${preview.digest}`), /active task or transfer/)
  assert.equal(await prisma.instance.count({ where: { id: { in: instances.map(i => i.id) }, status: 'running' } }), 9, 'all earlier writes roll back on a late conflict')
  assert.equal(await prisma.log.count({ where: { action: 'instance.operator_approved_pending_delete', instanceId: { in: instances.map(i => i.id) } } }), 0)
  await prisma.instanceTask.update({ where: { id: task.id }, data: { status: 'FAILED' } })
  const results = await Promise.allSettled([invoke(`--apply=${preview.digest}`), invoke(`--apply=${preview.digest}`)])
  assert.equal(results.filter(result => result.status === 'fulfilled' && result.value.result === 'queued').length, 1)
  assert.equal((await invoke(`--apply=${preview.digest}`)).result, 'already_applied')
  assert.equal(await prisma.instance.count({ where: { id: { in: instances.map(i => i.id) }, status: 'deleting' } }), 9)
  assert.equal(await prisma.log.count({ where: { action: 'instance.operator_approved_pending_delete', instanceId: { in: instances.map(i => i.id) } } }), 9)
  const rollbackRetention = new Error('rollback retention fixture')
  await assert.rejects(prisma.$transaction(async tx => {
    await tx.log.updateMany({ where: { action: 'instance.operator_approved_pending_delete', instanceId: { in: instances.map(i => i.id) } }, data: { createdAt: new Date(Date.now() - 100 * 86400000) } })
    await cleanOldLogs(90, tx)
    assert.equal(await tx.log.count({ where: { action: 'instance.operator_approved_pending_delete', instanceId: { in: instances.map(i => i.id) } } }), 9)
    throw rollbackRetention
  }), error => error === rollbackRetention)
  assert.equal(await prisma.ipAddress.count({ where: { instanceId: { in: instances.map(i => i.id) } } }), 9)
  assert.equal((await prisma.instance.findUniqueOrThrow({ where: { id: outside.id } })).status, 'running')
  for (const item of instances) {
    const row = await prisma.instance.findUniqueOrThrow({ where: { id: item.id } })
    assert.equal(row.deletionRemoteDeleted, false)
    assert.equal(row.deletionBillingPending, item.packagePlanId !== null)
    assert.equal(Number((await prisma.user.findUniqueOrThrow({ where: { id: item.userId } })).balance), 10)
    assert.equal(await prisma.instanceBillingRecord.count({ where: { instanceId: item.id, type: 'refund' } }), 0)
  }
  for (const host of hosts) {
    const row = await prisma.host.findUniqueOrThrow({ where: { id: host.id } })
    assert.deepEqual([row.cpuUsed, row.memoryUsed, row.diskUsed, row.natPortsUsedCount], [50, 640, 2560, 10])
  }
  console.log('operator offline batch PostgreSQL integration tests passed')
} finally { await prisma.$disconnect() }
process.exit(0)
