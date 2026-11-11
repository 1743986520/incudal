import assert from 'node:assert/strict'
import type { IncusClient } from '../src/lib/incus/incus-client.js'

const testUrl = process.env.DATABASE_URL ?? ''
const allowedUrl = /^postgresql:\/\/postgres@(?:localhost|127\.0\.0\.1|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}):\d{1,5}\/incudal_deletion_test$/
if (process.env.INSTANCE_DELETION_TEST_ALLOW !== '1' || testUrl !== process.env.INSTANCE_DELETION_TEST_DATABASE_URL || !allowedUrl.test(testUrl)) {
  throw new Error('This fixture test requires the dedicated local deletion test database and explicit opt-in')
}
const { prisma } = await import('../src/db/prisma.js')
const { IncusApiError } = await import('../src/lib/incus/incus-client.js')
const { reconcileMissingInstanceStatus } = await import('../src/services/status-scheduler.js')
const { claimInstanceForDelete } = await import('../src/routes/instances/helpers.js')
const suffix = `${Date.now()}_${Math.floor(Math.random() * 100000)}`
const user = await prisma.user.create({ data: { username: `status_owner_${suffix}`, passwordHash: 'test-only', role: 'admin' } })
const host = await prisma.host.create({ data: { userId: user.id, name: `status_host_${suffix}`, url: 'https://127.0.0.1:1', status: 'offline', cpuUsed: 30, memoryUsed: 384, diskUsed: 1536 } })
async function fixture(name: string, billingMode: 'package' | 'hourly', trafficBillingMode: 'package' | 'usage' = 'package') {
  return prisma.instance.create({ data: {
    incusId: `${name}_${suffix}`, name, userId: user.id, hostId: host.id, image: 'test', status: 'running',
    cpu: 10, memory: 128, disk: 512, billingMode, trafficBillingMode
  } })
}
function error(path: string, statusCode = 404) { return new IncusApiError('not found', { statusCode, method: 'GET', path }) }
function clientFor(path: string): Pick<IncusClient, 'request'> {
  return { request: async () => { throw error(path) } } as unknown as Pick<IncusClient, 'request'>
}
try {
  for (const [billingMode, trafficBillingMode] of [['hourly', 'package'], ['package', 'usage']] as const) {
    const instance = await fixture(`status_${billingMode}_${trafficBillingMode}`, billingMode, trafficBillingMode)
    const path = `/1.0/instances/${instance.incusId}`
    await prisma.ipAddress.create({ data: { instanceId: instance.id, hostId: host.id, address: `10.0.0.${instance.id % 250 + 1}`, type: 'inet4', isPrimary: true } })
    const result = await reconcileMissingInstanceStatus(instance, clientFor(path), error(`${path}/state`))
    assert.equal(result.changed, false)
    assert.match(result.error ?? '', /manual reconciliation/)
    assert.equal((await prisma.instance.findUniqueOrThrow({ where: { id: instance.id } })).status, 'running')
    assert.equal(await prisma.ipAddress.count({ where: { instanceId: instance.id } }), 1)
  }
  const plain = await fixture('status_plain', 'package')
  const path = `/1.0/instances/${plain.incusId}`
  assert.deepEqual(await reconcileMissingInstanceStatus(plain, clientFor(path), new Error('instance not found')), { changed: false })
  assert.deepEqual(await reconcileMissingInstanceStatus(plain, clientFor(path), error(`${path}/state`, 503)), { changed: false })
  const missing = await reconcileMissingInstanceStatus(plain, clientFor(path), error(`${path}/state`))
  assert.equal(missing.changed, false)
  assert.match(missing.error ?? '', /resources require reconciliation/)
  assert.equal((await prisma.instance.findUniqueOrThrow({ where: { id: plain.id } })).status, 'running')
  let release!: () => void
  let entered!: () => void
  const wait = new Promise<void>(resolve => { release = resolve })
  const ready = new Promise<void>(resolve => { entered = resolve })
  const client = { request: async () => { entered(); await wait; throw error(path) } } as unknown as Pick<IncusClient, 'request'>
  const sync = reconcileMissingInstanceStatus(plain, client, error(`${path}/state`))
  await ready
  const claimed = await claimInstanceForDelete(plain.id, 'running', { authorization: {
    actorUserId: user.id, actorRole: 'admin', scope: 'instance-or-host', expectedUserId: user.id,
    expectedHostId: host.id, expectedHostUserId: user.id, expectedIncusId: plain.incusId,
    expectedVersion: plain.version, expectedPackagePlanId: plain.packagePlanId,
    expectedPackageId: plain.packageId, expectedSuspendReason: plain.suspendReason,
    expectedBillingMode: plain.billingMode, expectedTrafficBillingMode: plain.trafficBillingMode
  }, pending: { requestedById: user.id } })
  assert.equal(claimed, true)
  release()
  assert.deepEqual(await sync, { changed: false })
  assert.equal((await prisma.instance.findUniqueOrThrow({ where: { id: plain.id } })).status, 'deleting')
  const counters = await prisma.host.findUniqueOrThrow({ where: { id: host.id } })
  assert.deepEqual([counters.cpuUsed, counters.memoryUsed, counters.diskUsed], [30, 384, 1536])
  console.log('status sync absence and deletion race PostgreSQL integration tests passed')
} finally { await prisma.$disconnect() }
process.exit(0)
