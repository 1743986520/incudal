import assert from 'node:assert/strict'
import Fastify from 'fastify'

const url = process.env.DATABASE_URL ?? ''
let valid = false
try {
  const parsed = new URL(url)
  const octets = parsed.hostname.split('.').map(Number)
  const ipv4 = octets.length === 4 && octets.every(n => Number.isInteger(n) && n >= 0 && n <= 255)
  const privateIp = ipv4 && (octets[0] === 127 || octets[0] === 10 || (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) || (octets[0] === 192 && octets[1] === 168))
  valid = ['postgres:', 'postgresql:'].includes(parsed.protocol) && (parsed.hostname === 'localhost' || privateIp) && parsed.pathname === '/incudal_deletion_test'
} catch { /* invalid URL */ }
if (!valid || process.env.INSTANCE_DELETION_TEST_ALLOW !== '1' || url !== process.env.INSTANCE_DELETION_TEST_DATABASE_URL) {
  throw new Error('This fixture test only runs against the dedicated local deletion test database')
}
const { prisma } = await import('../src/db/prisma.js')
const { default: instanceDestroyRoutes } = await import('../src/routes/instance-destroy.js')
const { processPendingInstanceDeletion } = await import('../src/services/pending-instance-deletion.js')
const { recordNewInstanceReservation } = await import('../src/db/resource-reservation-evidence.js')
const suffix = `${Date.now()}_${Math.floor(Math.random() * 100000)}`
const owner = await prisma.user.create({ data: { username: `offline_owner_${suffix}`, passwordHash: 'test-only' } })
const customer = await prisma.user.create({ data: { username: `offline_customer_${suffix}`, passwordHash: 'test-only', balance: 10 } })
const other = await prisma.user.create({ data: { username: `offline_other_${suffix}`, passwordHash: 'test-only' } })
const pkg = await prisma.package.create({ data: { userId: owner.id, name: `offline_pkg_${suffix}`, cpuMax: 100, memoryMax: 1024, diskMax: 2048 } })
const plan = await prisma.packagePlan.create({ data: { packageId: pkg.id, name: 'test', cpu: 10, memory: 256, disk: 512, portLimit: 2, snapshotLimit: 1, backupLimit: 1, siteLimit: 1, trafficLimit: 1000n, price: 100 } })
const now = Date.now(), end = new Date(now + 30 * 86400000), start = new Date(now - 30 * 86400000)
let seq = 0
async function fixture(options: { billingMode?: 'package' | 'hourly'; trafficBillingMode?: 'package' | 'usage'; used?: bigint; hostStatus?: 'online' | 'offline'; status?: 'running' | 'stopped' | 'error'; free?: boolean } = {}) {
  const name = `offline_paid_${suffix}_${++seq}`
  const host = await prisma.host.create({ data: { userId: owner.id, name, url: 'https://127.0.0.1:1', status: options.hostStatus ?? 'offline', cpuUsed: 10, memoryUsed: 256, diskUsed: 512, natPortsUsedCount: 2 } })
  const instance = await prisma.instance.create({ data: {
    incusId: name, name, userId: customer.id, hostId: host.id, packageId: pkg.id, packagePlanId: options.free ? null : plan.id,
    image: 'test', status: options.status ?? 'running', cpu: 10, memory: 256, disk: 512, portLimit: 2,
    expiresAt: end, billingPrice: 100, billingCycle: 1,
    billingMode: options.billingMode ?? 'package', trafficBillingMode: options.trafficBillingMode ?? 'package',
    monthlyTrafficUsed: options.used ?? 0n
  } })
  await prisma.instanceBillingRecord.create({ data: { instanceId: instance.id, userId: customer.id, type: 'newPurchase', amount: 100, periodStart: start, periodEnd: end } })
  await prisma.ipAddress.create({ data: { address: `10.222.${Math.floor(seq / 250)}.${(seq % 250) + 1}`, type: 'inet4', isPrimary: true, isCustom: false, hostId: host.id, instanceId: instance.id } })
  return { host, instance }
}
const app = Fastify()
app.decorateRequest('user', null)
const authenticate = async (request: any) => {
  const actor = request.headers['x-test-user'] === 'other' ? other : customer
  request.user = { id: actor.id, role: 'user', username: actor.username }
}
app.decorate('authenticate', authenticate)
app.decorate('authenticateUser', authenticate)
app.decorate('requireAdmin', authenticate)
await app.register(instanceDestroyRoutes, { prefix: '/api/instances' })
let remoteCalls = 0
const remote = { async ensureDeleted() { remoteCalls++ }, async deleteProxySite() { remoteCalls++ } }
try {
  const first = await fixture()
  const wrongOwner = await app.inject({ method: 'POST', url: `/api/instances/${first.instance.id}/destroy`, headers: { 'x-test-user': 'other' } })
  assert.equal(wrongOwner.statusCode, 403)
  const responses = await Promise.all(Array.from({ length: 2 }, () => app.inject({ method: 'POST', url: `/api/instances/${first.instance.id}/destroy` })))
  assert.deepEqual(responses.map(r => r.statusCode).sort(), [202, 409])
  const body = responses.find(r => r.statusCode === 202)!.json()
  assert.equal(body.pending, true)
  assert.equal(body.success, false)
  assert.equal(body.isFreeInstance, false)
  const claimed = await prisma.instance.findUniqueOrThrow({ where: { id: first.instance.id } })
  assert.equal(claimed.status, 'deleting')
  assert.equal(claimed.deletionBillingMode, 'user_destroy')
  assert.ok(claimed.deletionRequestedAt)
  assert.ok(Number(claimed.deletionRefundableValue) > 0)
  assert.equal(claimed.deletionRemoteDeleted, false)
  assert.equal(Number((await prisma.user.findUniqueOrThrow({ where: { id: customer.id } })).balance), 10)
  assert.equal(await prisma.userDestroyRecord.count({ where: { instanceId: first.instance.id } }), 0)
  assert.equal(await prisma.ipAddress.count({ where: { instanceId: first.instance.id } }), 1)
  await prisma.host.update({ where: { id: first.host.id }, data: { status: 'online' } })
  await assert.rejects(processPendingInstanceDeletion(first.instance.id, remote), /final traffic reconciliation/)
  assert.equal(remoteCalls, 0, 'unverified final traffic must block even remote deletion')
  assert.equal((await prisma.host.findUniqueOrThrow({ where: { id: first.host.id } })).cpuUsed, 10)
  assert.equal(Number((await prisma.user.findUniqueOrThrow({ where: { id: customer.id } })).balance), 10)

  const a = await fixture()
  const b = await fixture({ billingMode: 'hourly' })
  const c = await fixture({ trafficBillingMode: 'usage' })
  const batch = await app.inject({ method: 'POST', url: '/api/instances/batch/destroy', payload: { instanceIds: [a.instance.id, b.instance.id, c.instance.id] } })
  assert.equal(batch.statusCode, 200, batch.body)
  assert.equal(batch.json().pendingCount, 3)
  assert.equal(batch.json().successCount, 0)
  for (const item of [a, b, c]) {
    const row = await prisma.instance.findUniqueOrThrow({ where: { id: item.instance.id } })
    assert.equal(row.status, 'deleting')
    assert.equal(row.deletionRemoteDeleted, false)
    assert.equal(await prisma.ipAddress.count({ where: { instanceId: item.instance.id } }), 1)
    await prisma.host.update({ where: { id: item.host.id }, data: { status: 'online' } })
    await assert.rejects(processPendingInstanceDeletion(item.instance.id, remote))
  }
  assert.equal(remoteCalls, 0)
  assert.equal(Number((await prisma.user.findUniqueOrThrow({ where: { id: customer.id } })).balance), 10)

  const overLimit = await fixture({ used: 6n * 1024n * 1024n * 1024n })
  const denied = await app.inject({ method: 'POST', url: `/api/instances/${overLimit.instance.id}/destroy` })
  assert.equal(denied.statusCode, 400)
  assert.equal((await prisma.instance.findUniqueOrThrow({ where: { id: overLimit.instance.id } })).status, 'running')

  // A host can still be marked online when the actual Incus connection fails.
  // Both paths must retain an inconclusive claim rather than restore it or
  // report completion; the persisted request-time quote survives the handoff.
  for (const batchMode of [false, true]) {
    const unreachable = await fixture({ hostStatus: 'online', status: 'stopped' })
    assert.equal(await prisma.ipAddress.count({ where: { instanceId: unreachable.instance.id } }), 1, 'fixture must begin with an allocated IP')
    const response = batchMode
      ? await app.inject({ method: 'POST', url: '/api/instances/batch/destroy', payload: { instanceIds: [unreachable.instance.id] } })
      : await app.inject({ method: 'POST', url: `/api/instances/${unreachable.instance.id}/destroy` })
    if (batchMode) {
      assert.equal(response.statusCode, 200, response.body)
      assert.equal(response.json().pendingCount, 1, response.body)
    } else {
      assert.equal(response.statusCode, 202, response.body)
      assert.equal(response.json().pending, true)
    }
    const row = await prisma.instance.findUniqueOrThrow({ where: { id: unreachable.instance.id } })
    assert.equal(row.status, 'deleting')
    assert.equal(row.deletionOriginalStatus, 'stopped')
    assert.equal(row.deletionRemoteDeleted, false)
    assert.ok(Number(row.deletionRefundableValue) > 0)
    assert.equal(await prisma.ipAddress.count({ where: { instanceId: row.id } }), 1)
    assert.equal((await prisma.host.findUniqueOrThrow({ where: { id: unreachable.host.id } })).cpuUsed, 10)
    assert.equal(await prisma.userDestroyRecord.count({ where: { instanceId: row.id } }), 0)
  }
  for (const options of [{ free: true, trafficBillingMode: 'usage' as const }, { free: true, status: 'error' as const }]) {
    const free = await fixture(options)
    const response = await app.inject({ method: 'POST', url: `/api/instances/${free.instance.id}/destroy` })
    assert.equal(response.statusCode, 202, response.body)
    assert.equal(response.json().isFreeInstance, true)
    assert.equal((await prisma.instance.findUniqueOrThrow({ where: { id: free.instance.id } })).status, 'deleting')
    assert.equal(await prisma.ipAddress.count({ where: { instanceId: free.instance.id } }), 1)
  }
  // Existing policy exempts already-expired suspended fixed plans from the
  // traffic threshold. A zero request-time quote makes this case settleable
  // without inventing a final traffic counter or refund amount.
  const expired = await fixture({ used: 6n * 1024n * 1024n * 1024n })
  await prisma.$transaction(async tx => {
    await tx.instance.update({ where: { id: expired.instance.id }, data: {
      status: 'suspended', suspendReason: 'expired', suspendedAt: new Date(now - 3 * 86400000), expiresAt: new Date(now - 86400000)
    } })
    await recordNewInstanceReservation(tx, { instanceId: expired.instance.id, hostId: expired.host.id, cpu: 10, memory: 256, disk: 512, portCount: 2 })
  })
  const expiredResponse = await app.inject({ method: 'POST', url: `/api/instances/${expired.instance.id}/destroy` })
  assert.equal(expiredResponse.statusCode, 202, expiredResponse.body)
  const expiredClaim = await prisma.instance.findUniqueOrThrow({ where: { id: expired.instance.id } })
  assert.equal(expiredClaim.status, 'deleting')
  assert.equal(Number(expiredClaim.deletionRefundableValue), 0)
  await assert.rejects(processPendingInstanceDeletion(expired.instance.id, remote), /unavailable/)
  assert.equal(await prisma.ipAddress.count({ where: { instanceId: expired.instance.id } }), 1)
  await prisma.host.update({ where: { id: expired.host.id }, data: { status: 'online' } })
  const expiredResult = await processPendingInstanceDeletion(expired.instance.id, remote)
  assert.equal(expiredResult?.refundAmount, 0)
  assert.equal((await prisma.instance.findUniqueOrThrow({ where: { id: expired.instance.id } })).status, 'deleted')
  assert.equal(await prisma.ipAddress.count({ where: { instanceId: expired.instance.id } }), 0)
  assert.equal((await prisma.host.findUniqueOrThrow({ where: { id: expired.host.id } })).cpuUsed, 0)
  assert.equal(await prisma.userDestroyRecord.count({ where: { instanceId: expired.instance.id } }), 1)
  assert.equal(await processPendingInstanceDeletion(expired.instance.id, remote), null)
  assert.equal(await prisma.userDestroyRecord.count({ where: { instanceId: expired.instance.id } }), 1)
  assert.equal(Number((await prisma.user.findUniqueOrThrow({ where: { id: customer.id } })).balance), 10)

  const rollback = await fixture()
  await prisma.$transaction(async tx => {
    await tx.host.update({ where: { id: rollback.host.id }, data: { status: 'online', cpuUsed: 0, memoryUsed: 0, diskUsed: 0, natPortsUsedCount: 0 } })
    await tx.instance.update({ where: { id: rollback.instance.id }, data: {
      status: 'suspended', suspendReason: 'expired', suspendedAt: new Date(now - 3 * 86400000), expiresAt: new Date(now - 86400000)
    } })
    // Deliberately inconsistent counters exercise atomic resource rollback.
    await recordNewInstanceReservation(tx, { instanceId: rollback.instance.id, hostId: rollback.host.id, cpu: 10, memory: 256, disk: 512, portCount: 2 })
  })
  const rollbackResponse = await app.inject({ method: 'POST', url: `/api/instances/${rollback.instance.id}/destroy` })
  assert.equal(rollbackResponse.statusCode, 202, rollbackResponse.body)
  for (let retry = 0; retry < 2; retry++) {
    await assert.rejects(processPendingInstanceDeletion(rollback.instance.id, remote), /counters are lower/)
    assert.equal((await prisma.instance.findUniqueOrThrow({ where: { id: rollback.instance.id } })).status, 'deleting')
    assert.equal(await prisma.ipAddress.count({ where: { instanceId: rollback.instance.id } }), 1)
    assert.equal(await prisma.userDestroyRecord.count({ where: { instanceId: rollback.instance.id } }), 1)
    assert.equal(Number((await prisma.user.findUniqueOrThrow({ where: { id: customer.id } })).balance), 10)
  }
  console.log('offline paid destruction PostgreSQL integration tests passed')
} finally {
  await app.close()
  await prisma.$disconnect()
}
process.exit(0)
