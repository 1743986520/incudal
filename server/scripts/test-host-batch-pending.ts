import assert from 'node:assert/strict'
import Fastify from 'fastify'

const testUrl = process.env.DATABASE_URL ?? ''
const allowedUrl = /^postgresql:\/\/postgres@(?:localhost|127\.0\.0\.1|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}):\d{1,5}\/incudal_deletion_test$/
if (process.env.INSTANCE_DELETION_TEST_ALLOW !== '1' || testUrl !== process.env.INSTANCE_DELETION_TEST_DATABASE_URL || !allowedUrl.test(testUrl)) {
  throw new Error('This fixture test requires the dedicated local deletion test database and explicit opt-in')
}
const { prisma } = await import('../src/db/prisma.js')
const { default: hostsRoutes } = await import('../src/routes/hosts.js')
const tag = `${Date.now()}_${Math.floor(Math.random() * 100000)}`
const admin = await prisma.user.create({ data: { username: `batch_owner_${tag}`, passwordHash: 'test-only', role: 'admin' } })
const customer = await prisma.user.create({ data: { username: `batch_customer_${tag}`, passwordHash: 'test-only', balance: 7 } })
const outsider = await prisma.user.create({ data: { username: `batch_outsider_${tag}`, passwordHash: 'test-only', role: 'user' } })
const host = await prisma.host.create({ data: { userId: admin.id, name: `batch_host_${tag}`, url: 'https://127.0.0.1:1', status: 'offline', cpuUsed: 30, memoryUsed: 384, diskUsed: 1536, natPortsUsedCount: 6 } })
const pkg = await prisma.package.create({ data: { userId: admin.id, name: `batch_pkg_${tag}`, cpuMax: 100, memoryMax: 1024, diskMax: 2048 } })
const plan = await prisma.packagePlan.create({ data: { packageId: pkg.id, name: 'paid', cpu: 10, memory: 128, disk: 512, portLimit: 2, snapshotLimit: 1, backupLimit: 1, siteLimit: 1, trafficLimit: 1000n, price: 100 } })
async function fixture(name: string, billingMode: 'package' | 'hourly', paid: boolean) {
  const row = await prisma.instance.create({ data: {
    incusId: `${name}_${tag}`, name, userId: customer.id, hostId: host.id, packageId: pkg.id,
    packagePlanId: paid ? plan.id : null, image: 'test', status: 'running', cpu: 10, memory: 128, disk: 512, portLimit: 2, billingMode
  } })
  await prisma.ipAddress.create({ data: { instanceId: row.id, hostId: host.id, address: `10.${row.id % 250}.0.1`, type: 'inet4', isPrimary: true } })
  await prisma.ipv6Subnet.create({ data: { instanceId: row.id, cidr: `2001:db8:${row.id.toString(16)}::/64`, primaryIp: `2001:db8:${row.id.toString(16)}::1` } })
  return row
}
const app = Fastify()
app.decorateRequest('user', null)
const authenticate = async (request: any) => { request.user = request.headers['x-test-user'] === 'outsider'
  ? { id: outsider.id, role: 'user', username: outsider.username }
  : { id: admin.id, role: 'admin', username: admin.username } }
app.decorate('authenticate', authenticate)
app.decorate('authenticateUser', authenticate)
app.decorate('authenticateAdmin', authenticate)
app.decorate('requireAdmin', authenticate)
await app.register(hostsRoutes, { prefix: '/api/hosts' })
try {
  const free = await fixture('batch_free', 'package', false)
  const paid = await fixture('batch_paid', 'package', true)
  const hourly = await fixture('batch_hourly', 'hourly', true)
  const ids = [free.id, paid.id, hourly.id]
  const denied = await app.inject({ method: 'DELETE', url: `/api/hosts/${host.id}/instances/batch`, headers: { 'x-test-user': 'outsider' }, payload: { instanceIds: ids } })
  assert.equal(denied.statusCode, 403, denied.body)
  const response = await app.inject({ method: 'DELETE', url: `/api/hosts/${host.id}/instances/batch`, payload: { instanceIds: ids, reason: 'node offline' } })
  assert.equal(response.statusCode, 200, response.body)
  const body = response.json()
  assert.equal(body.pendingCount, 3)
  assert.equal(body.successCount, 0)
  assert.equal(body.failedCount, 0)
  assert.equal(body.totalRefundAmount, 0)
  for (const item of body.results) assert.deepEqual([item.pending, item.success, item.status], [true, false, 'deleting'])
  for (const instance of [free, paid, hourly]) {
    const row = await prisma.instance.findUniqueOrThrow({ where: { id: instance.id } })
    assert.equal(row.status, 'deleting')
    assert.equal(row.deletionOriginalStatus, 'running')
    assert.equal(row.deletionRemoteDeleted, false)
    assert.equal(await prisma.ipAddress.count({ where: { instanceId: instance.id } }), 1)
    assert.equal(await prisma.ipv6Subnet.count({ where: { instanceId: instance.id } }), 1)
  }
  const paidState = await prisma.instance.findUniqueOrThrow({ where: { id: paid.id } })
  assert.equal(paidState.deletionBillingMode, 'privileged_delete')
  assert.equal(paidState.deletionBillingPending, true)
  const hourlyState = await prisma.instance.findUniqueOrThrow({ where: { id: hourly.id } })
  assert.equal(hourlyState.deletionBillingMode, 'hourly_close')
  const hostAfter = await prisma.host.findUniqueOrThrow({ where: { id: host.id } })
  assert.deepEqual([hostAfter.cpuUsed, hostAfter.memoryUsed, hostAfter.diskUsed, hostAfter.natPortsUsedCount], [30, 384, 1536, 6])
  assert.equal(Number((await prisma.user.findUniqueOrThrow({ where: { id: customer.id } })).balance), 7)
  console.log('host batch pending deletion IP/resource preservation PostgreSQL test passed')
} finally {
  await app.close()
  await prisma.$disconnect()
}
process.exit(0)
