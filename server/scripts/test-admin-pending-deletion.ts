import assert from 'node:assert/strict'
import Fastify from 'fastify'

const testUrl = process.env.DATABASE_URL ?? ''
let valid = false
try {
  const url = new URL(testUrl)
  const parts = url.hostname.split('.').map(Number)
  const ipv4 = parts.length === 4 && parts.every(n => Number.isInteger(n) && n >= 0 && n <= 255)
  const privateIp = ipv4 && (parts[0] === 127 || parts[0] === 10 || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) || (parts[0] === 192 && parts[1] === 168))
  valid = ['postgres:', 'postgresql:'].includes(url.protocol) && (url.hostname === 'localhost' || privateIp) && url.pathname === '/incudal_deletion_test'
} catch { /* invalid URL */ }
if (!valid || process.env.INSTANCE_DELETION_TEST_ALLOW !== '1' || testUrl !== process.env.INSTANCE_DELETION_TEST_DATABASE_URL) {
  throw new Error('Requires opt-in and dedicated local deletion test database')
}

const { prisma } = await import('../src/db/prisma.js')
const { default: adminRoutes } = await import('../src/routes/admin-billing.js')
const { processPendingInstanceDeletion } = await import('../src/services/pending-instance-deletion.js')
const { recordNewInstanceReservation } = await import('../src/db/resource-reservation-evidence.js')
const tag = `${Date.now()}_${Math.floor(Math.random() * 100000)}`
const admin = await prisma.user.create({ data: { username: `admin_pending_${tag}`, passwordHash: 'test-only', role: 'admin' } })
const customer = await prisma.user.create({ data: { username: `admin_customer_${tag}`, passwordHash: 'test-only', balance: 10 } })
const pkg = await prisma.package.create({ data: { userId: admin.id, name: `admin_pending_pkg_${tag}`, cpuMax: 100, memoryMax: 1024, diskMax: 2048 } })
const plan = await prisma.packagePlan.create({ data: { packageId: pkg.id, name: 'test', cpu: 10, memory: 256, disk: 512, portLimit: 2, snapshotLimit: 1, backupLimit: 1, siteLimit: 1, trafficLimit: 1000n, price: 100 } })
const now = Date.now(), day = 86400000
let sequence = 0
async function fixture(options: { hostStatus?: 'online' | 'offline'; billingMode?: 'package' | 'hourly'; trafficBillingMode?: 'package' | 'usage'; evidence?: boolean } = {}) {
  const name = `admin_pending_${tag}_${++sequence}`
  const host = await prisma.host.create({ data: { userId: admin.id, name, url: 'https://127.0.0.1:1', status: options.hostStatus ?? 'offline', cpuUsed: 10, memoryUsed: 256, diskUsed: 512, natPortsUsedCount: 2 } })
  const instance = await prisma.$transaction(async tx => {
    const row = await tx.instance.create({ data: {
      incusId: name, name, userId: customer.id, hostId: host.id, packageId: pkg.id, packagePlanId: plan.id,
      image: 'test', status: 'running', cpu: 10, memory: 256, disk: 512, portLimit: 2,
      expiresAt: new Date(now + 30 * day), billingPrice: 100, billingCycle: 1,
      billingMode: options.billingMode ?? 'package', trafficBillingMode: options.trafficBillingMode ?? 'package'
    } })
    if (options.evidence !== false) await recordNewInstanceReservation(tx, { instanceId: row.id, hostId: host.id, cpu: 10, memory: 256, disk: 512, portCount: 2 })
    return row
  })
  await prisma.instanceBillingRecord.create({ data: { instanceId: instance.id, userId: customer.id, type: 'newPurchase', amount: 100, periodStart: new Date(now - 30 * day), periodEnd: new Date(now + 30 * day) } })
  await prisma.ipAddress.create({ data: { address: `10.233.0.${sequence}`, type: 'inet4', isPrimary: true, hostId: host.id, instanceId: instance.id } })
  return { host, instance }
}
const app = Fastify()
app.decorateRequest('user', null)
app.decorate('authenticate', async (request: any) => { request.user = request.headers['x-test-user'] === 'customer' ? { id: customer.id, role: 'user' } : { id: admin.id, role: 'admin', username: admin.username } })
app.decorate('requireAdmin', async (request: any, reply: any) => { if (request.user.role !== 'admin') return reply.code(403).send({ code: 'FORBIDDEN' }) })
app.decorate('authenticateUser', async () => {})
await app.register(adminRoutes)
const request = (id: number, refundType: 'full' | 'remaining', headers?: Record<string, string>) => app.inject({
  method: 'POST', url: `/api/admin/instances/${id}/delete-and-refund`, headers,
  payload: { refundType, reason: 'fixture reconciliation' }
})
const remote = { async ensureDeleted() {}, async deleteProxySite() {} }
try {
  for (const refundType of ['full', 'remaining'] as const) {
    const item = await fixture()
    const unauthorized = await request(item.instance.id, refundType, { 'x-test-user': 'customer' })
    assert.equal(unauthorized.statusCode, 403)
    const responses = await Promise.all([request(item.instance.id, refundType), request(item.instance.id, refundType)])
    assert.deepEqual(responses.map(r => r.statusCode).sort(), [202, 409])
    const pending = responses.find(r => r.statusCode === 202)!.json()
    assert.equal(pending.pending, true)
    assert.equal(pending.success, false)
    const row = await prisma.instance.findUniqueOrThrow({ where: { id: item.instance.id } })
    const quote = Number(row.deletionRefundableValue)
    assert.equal(row.status, 'deleting')
    assert.equal(row.deletionRemoteDeleted, false)
    assert.equal(row.deletionBillingMode, 'privileged_delete')
    assert.equal(row.deletionReason, 'fixture reconciliation')
    assert.ok(refundType === 'full' ? quote === 100 : quote > 0 && quote < 100, `${refundType} quotation: ${quote}`)
    assert.equal(await prisma.ipAddress.count({ where: { instanceId: row.id } }), 1)
    assert.equal((await prisma.host.findUniqueOrThrow({ where: { id: item.host.id } })).cpuUsed, 10)
    assert.equal(await prisma.instanceBillingRecord.count({ where: { instanceId: row.id, type: 'refund' } }), 0)
    const audit = await prisma.log.findFirstOrThrow({ where: { instanceId: row.id, action: 'instance.admin_delete_refund_requested' } })
    assert.equal(JSON.parse(audit.content).refundType, refundType)
    await prisma.host.update({ where: { id: item.host.id }, data: { status: 'online' } })
    const before = Number((await prisma.user.findUniqueOrThrow({ where: { id: customer.id } })).balance)
    assert.equal((await processPendingInstanceDeletion(row.id, remote))?.refundAmount, quote)
    assert.equal(Number((await prisma.user.findUniqueOrThrow({ where: { id: customer.id } })).balance), before + quote)
    assert.equal((await prisma.instance.findUniqueOrThrow({ where: { id: row.id } })).status, 'deleted')
    assert.equal(await prisma.ipAddress.count({ where: { instanceId: row.id } }), 0)
    assert.equal((await prisma.host.findUniqueOrThrow({ where: { id: item.host.id } })).cpuUsed, 0)
    assert.equal(await processPendingInstanceDeletion(row.id, remote), null)
    assert.equal(await prisma.instanceBillingRecord.count({ where: { instanceId: row.id, type: 'refund' } }), 1)
  }
  for (const options of [{ billingMode: 'hourly' as const }, { trafficBillingMode: 'usage' as const }]) {
    const item = await fixture(options)
    const response = await request(item.instance.id, 'full')
    assert.equal(response.statusCode, 202, response.body)
    await prisma.host.update({ where: { id: item.host.id }, data: { status: 'online' } })
    await assert.rejects(processPendingInstanceDeletion(item.instance.id, remote), /requires final settlement/)
    const row = await prisma.instance.findUniqueOrThrow({ where: { id: item.instance.id } })
    assert.equal(row.status, 'deleting')
    assert.equal(row.deletionRemoteDeleted, false)
    assert.equal(await prisma.ipAddress.count({ where: { instanceId: row.id } }), 1)
    assert.equal((await prisma.host.findUniqueOrThrow({ where: { id: item.host.id } })).cpuUsed, 10)
  }
  const unknown = await fixture({ evidence: false })
  assert.equal((await request(unknown.instance.id, 'full')).statusCode, 202)
  await prisma.host.update({ where: { id: unknown.host.id }, data: { status: 'online' } })
  await assert.rejects(processPendingInstanceDeletion(unknown.instance.id, remote), /reservation evidence is unavailable or stale/)
  assert.equal((await prisma.instance.findUniqueOrThrow({ where: { id: unknown.instance.id } })).status, 'deleting')
  assert.equal(await prisma.ipAddress.count({ where: { instanceId: unknown.instance.id } }), 1)
  assert.equal((await prisma.host.findUniqueOrThrow({ where: { id: unknown.host.id } })).cpuUsed, 10)
  const staleOnline = await fixture({ hostStatus: 'online' })
  assert.equal((await request(staleOnline.instance.id, 'full')).statusCode, 202)
  assert.equal((await prisma.instance.findUniqueOrThrow({ where: { id: staleOnline.instance.id } })).deletionRemoteDeleted, false)
  assert.equal(await prisma.ipAddress.count({ where: { instanceId: staleOnline.instance.id } }), 1)
  console.log('admin pending deletion PostgreSQL integration tests passed')
} finally { await app.close(); await prisma.$disconnect() }
process.exit(0)
