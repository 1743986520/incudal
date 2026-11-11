import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import Fastify from 'fastify'

const url = process.env.DATABASE_URL ?? ''
let local = false
try {
  const u = new URL(url), p = u.hostname.split('.').map(Number)
  const ip = p.length === 4 && p.every(n => Number.isInteger(n) && n >= 0 && n <= 255)
  local = ['postgres:', 'postgresql:'].includes(u.protocol) && u.pathname === '/incudal_deletion_test' &&
    (u.hostname === 'localhost' || (ip && (p[0] === 127 || p[0] === 10 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168))))
} catch { /* invalid URL */ }
if (!local || process.env.INSTANCE_DELETION_TEST_ALLOW !== '1' || url !== process.env.INSTANCE_DELETION_TEST_DATABASE_URL) throw new Error('Requires opt-in and dedicated local deletion test database')
const { prisma } = await import('../src/db/prisma.js')
const { cleanOldLogs } = await import('../src/db/logs.js')
const { default: routes } = await import('../src/routes/deletion-reservation-reconciliation.js')
const tag = `${Date.now()}_${Math.floor(Math.random() * 100000)}`
const admin = await prisma.user.create({ data: { username: `billing_review_admin_${tag}`, passwordHash: 'test-only', role: 'admin' } })
const user = await prisma.user.create({ data: { username: `billing_review_user_${tag}`, passwordHash: 'test-only', balance: 10 } })
const host = await prisma.host.create({ data: { userId: admin.id, name: `billing_review_host_${tag}`, url: 'https://127.0.0.1:1', cpuUsed: 10, memoryUsed: 128, diskUsed: 512, natPortsUsedCount: 2 } })
const requestedAt = new Date()
const instance = await prisma.instance.create({ data: { name: `billing_review_${tag}`, incusId: `billing_review_${tag}`, image: 'test', userId: user.id, hostId: host.id,
  status: 'deleting', deletionOriginalStatus: 'running', deletionRequestedAt: requestedAt, deletionBillingMode: 'user_destroy', deletionBillingPending: true,
  trafficBillingMode: 'usage', cpu: 10, memory: 128, disk: 512, portLimit: 2 } })
await prisma.ipAddress.create({ data: { address: '10.253.0.1', type: 'inet4', isPrimary: true, isCustom: false, device: 'eth0', hostId: host.id, instanceId: instance.id } })
const app = Fastify()
app.decorateRequest('user', null)
app.decorate('authenticate', async (request: any) => { request.user = request.headers['x-test-user'] === 'customer' ? { id: user.id, role: 'user' } : { id: admin.id, role: 'admin' } })
app.decorate('requireAdmin', async (request: any, reply: any) => { if (request.user.role !== 'admin') return reply.code(403).send({ code: 'FORBIDDEN' }) })
await app.register(routes)
const path = `/api/admin/instances/${instance.id}/deletion-billing-review`
const payload = { requestId: randomUUID(), category: 'usage', evidenceReference: 'ticket:billing-2026', note: 'Reviewed host audit evidence and counter epochs',
  expected: { instanceVersion: instance.version, hostId: host.id, incusId: instance.incusId, requestedAt: requestedAt.toISOString() } }
try {
  assert.equal((await app.inject({ method: 'GET', url: path, headers: { 'x-test-user': 'customer' } })).statusCode, 403)
  assert.equal((await app.inject({ method: 'POST', url: path, headers: { 'x-test-user': 'customer' }, payload })).statusCode, 403)
  await prisma.user.update({ where: { id: admin.id }, data: { role: 'user' } })
  assert.equal((await app.inject({ method: 'GET', url: path })).statusCode, 403)
  assert.equal((await app.inject({ method: 'POST', url: path, payload })).statusCode, 403)
  await prisma.user.update({ where: { id: admin.id }, data: { role: 'admin' } })
  assert.equal((await app.inject({ method: 'POST', url: path, payload: { ...payload, category: 'hourly' } })).json().code, 'REVIEW_CATEGORY_MISMATCH')
  assert.equal((await app.inject({ method: 'POST', url: path, payload: { ...payload, expected: { ...payload.expected, hostId: host.id + 1 } } })).json().code, 'REVIEW_SNAPSHOT_STALE')
  assert.equal((await app.inject({ method: 'POST', url: path, payload: { ...payload, evidenceReference: 'short' } })).statusCode, 400)
  const attempts = await Promise.all(Array.from({ length: 3 }, () => app.inject({ method: 'POST', url: path, payload })))
  assert.equal(attempts.filter(result => result.statusCode === 200 && result.json().result === 'recorded').length, 1)
  assert.ok(attempts.every(result => result.statusCode === 200 || result.statusCode === 409))
  assert.equal((await app.inject({ method: 'POST', url: path, payload })).json().result, 'already_recorded')
  assert.equal((await app.inject({ method: 'POST', url: path, payload: { ...payload, note: 'A different evidence note for the same request' } })).json().code, 'REVIEW_REQUEST_CONFLICT')
  const listed = await app.inject({ method: 'GET', url: path })
  assert.equal(listed.statusCode, 200)
  assert.equal(listed.json().reviews.length, 1)
  assert.equal(listed.json().reviews[0].evidenceReference, payload.evidenceReference)
  const triggerName = `test_billing_review_${tag}`
  await prisma.$executeRawUnsafe(`CREATE FUNCTION "${triggerName}"() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.instance_id = ${instance.id} AND NEW.action = 'instance.deletion_billing_review_noted' THEN RAISE EXCEPTION 'simulated review audit failure'; END IF; RETURN NEW; END $$`)
  try {
    await prisma.$executeRawUnsafe(`CREATE TRIGGER "${triggerName}" BEFORE INSERT ON logs FOR EACH ROW EXECUTE FUNCTION "${triggerName}"()`)
    const failed = await app.inject({ method: 'POST', url: path, payload: { ...payload, requestId: randomUUID() } })
    assert.equal(failed.statusCode, 500)
    assert.equal(await prisma.log.count({ where: { instanceId: instance.id, action: 'instance.deletion_billing_review_noted' } }), 1)
  } finally {
    await prisma.$executeRawUnsafe(`DROP TRIGGER IF EXISTS "${triggerName}" ON logs`)
    await prisma.$executeRawUnsafe(`DROP FUNCTION "${triggerName}"()`)
  }
  assert.equal((await prisma.instance.findUniqueOrThrow({ where: { id: instance.id } })).status, 'deleting')
  assert.equal(await prisma.ipAddress.count({ where: { instanceId: instance.id } }), 1)
  assert.equal(Number((await prisma.user.findUniqueOrThrow({ where: { id: user.id } })).balance), 10)
  assert.equal(await prisma.trafficBillingRecord.count({ where: { instanceId: instance.id } }), 0)
  const currentHost = await prisma.host.findUniqueOrThrow({ where: { id: host.id } })
  assert.deepEqual([currentHost.cpuUsed, currentHost.memoryUsed, currentHost.diskUsed, currentHost.natPortsUsedCount], [10, 128, 512, 2])
  await prisma.instance.update({ where: { id: instance.id }, data: { version: { increment: 1 } } })
  const stale = await app.inject({ method: 'POST', url: path, payload: { ...payload, requestId: randomUUID() } })
  assert.equal(stale.statusCode, 409)
  assert.equal(stale.json().code, 'REVIEW_SNAPSHOT_STALE')
  const audit = await prisma.log.findFirstOrThrow({ where: { instanceId: instance.id, action: 'instance.deletion_billing_review_noted' } })
  const rollback = new Error('rollback fixture')
  await assert.rejects(prisma.$transaction(async tx => {
    await tx.log.update({ where: { id: audit.id }, data: { createdAt: new Date(Date.now() - 100 * 86400000) } })
    await cleanOldLogs(90, tx)
    assert.ok(await tx.log.findUnique({ where: { id: audit.id } }))
    throw rollback
  }), error => error === rollback)
  console.log('deletion billing review PostgreSQL integration tests passed')
} finally { await app.close(); await prisma.$disconnect() }
process.exit(0)
