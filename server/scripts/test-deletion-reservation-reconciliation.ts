import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import Fastify from 'fastify'
const url = process.env.DATABASE_URL ?? ''
let local = false
try {
  const u = new URL(url), p = u.hostname.split('.').map(Number)
  const ipv4 = p.length === 4 && p.every(n => Number.isInteger(n) && n >= 0 && n <= 255)
  const privateIp = ipv4 && (p[0] === 127 || p[0] === 10 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168))
  local = ['postgres:', 'postgresql:'].includes(u.protocol) && (u.hostname === 'localhost' || privateIp) && u.pathname === '/incudal_deletion_test'
} catch { /* invalid URL */ }
if (!local || process.env.INSTANCE_DELETION_TEST_ALLOW !== '1' || url !== process.env.INSTANCE_DELETION_TEST_DATABASE_URL) {
  throw new Error('Requires opt-in and dedicated local deletion test database')
}
const { prisma } = await import('../src/db/prisma.js')
const { default: routes } = await import('../src/routes/deletion-reservation-reconciliation.js')
const { processPendingInstanceDeletion } = await import('../src/services/pending-instance-deletion.js')
const { cleanOldLogs } = await import('../src/db/logs.js')
const tag = `${Date.now()}_${Math.floor(Math.random() * 100000)}`
const admin = await prisma.user.create({ data: { username: `recon_admin_${tag}`, passwordHash: 'test-only', role: 'admin' } })
const customer = await prisma.user.create({ data: { username: `recon_user_${tag}`, passwordHash: 'test-only', role: 'user' } })
const host = await prisma.host.create({ data: { userId: admin.id, name: `recon_host_${tag}`, url: 'https://127.0.0.1:1', status: 'online', cpuUsed: 10, memoryUsed: 256, diskUsed: 512, natPortsUsedCount: 2 } })
const instance = await prisma.instance.create({ data: { incusId: `recon_${tag}`, name: `recon_${tag}`, userId: customer.id, hostId: host.id, image: 'test', status: 'deleting', deletionOriginalStatus: 'running', deletionRemoteDeleted: true, cpu: 10, memory: 256, disk: 512, portLimit: 2 } })
const app = Fastify()
app.decorateRequest('user', null)
app.decorate('authenticate', async (request: any) => { request.user = request.headers['x-test-user'] === 'customer' ? { id: customer.id, role: 'user' } : { id: admin.id, role: 'admin' } })
app.decorate('requireAdmin', async (request: any, reply: any) => { if (request.user.role !== 'admin') return reply.code(403).send({ code: 'FORBIDDEN' }) })
await app.register(routes)
const path = `/api/admin/instances/${instance.id}/deletion-reservation-reconciliation`
const expected = { instanceVersion: instance.version, hostId: host.id, cpu: 10, memory: 256, disk: 512, portCount: 2, hostEpoch: host.reservationEpoch.toString() }
const payload = { requestId: randomUUID(), state: 'reserved', evidenceReference: 'ticket:2026-0001', reason: 'verified original reservation records', expected }
try {
  const nonAdminGet = await app.inject({ method: 'GET', url: path, headers: { 'x-test-user': 'customer' } })
  assert.equal(nonAdminGet.statusCode, 403)
  const nonAdminPost = await app.inject({ method: 'POST', url: path, headers: { 'x-test-user': 'customer' }, payload })
  assert.equal(nonAdminPost.statusCode, 403)
  const snapshot = await app.inject({ method: 'GET', url: path })
  assert.equal(snapshot.statusCode, 200)
  assert.equal(snapshot.json().instance.portCount, 2)
  assert.equal(snapshot.json().host.reservationEpoch, expected.hostEpoch)
  assert.equal(snapshot.json().host.status, 'online')
  assert.equal(snapshot.json().instance.billingMode, 'package')
  assert.equal(snapshot.json().instance.trafficBillingMode, 'package')
  assert.equal(snapshot.json().instance.deletionBillingMode, null)
  assert.equal(snapshot.json().instance.deletionOriginalStatus, 'running')
  assert.equal(snapshot.json().instance.provisioningCleanupPending, false)
  assert.equal(snapshot.json().reservation, null)
  await prisma.instance.update({ where: { id: instance.id }, data: {
    billingMode: 'hourly', trafficBillingMode: 'usage', deletionBillingMode: 'user_destroy', deletionBillingPending: true
  } })
  const billingSnapshot = await app.inject({ method: 'GET', url: path })
  assert.equal(billingSnapshot.statusCode, 200)
  assert.equal(billingSnapshot.json().instance.billingMode, 'hourly')
  assert.equal(billingSnapshot.json().instance.trafficBillingMode, 'usage')
  assert.equal(billingSnapshot.json().instance.deletionBillingMode, 'user_destroy')
  assert.equal(billingSnapshot.json().instance.deletionBillingPending, true)
  await prisma.instance.update({ where: { id: instance.id }, data: {
    billingMode: 'package', trafficBillingMode: 'package', deletionBillingMode: null, deletionBillingPending: false
  } })
  for (const bad of [
    { ...payload, reason: 'too short' },
    { ...payload, evidenceReference: 'short' },
    { ...payload, expected: { ...expected, hostEpoch: 0 } },
    { ...payload, requestId: null },
    { ...payload, expected: { ...expected, portCount: 1 } },
    { ...payload, expected: { ...expected, hostId: host.id + 1 } },
    { ...payload, expected: { ...expected, hostEpoch: '999' } }
  ]) {
    const response = await app.inject({ method: 'POST', url: path, payload: bad })
    assert.ok([400, 409].includes(response.statusCode), response.body)
  }
  await prisma.instance.update({ where: { id: instance.id }, data: { deletionRemoteDeleted: false } })
  const pendingSnapshot = await app.inject({ method: 'GET', url: path })
  assert.equal(pendingSnapshot.statusCode, 200)
  assert.equal(pendingSnapshot.json().instance.deletionRemoteDeleted, false)
  const unconfirmed = await app.inject({ method: 'POST', url: path, payload })
  assert.equal(unconfirmed.statusCode, 409)
  assert.equal(unconfirmed.json().code, 'REMOTE_DELETION_NOT_CONFIRMED')
  await prisma.instance.update({ where: { id: instance.id }, data: { deletionRemoteDeleted: true } })
  await prisma.user.update({ where: { id: admin.id }, data: { role: 'user' } })
  const revoked = await app.inject({ method: 'POST', url: path, payload })
  assert.equal(revoked.statusCode, 403)
  await prisma.user.update({ where: { id: admin.id }, data: { role: 'admin' } })
  // Requests can race; at most one audit/evidence write succeeds. Lock-busy
  // responses are safe to retry with the same idempotency key.
  const results = await Promise.all(Array.from({ length: 4 }, () => app.inject({ method: 'POST', url: path, payload })))
  assert.equal(results.filter(r => r.statusCode === 200 && r.json().result === 'recorded').length, 1)
  assert.ok(results.every(r => r.statusCode === 200 || (r.statusCode === 409 && r.json().code === 'INSTANCE_OPERATION_IN_PROGRESS')))
  const retry = await app.inject({ method: 'POST', url: path, payload })
  assert.equal(retry.json().result, 'already_recorded')
  const conflict = await app.inject({ method: 'POST', url: path, payload: { ...payload, state: 'released' } })
  assert.equal(conflict.statusCode, 409)
  assert.equal(conflict.json().code, 'RECONCILIATION_REQUEST_CONFLICT')
  assert.equal(await prisma.log.count({ where: { instanceId: instance.id, action: 'instance.deletion_reservation_reconciled' } }), 1)
  const audit = await prisma.log.findFirstOrThrow({ where: { instanceId: instance.id, action: 'instance.deletion_reservation_reconciled' } })
  assert.equal(JSON.parse(audit.content).instanceId, instance.id)
  assert.equal(JSON.parse(audit.content).actorId, admin.id)
  // Exercise the real retention function inside a rolled-back fixture
  // transaction, so no logs from other tests or users are removed.
  const rollback = new Error('rollback retention fixture')
  await assert.rejects(prisma.$transaction(async tx => {
    const old = new Date(Date.now() - 100 * 24 * 60 * 60 * 1000)
    await tx.log.update({ where: { id: audit.id }, data: { createdAt: old } })
    const ordinary = await tx.log.create({ data: { userId: admin.id, instanceId: instance.id, module: 'instance', action: `retention_test_${tag}`, content: 'fixture', result: 'success', createdAt: old } })
    await cleanOldLogs(90, tx)
    assert.ok(await tx.log.findUnique({ where: { id: audit.id } }), 'reconciliation audit and idempotency key survive normal log retention')
    assert.equal(await tx.log.findUnique({ where: { id: ordinary.id } }), null)
    throw rollback
  }), error => error === rollback)
  assert.deepEqual(await prisma.host.findUnique({ where: { id: host.id }, select: { cpuUsed: true, memoryUsed: true, diskUsed: true, natPortsUsedCount: true } }), { cpuUsed: 10, memoryUsed: 256, diskUsed: 512, natPortsUsedCount: 2 })
  assert.ok(await processPendingInstanceDeletion(instance.id, { async ensureDeleted() { throw new Error('already remotely absent') }, async deleteProxySite() {} }))
  const after = await prisma.host.findUniqueOrThrow({ where: { id: host.id } })
  assert.deepEqual([after.cpuUsed, after.memoryUsed, after.diskUsed, after.natPortsUsedCount], [0, 0, 0, 0])
  const lateRetry = await app.inject({ method: 'POST', url: path, payload })
  assert.equal(lateRetry.json().result, 'already_recorded')
  const secondRequest = await app.inject({ method: 'POST', url: path, payload: { ...payload, requestId: randomUUID() } })
  assert.equal(secondRequest.statusCode, 409)

  const insufficientHost = await prisma.host.create({ data: { userId: admin.id, name: `recon_insufficient_${tag}`, url: 'https://127.0.0.1:1', cpuUsed: 1, memoryUsed: 256, diskUsed: 512, natPortsUsedCount: 2 } })
  const insufficient = await prisma.instance.create({ data: { incusId: `recon_bad_${tag}`, name: `recon_bad_${tag}`, userId: customer.id, hostId: insufficientHost.id, image: 'test', status: 'deleting', deletionOriginalStatus: 'running', deletionRemoteDeleted: true, cpu: 10, memory: 256, disk: 512, portLimit: 2 } })
  const insufficientResponse = await app.inject({ method: 'POST', url: `/api/admin/instances/${insufficient.id}/deletion-reservation-reconciliation`, payload: { ...payload, requestId: randomUUID(), expected: { ...expected, instanceVersion: insufficient.version, hostId: insufficientHost.id, hostEpoch: insufficientHost.reservationEpoch.toString() } } })
  assert.equal(insufficientResponse.statusCode, 409)
  assert.equal(insufficientResponse.json().code, 'HOST_COUNTERS_INSUFFICIENT')
  assert.equal(await prisma.instanceResourceReservation.count({ where: { instanceId: insufficient.id } }), 0)

  // Independently confirmed already-released resources must never be
  // subtracted again from a host's remaining instances on finalization.
  const releasedHost = await prisma.host.create({ data: { userId: admin.id, name: `recon_released_${tag}`, url: 'https://127.0.0.1:1', status: 'online', cpuUsed: 20, memoryUsed: 512, diskUsed: 1024, natPortsUsedCount: 4 } })
  const released = await prisma.instance.create({ data: { incusId: `recon_released_${tag}`, name: `recon_released_${tag}`, userId: customer.id, hostId: releasedHost.id, image: 'test', status: 'deleting', deletionOriginalStatus: 'error', deletionRemoteDeleted: true, cpu: 10, memory: 256, disk: 512, portLimit: 2 } })
  const releasedResponse = await app.inject({ method: 'POST', url: `/api/admin/instances/${released.id}/deletion-reservation-reconciliation`, payload: {
    ...payload, state: 'released', requestId: randomUUID(), expected: { ...expected, instanceVersion: released.version, hostId: releasedHost.id, hostEpoch: releasedHost.reservationEpoch.toString() }
  } })
  assert.equal(releasedResponse.statusCode, 200, releasedResponse.body)
  assert.ok(await processPendingInstanceDeletion(released.id, { async ensureDeleted() { throw new Error('already remotely absent') }, async deleteProxySite() {} }))
  const stillReserved = await prisma.host.findUniqueOrThrow({ where: { id: releasedHost.id } })
  assert.deepEqual([stillReserved.cpuUsed, stillReserved.memoryUsed, stillReserved.diskUsed, stillReserved.natPortsUsedCount], [20, 512, 1024, 4])

  // A concurrent host counter writer holds the same row lock. The observed
  // epoch must be checked after that writer commits, not from a stale read.
  const raceHost = await prisma.host.create({ data: { userId: admin.id, name: `recon_race_${tag}`, url: 'https://127.0.0.1:1', cpuUsed: 10, memoryUsed: 256, diskUsed: 512, natPortsUsedCount: 2 } })
  const raceInstance = await prisma.instance.create({ data: { incusId: `recon_race_${tag}`, name: `recon_race_${tag}`, userId: customer.id, hostId: raceHost.id, image: 'test', status: 'deleting', deletionOriginalStatus: 'running', deletionRemoteDeleted: true, cpu: 10, memory: 256, disk: 512, portLimit: 2 } })
  let locked!: () => void, release!: () => void
  const hasLock = new Promise<void>(resolve => { locked = resolve })
  const wait = new Promise<void>(resolve => { release = resolve })
  const writer = prisma.$transaction(async tx => {
    await tx.host.update({ where: { id: raceHost.id }, data: { cpuUsed: { increment: 1 } } })
    locked()
    await wait
  })
  await hasLock
  const racingRequest = app.inject({ method: 'POST', url: `/api/admin/instances/${raceInstance.id}/deletion-reservation-reconciliation`, payload: {
    ...payload, requestId: randomUUID(), expected: { ...expected, instanceVersion: raceInstance.version, hostId: raceHost.id, hostEpoch: raceHost.reservationEpoch.toString() }
  } })
  await new Promise(resolve => setTimeout(resolve, 100))
  release()
  await writer
  const racingResponse = await racingRequest
  assert.equal(racingResponse.statusCode, 409, racingResponse.body)
  assert.equal(racingResponse.json().code, 'RECONCILIATION_SNAPSHOT_STALE')
  assert.equal(await prisma.instanceResourceReservation.count({ where: { instanceId: raceInstance.id } }), 0)

  // A failed audit write must roll back the evidence row in the same
  // transaction; this temporary trigger only affects this fresh fixture.
  const atomicHost = await prisma.host.create({ data: { userId: admin.id, name: `recon_atomic_${tag}`, url: 'https://127.0.0.1:1', cpuUsed: 10, memoryUsed: 256, diskUsed: 512, natPortsUsedCount: 2 } })
  const atomicInstance = await prisma.instance.create({ data: { incusId: `recon_atomic_${tag}`, name: `recon_atomic_${tag}`, userId: customer.id, hostId: atomicHost.id, image: 'test', status: 'deleting', deletionOriginalStatus: 'running', deletionRemoteDeleted: true, cpu: 10, memory: 256, disk: 512, portLimit: 2 } })
  const triggerName = `test_recon_${tag}`
  await prisma.$executeRawUnsafe(`CREATE FUNCTION "${triggerName}"() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.instance_id = ${atomicInstance.id} THEN RAISE EXCEPTION 'simulated audit failure'; END IF; RETURN NEW; END $$`)
  try {
    await prisma.$executeRawUnsafe(`CREATE TRIGGER "${triggerName}" BEFORE INSERT ON logs FOR EACH ROW EXECUTE FUNCTION "${triggerName}"()`)
    const failed = await app.inject({ method: 'POST', url: `/api/admin/instances/${atomicInstance.id}/deletion-reservation-reconciliation`, payload: {
      ...payload, requestId: randomUUID(), expected: { ...expected, instanceVersion: atomicInstance.version, hostId: atomicHost.id, hostEpoch: atomicHost.reservationEpoch.toString() }
    } })
    assert.equal(failed.statusCode, 500)
    assert.equal(await prisma.instanceResourceReservation.count({ where: { instanceId: atomicInstance.id } }), 0)
    assert.equal(await prisma.log.count({ where: { instanceId: atomicInstance.id, action: 'instance.deletion_reservation_reconciled' } }), 0)
  } finally {
    await prisma.$executeRawUnsafe(`DROP TRIGGER IF EXISTS "${triggerName}" ON logs`)
    await prisma.$executeRawUnsafe(`DROP FUNCTION "${triggerName}"()`)
  }
  console.log('deletion reservation reconciliation PostgreSQL integration tests passed')
} finally { await app.close(); await prisma.$disconnect() }
process.exit(0)
