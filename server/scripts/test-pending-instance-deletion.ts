import assert from 'node:assert/strict'
import type { PendingDeletionRemoteOperations } from '../src/services/pending-instance-deletion.js'
import Fastify from 'fastify'

const testUrl = process.env.DATABASE_URL ?? ''
let validLocalUrl = false
try {
  const url = new URL(testUrl)
  const octets = url.hostname.split('.').map(Number)
  const validIpv4 = octets.length === 4 && octets.every(n => Number.isInteger(n) && n >= 0 && n <= 255)
  const privateAddress = validIpv4 && (octets[0] === 10 || (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) || (octets[0] === 192 && octets[1] === 168) || (octets[0] === 127))
  const port = Number(url.port || '5432')
  validLocalUrl = ['postgres:', 'postgresql:'].includes(url.protocol) && (url.hostname === 'localhost' || privateAddress)
    && url.pathname === '/incudal_deletion_test' && Number.isInteger(port) && port >= 1 && port <= 65535
} catch { /* invalid URL */ }
if (process.env.INSTANCE_DELETION_TEST_ALLOW !== '1' || testUrl !== process.env.INSTANCE_DELETION_TEST_DATABASE_URL || !validLocalUrl) {
  throw new Error('This destructive fixture test only runs against the dedicated local deletion test database')
}
// Load DB modules only after validating the opt-in and database URL: prisma.ts
// performs startup normalization as a module side effect.
const { prisma } = await import('../src/db/prisma.js')
const { claimInstanceForDelete } = await import('../src/routes/instances/helpers.js')
const { processPendingInstanceDeletion } = await import('../src/services/pending-instance-deletion.js')
const { pauseHourlyBilling, settleHourlyInstance } = await import('../src/services/hourly-billing-scheduler.js')
const { recordNewInstanceReservation } = await import('../src/db/resource-reservation-evidence.js')
const { default: instanceRoutes } = await import('../src/routes/instances.js')
const { default: adminBillingRoutes } = await import('../src/routes/admin-billing.js')
const { default: proxySitesRoutes } = await import('../src/routes/proxy-sites.js')
const { default: instanceDestroyRoutes } = await import('../src/routes/instance-destroy.js')
const { createInstanceTask } = await import('../src/db/instance-tasks.js')
const { createRestoreTask } = await import('../src/db/restore-tasks.js')
const { createBackupUploadTask } = await import('../src/db/backup-upload-tasks.js')
const { withInstanceRemoteOperationLock, withInstanceAndDomainRemoteOperationLock } = await import('../src/services/instance-remote-operation-lock.js')
const suffix = `${Date.now()}_${Math.floor(Math.random() * 100000)}`
const owner = await prisma.user.create({ data: { username: `del_owner_${suffix}`, passwordHash: 'test-only', role: 'admin' } })
const customer = await prisma.user.create({ data: { username: `del_customer_${suffix}`, passwordHash: 'test-only', balance: 10 } })
const pkg = await prisma.package.create({ data: { userId: owner.id, name: `del_pkg_${suffix}`, cpuMax: 100, memoryMax: 1024, diskMax: 2048 } })
const plan = await prisma.packagePlan.create({ data: { packageId: pkg.id, name: 'test', cpu: 10, memory: 256, disk: 512, portLimit: 2, snapshotLimit: 1, backupLimit: 1, siteLimit: 1, trafficLimit: 1000n, price: 100 } })
const now = Date.now()
const begin = new Date(now - 30 * 86400000)
const end = new Date(now + 30 * 86400000)
const requestedAt = new Date(now - 15 * 86400000)
let remoteCalls = 0
let failRemote = false
let gate: (() => Promise<void>) | undefined
let siteGate: (() => Promise<void>) | undefined
const remote: PendingDeletionRemoteOperations = {
  async ensureDeleted() { remoteCalls++; if (gate) await gate(); if (failRemote) throw new Error('simulated remote failure') },
  async deleteProxySite() { if (siteGate) await siteGate() }
}
async function makeFixture(name: string, status: 'online' | 'offline', counters = true) {
  const host = await prisma.host.create({ data: { userId: owner.id, name, url: 'https://127.0.0.1:1', status, cpuUsed: counters ? 10 : 0, memoryUsed: counters ? 256 : 0, diskUsed: counters ? 512 : 0, natPortsUsedCount: counters ? 2 : 0 } })
  const instance = await prisma.$transaction(async tx => {
    const row = await tx.instance.create({ data: { incusId: name, name, userId: customer.id, hostId: host.id, packageId: pkg.id, packagePlanId: plan.id, image: 'test', status: 'running', cpu: 10, memory: 256, disk: 512, portLimit: 2, expiresAt: end, billingPrice: 100, billingCycle: 1 } })
    await recordNewInstanceReservation(tx, { instanceId: row.id, hostId: host.id, cpu: 10, memory: 256, disk: 512, portCount: 2 })
    return row
  })
  await prisma.instanceBillingRecord.create({ data: { instanceId: instance.id, userId: customer.id, type: 'newPurchase', amount: 100, periodStart: begin, periodEnd: end } })
  return { host, instance }
}
async function makeFreeFixture(name: string) {
  const host = await prisma.host.create({ data: { userId: owner.id, name, url: 'https://127.0.0.1:1', status: 'offline', cpuUsed: 10, memoryUsed: 256, diskUsed: 512, natPortsUsedCount: 2 } })
  const instance = await prisma.$transaction(async tx => {
    const row = await tx.instance.create({ data: { incusId: name, name, userId: customer.id, hostId: host.id, packageId: pkg.id, image: 'test', status: 'running', cpu: 10, memory: 256, disk: 512, portLimit: 2 } })
    await recordNewInstanceReservation(tx, { instanceId: row.id, hostId: host.id, cpu: 10, memory: 256, disk: 512, portCount: 2 })
    return row
  })
  return { host, instance }
}
async function authorizationSnapshot(id: number, actorUserId = owner.id, actorRole: 'admin' | 'user' = 'admin', scope: 'instance-or-host' | 'host-only' = 'instance-or-host') {
  const instance = await prisma.instance.findUniqueOrThrow({ where: { id }, include: { host: true } })
  return {
    actorUserId, actorRole, scope,
    expectedUserId: instance.userId, expectedHostId: instance.hostId,
    expectedHostUserId: instance.host.userId, expectedIncusId: instance.incusId,
    expectedVersion: instance.version, expectedPackagePlanId: instance.packagePlanId,
    expectedPackageId: instance.packageId, expectedSuspendReason: instance.suspendReason,
    expectedBillingMode: instance.billingMode, expectedTrafficBillingMode: instance.trafficBillingMode
  }
}
async function claim(id: number, status: 'running' | 'error' | 'creating' = 'running') {
  const authorization = await authorizationSnapshot(id)
  return claimInstanceForDelete(id, status, { authorization, deletionBillingPending: true, deletionBillingMode: 'privileged_delete', pending: { requestedById: owner.id } })
}
async function balance() { return Number((await prisma.user.findUniqueOrThrow({ where: { id: customer.id } })).balance) }
try {
  const first = await makeFixture(`del_first_${suffix}`, 'offline')
  const claims = await Promise.all([claim(first.instance.id), claim(first.instance.id)])
  assert.equal(claims.filter(Boolean).length, 1, 'only one duplicate deletion claim succeeds')
  await prisma.instance.update({ where: { id: first.instance.id }, data: { deletionRequestedAt: requestedAt } })
  await assert.rejects(processPendingInstanceDeletion(first.instance.id, remote), /unavailable/)
  assert.equal(remoteCalls, 0)
  assert.equal(await balance(), 10)
  assert.equal((await prisma.host.findUniqueOrThrow({ where: { id: first.host.id } })).cpuUsed, 10)
  assert.equal((await prisma.instance.findUniqueOrThrow({ where: { id: first.instance.id } })).status, 'deleting')
  await prisma.host.update({ where: { id: first.host.id }, data: { status: 'online' } })
  failRemote = true
  await assert.rejects(processPendingInstanceDeletion(first.instance.id, remote), /simulated remote failure/)
  assert.equal(await balance(), 10)
  assert.equal((await prisma.host.findUniqueOrThrow({ where: { id: first.host.id } })).cpuUsed, 10)
  failRemote = false
  let release!: () => void
  let entered!: () => void
  const enteredPromise = new Promise<void>(resolve => { entered = resolve })
  const wait = new Promise<void>(resolve => { release = resolve })
  gate = async () => { entered(); await wait }
  const running = processPendingInstanceDeletion(first.instance.id, remote)
  await enteredPromise
  const concurrent = await processPendingInstanceDeletion(first.instance.id, remote)
  assert.equal(concurrent, null, 'concurrent worker cannot acquire session lock')
  const snapshotLock = await withInstanceRemoteOperationLock(first.instance.id, async () => true)
  assert.equal(snapshotLock.acquired, false, 'snapshot and pending worker share the same session lock')
  release()
  const completed = await running
  gate = undefined
  assert.equal(completed?.refundAmount, 75)
  assert.equal(await balance(), 85)
  assert.equal((await prisma.host.findUniqueOrThrow({ where: { id: first.host.id } })).cpuUsed, 0)
  assert.equal((await prisma.instance.findUniqueOrThrow({ where: { id: first.instance.id } })).status, 'deleted')
  await Promise.all(Array.from({ length: 5 }, () => processPendingInstanceDeletion(first.instance.id, remote)))
  assert.equal(await balance(), 85)
  assert.equal(await prisma.instanceBillingRecord.count({ where: { instanceId: first.instance.id, type: 'refund' } }), 1)

  const second = await makeFixture(`del_rollback_${suffix}`, 'online', false)
  assert.equal(await claim(second.instance.id), true)
  await prisma.instance.update({ where: { id: second.instance.id }, data: { deletionRequestedAt: requestedAt } })
  await assert.rejects(processPendingInstanceDeletion(second.instance.id, remote), /counters are lower/)
  const afterFailure = await prisma.instance.findUniqueOrThrow({ where: { id: second.instance.id } })
  assert.equal(afterFailure.status, 'deleting', 'status update rolled back with resource release')
  assert.equal(afterFailure.deletionRemoteDeleted, true)
  assert.equal(afterFailure.deletionBillingPending, false)
  assert.equal(await balance(), 160)
  const priorRemoteCalls = remoteCalls
  // Simulate trusted fixture reconciliation after repairing intentionally invalid counters.
  // Production must not infer reservation provenance from aggregate counters.
  await prisma.$transaction(async tx => {
    await tx.host.update({ where: { id: second.host.id }, data: { cpuUsed: 10, memoryUsed: 256, diskUsed: 512, natPortsUsedCount: 2 } })
    await tx.instanceResourceReservation.delete({ where: { instanceId: second.instance.id } })
    await recordNewInstanceReservation(tx, { instanceId: second.instance.id, hostId: second.host.id, cpu: 10, memory: 256, disk: 512, portCount: 2 })
  })
  assert.ok(await processPendingInstanceDeletion(second.instance.id, remote))
  assert.equal(remoteCalls, priorRemoteCalls, 'confirmed deletion is not reissued')
  assert.equal(await balance(), 160, 'retry never duplicates refund')
  assert.equal(await prisma.instanceBillingRecord.count({ where: { instanceId: second.instance.id, type: 'refund' } }), 1)

  // A disabled or unconfigured Caddy is not proof that an old route is gone;
  // the IP/counters must remain reserved until cleanup can be confirmed.
  const siteFixture = await makeFixture(`del_caddy_${suffix}`, 'online')
  const domain = `site-${suffix.replace('_', '-')}.example`
  await prisma.proxySite.create({ data: { instanceId: siteFixture.instance.id, hostId: siteFixture.host.id, domain, targetPort: 80 } })
  assert.equal(await claim(siteFixture.instance.id), true)
  await assert.rejects(processPendingInstanceDeletion(siteFixture.instance.id, remote), /Caddy site removal cannot be confirmed/)
  assert.equal((await prisma.instance.findUniqueOrThrow({ where: { id: siteFixture.instance.id } })).status, 'deleting')
  assert.equal((await prisma.host.findUniqueOrThrow({ where: { id: siteFixture.host.id } })).cpuUsed, 10)
  await prisma.host.update({ where: { id: siteFixture.host.id }, data: { caddyEnabled: true } })
  await assert.rejects(processPendingInstanceDeletion(siteFixture.instance.id, remote), /Caddy site removal cannot be confirmed/)
  assert.equal(await prisma.proxySite.count({ where: { instanceId: siteFixture.instance.id } }), 1)
  await prisma.host.update({ where: { id: siteFixture.host.id }, data: { caddyUsername: 'test-user', caddyPassword: 'test-only', natPublicIp: '192.0.2.1' } })
  let siteEntered!: () => void
  let releaseSite!: () => void
  const siteEnteredPromise = new Promise<void>(resolve => { siteEntered = resolve })
  const siteWait = new Promise<void>(resolve => { releaseSite = resolve })
  siteGate = async () => { siteEntered(); await siteWait }
  const siteDeletion = processPendingInstanceDeletion(siteFixture.instance.id, remote)
  await siteEnteredPromise
  assert.deepEqual(await withInstanceAndDomainRemoteOperationLock(siteFixture.instance.id + 1000000, domain, async () => true), { acquired: false }, 'worker and other instances serialize Caddy domain operations')
  releaseSite()
  await siteDeletion
  siteGate = undefined
  assert.equal((await prisma.instance.findUniqueOrThrow({ where: { id: siteFixture.instance.id } })).status, 'deleted')
  assert.equal(await prisma.proxySite.count({ where: { instanceId: siteFixture.instance.id } }), 0)

  const app = Fastify()
  app.decorateRequest('user', null)
  const authenticate = async (request: any) => { request.user = request.headers['x-test-user'] === 'customer'
    ? { id: customer.id, role: 'user', username: customer.username }
    : { id: owner.id, role: 'admin', username: owner.username } }
  app.decorate('authenticate', authenticate)
  app.decorate('authenticateUser', authenticate)
  app.decorate('requireAdmin', authenticate)
  await app.register(instanceRoutes, { prefix: '/api/instances' })
  await app.register(instanceDestroyRoutes, { prefix: '/api/instances' })
  await app.register(proxySitesRoutes, { prefix: '/api' })
  await app.register(adminBillingRoutes)
  const offline = await makeFixture(`del_http_${suffix}`, 'offline')
  const beforeHttp = await balance()
  const response = await app.inject({ method: 'DELETE', url: `/api/instances/${offline.instance.id}`, payload: {} })
  assert.equal(response.statusCode, 202, response.body)
  assert.equal(response.json().status, 'deleting')
  assert.equal(await balance(), beforeHttp)
  assert.equal((await prisma.host.findUniqueOrThrow({ where: { id: offline.host.id } })).cpuUsed, 10)
  assert.equal((await prisma.instance.findUniqueOrThrow({ where: { id: offline.instance.id } })).status, 'deleting')
  const pendingSite = await prisma.proxySite.create({ data: {
    instanceId: offline.instance.id, hostId: offline.host.id, domain: `locked-${suffix.replace('_', '-')}.example`, targetPort: 80
  } })
  for (const operation of [
    { method: 'POST', url: `/api/instances/${offline.instance.id}/sites`, payload: { domain: `new-${suffix.replace('_', '-')}.example`, targetPort: 80 } },
    { method: 'DELETE', url: `/api/instances/${offline.instance.id}/sites/${pendingSite.id}` },
    { method: 'POST', url: `/api/instances/${offline.instance.id}/sites/${pendingSite.id}/check-dns` },
    { method: 'POST', url: `/api/instances/${offline.instance.id}/sites/${pendingSite.id}/refresh` },
    { method: 'PATCH', url: `/api/instances/${offline.instance.id}/sites/${pendingSite.id}`, payload: { remark: 'blocked' } },
    { method: 'POST', url: `/api/instances/${offline.instance.id}/sites/${pendingSite.id}/toggle` }
  ] as const) {
    // The HTTP deletion handler may still hold the session lock briefly while
    // its initial offline attempt exits. Both responses reject the mutation;
    // retry until we can also assert the persisted deleting-state guard.
    let blocked = await app.inject({ ...operation, headers: { 'x-test-user': 'customer' } })
    for (let retry = 0; blocked.json().code === 'INSTANCE_OPERATION_IN_PROGRESS' && retry < 100; retry++) {
      await new Promise(resolve => setTimeout(resolve, 20))
      blocked = await app.inject({ ...operation, headers: { 'x-test-user': 'customer' } })
    }
    assert.equal(blocked.statusCode, 409, `${operation.method} ${operation.url}: ${blocked.body}`)
    assert.equal(blocked.json().code, 'INSTANCE_DELETE_IN_PROGRESS')
  }
  assert.equal(await prisma.proxySite.count({ where: { instanceId: offline.instance.id } }), 1)

  const busySites = await makeFixture(`del_site_task_${suffix}`, 'offline')
  const busySite = await prisma.proxySite.create({ data: {
    instanceId: busySites.instance.id, hostId: busySites.host.id,
    domain: `busy-${suffix.replace('_', '-')}.example`, targetPort: 80
  } })
  const busyTask = await createInstanceTask({ instanceId: busySites.instance.id, hostId: busySites.host.id, userId: customer.id, taskType: 'start' })
  for (const operation of [
    { method: 'POST', url: `/api/instances/${busySites.instance.id}/sites`, payload: { domain: `other-${suffix.replace('_', '-')}.example`, targetPort: 80 } },
    { method: 'DELETE', url: `/api/instances/${busySites.instance.id}/sites/${busySite.id}` },
    { method: 'POST', url: `/api/instances/${busySites.instance.id}/sites/${busySite.id}/check-dns` },
    { method: 'POST', url: `/api/instances/${busySites.instance.id}/sites/${busySite.id}/refresh` },
    { method: 'PATCH', url: `/api/instances/${busySites.instance.id}/sites/${busySite.id}`, payload: { remark: 'blocked' } },
    { method: 'POST', url: `/api/instances/${busySites.instance.id}/sites/${busySite.id}/toggle` }
  ] as const) {
    const blocked = await app.inject({ ...operation, headers: { 'x-test-user': 'customer' } })
    assert.equal(blocked.statusCode, 409, `${operation.method} ${operation.url}: ${blocked.body}`)
    assert.equal(blocked.json().code, 'TASK_IN_PROGRESS')
  }
  await prisma.instanceTask.update({ where: { id: busyTask.id }, data: { status: 'FAILED' } })
  const balanceBeforeSites = await balance()
  const paidDestroy = await app.inject({ method: 'POST', url: `/api/instances/${busySites.instance.id}/destroy`, headers: { 'x-test-user': 'customer' } })
  assert.equal(paidDestroy.statusCode, 202, paidDestroy.body)
  assert.equal(paidDestroy.json().status, 'deleting')
  const batchSiteFixture = await makeFixture(`del_paid_batch_site_${suffix}`, 'offline')
  await prisma.proxySite.create({ data: { instanceId: batchSiteFixture.instance.id, hostId: batchSiteFixture.host.id,
    domain: `batch-${suffix.replace('_', '-')}.example`, targetPort: 80 } })
  const paidBatch = await app.inject({ method: 'POST', url: '/api/instances/batch/destroy', headers: { 'x-test-user': 'customer' }, payload: { instanceIds: [batchSiteFixture.instance.id] } })
  assert.equal(paidBatch.statusCode, 200, paidBatch.body)
  assert.equal(paidBatch.json().pendingCount, 1)
  const adminSiteFixture = await makeFixture(`del_admin_site_${suffix}`, 'offline')
  await prisma.proxySite.create({ data: { instanceId: adminSiteFixture.instance.id, hostId: adminSiteFixture.host.id,
    domain: `admin-${suffix.replace('_', '-')}.example`, targetPort: 80 } })
  const adminDelete = await app.inject({ method: 'POST', url: `/api/admin/instances/${adminSiteFixture.instance.id}/delete-and-refund`, payload: { refundType: 'remaining', reason: 'test deletion' } })
  assert.equal(adminDelete.statusCode, 202, adminDelete.body)
  assert.equal(adminDelete.json().status, 'deleting')
  assert.equal(await prisma.proxySite.count({ where: { instanceId: adminSiteFixture.instance.id } }), 1)
  assert.equal(await balance(), balanceBeforeSites)
  assert.equal((await prisma.instance.findUniqueOrThrow({ where: { id: busySites.instance.id } })).status, 'deleting')
  assert.equal((await prisma.host.findUniqueOrThrow({ where: { id: busySites.host.id } })).cpuUsed, 10)
  assert.equal(await prisma.proxySite.count({ where: { instanceId: busySites.instance.id } }), 1)
  assert.equal(await prisma.proxySite.count({ where: { instanceId: batchSiteFixture.instance.id } }), 1)

  const usage = await makeFixture(`del_usage_${suffix}`, 'offline')
  await prisma.instance.update({ where: { id: usage.instance.id }, data: { trafficBillingMode: 'usage' } })
  const remoteBeforeUsage = remoteCalls
  const usageResponse = await app.inject({ method: 'DELETE', url: `/api/instances/${usage.instance.id}`, payload: {} })
  assert.equal(usageResponse.statusCode, 202, usageResponse.body)
  assert.equal((await prisma.instance.findUniqueOrThrow({ where: { id: usage.instance.id } })).status, 'deleting')
  await assert.rejects(processPendingInstanceDeletion(usage.instance.id, remote), /Usage-based traffic/)
  assert.equal(remoteCalls, remoteBeforeUsage, 'unknown final usage must not trigger remote deletion')
  assert.equal((await prisma.host.findUniqueOrThrow({ where: { id: usage.host.id } })).cpuUsed, 10)
  const usageOnline = await makeFixture(`del_usage_online_${suffix}`, 'online')
  await prisma.instance.update({ where: { id: usageOnline.instance.id }, data: { trafficBillingMode: 'usage' } })
  const usageOnlineResponse = await app.inject({ method: 'DELETE', url: `/api/instances/${usageOnline.instance.id}`, payload: {} })
  assert.equal(usageOnlineResponse.statusCode, 202, usageOnlineResponse.body)
  await assert.rejects(processPendingInstanceDeletion(usageOnline.instance.id, remote), /Usage-based traffic/)
  assert.equal((await prisma.instance.findUniqueOrThrow({ where: { id: usageOnline.instance.id } })).deletionRemoteDeleted, false)

  const hourly = await makeFixture(`del_hourly_${suffix}`, 'offline')
  await prisma.instance.update({ where: { id: hourly.instance.id }, data: { billingMode: 'hourly' } })
  await prisma.user.update({ where: { id: customer.id }, data: { hourlyReservedBalance: { increment: 5 } } })
  await prisma.hourlyBillingAccount.create({ data: {
    instanceId: hourly.instance.id, status: 'active', prepaidBalance: 5,
    pricingSnapshot: { cpuUnitPercent: 5, memoryUnitMb: 64, diskUnitMb: 512, minCpu: 10, minMemoryMb: 128, minDiskMb: 512,
      cpuPricePerUnit: '0', memoryPricePerUnit: '0', diskPricePerUnit: '0', reserveQuantum: '0.01' },
    lastSettledAt: new Date(Date.now() - 60000), nextSettlementAt: new Date(Date.now() - 1000)
  } })
  const hourlyResponse = await app.inject({ method: 'DELETE', url: `/api/instances/${hourly.instance.id}`, payload: {} })
  assert.equal(hourlyResponse.statusCode, 202, hourlyResponse.body)
  const hourlyClaimed = await prisma.instance.findUniqueOrThrow({ where: { id: hourly.instance.id } })
  assert.equal(hourlyClaimed.status, 'deleting')
  assert.equal(hourlyClaimed.deletionBillingPending, true)
  assert.equal(hourlyClaimed.deletionBillingMode, 'hourly_close')
  await assert.rejects(processPendingInstanceDeletion(hourly.instance.id, remote), /Hourly billing/)
  await pauseHourlyBilling(hourly.instance.id)
  await settleHourlyInstance(hourly.instance.id)
  const hourlyAccount = await prisma.hourlyBillingAccount.findUniqueOrThrow({ where: { instanceId: hourly.instance.id } })
  assert.equal(hourlyAccount.status, 'active')
  assert.equal(hourlyAccount.prepaidBalance.toString(), '5')
  assert.equal((await prisma.user.findUniqueOrThrow({ where: { id: customer.id } })).hourlyReservedBalance.toString(), '5')
  const hourlyOnline = await makeFixture(`del_hourly_online_${suffix}`, 'online')
  await prisma.instance.update({ where: { id: hourlyOnline.instance.id }, data: { billingMode: 'hourly' } })
  const hourlyOnlineResponse = await app.inject({ method: 'DELETE', url: `/api/instances/${hourlyOnline.instance.id}`, payload: {} })
  assert.equal(hourlyOnlineResponse.statusCode, 202, hourlyOnlineResponse.body)
  await assert.rejects(processPendingInstanceDeletion(hourlyOnline.instance.id, remote), /Hourly billing/)
  assert.equal((await prisma.instance.findUniqueOrThrow({ where: { id: hourlyOnline.instance.id } })).deletionRemoteDeleted, false)

  const provisioning = await makeFixture(`del_creating_${suffix}`, 'offline')
  await prisma.instance.update({ where: { id: provisioning.instance.id }, data: { status: 'creating' } })
  const creatingResponse = await app.inject({ method: 'DELETE', url: `/api/instances/${provisioning.instance.id}`, payload: {} })
  assert.equal(creatingResponse.statusCode, 409, creatingResponse.body)
  assert.equal(creatingResponse.json().code, 'INSTANCE_PROVISION_IN_PROGRESS')
  assert.equal(await claim(provisioning.instance.id, 'creating'), false, 'pending deletion must not race provisioning')

  const uncertain = await makeFixture(`del_error_${suffix}`, 'offline')
  await prisma.instance.update({ where: { id: uncertain.instance.id }, data: { status: 'error' } })
  const errorResponse = await app.inject({ method: 'DELETE', url: `/api/instances/${uncertain.instance.id}`, payload: {} })
  assert.equal(errorResponse.statusCode, 202, errorResponse.body)
  assert.equal((await prisma.instance.findUniqueOrThrow({ where: { id: uncertain.instance.id } })).deletionOriginalStatus, 'error')
  await assert.rejects(processPendingInstanceDeletion(uncertain.instance.id, remote), /unavailable/)
  assert.equal((await prisma.host.findUniqueOrThrow({ where: { id: uncertain.host.id } })).cpuUsed, 10)
  const cleanupPending = await makeFixture(`del_cleanup_pending_${suffix}`, 'offline')
  await prisma.instance.update({ where: { id: cleanupPending.instance.id }, data: { status: 'error', provisioningCleanupPending: true } })
  const cleanupResponse = await app.inject({ method: 'DELETE', url: `/api/instances/${cleanupPending.instance.id}`, payload: {} })
  assert.equal(cleanupResponse.statusCode, 409, cleanupResponse.body)
  assert.equal((await prisma.instance.findUniqueOrThrow({ where: { id: cleanupPending.instance.id } })).status, 'error')

  // Permission is checked before claim in the route. Simulate a transfer,
  // migration, changed Incus ID and billing version before the claim commits.
  const identity = await makeFixture(`del_identity_${suffix}`, 'offline')
  const anotherHost = await makeFixture(`del_identity_host_${suffix}`, 'offline')
  await prisma.instance.update({ where: { id: identity.instance.id }, data: { packagePlanId: null } })
  const baseline = await makeFixture(`del_identity_baseline_${suffix}`, 'offline')
  await prisma.instance.update({ where: { id: baseline.instance.id }, data: { packagePlanId: null } })
  const baselineAuth = await authorizationSnapshot(baseline.instance.id, customer.id, 'user')
  assert.equal(await claimInstanceForDelete(baseline.instance.id, 'running', { authorization: baselineAuth, pending: { requestedById: customer.id } }), true, 'unchanged free owner is authorized')
  const snapshot = await authorizationSnapshot(identity.instance.id, customer.id, 'user')
  const claimWithSnapshot = () => claimInstanceForDelete(identity.instance.id, 'running', {
    authorization: snapshot, pending: { requestedById: customer.id }
  })
  for (const change of [
    { userId: owner.id }, { hostId: anotherHost.host.id }, { incusId: `changed_${suffix}` },
    { version: { increment: 1 } }, { packagePlanId: plan.id }, { packageId: null },
    { suspendReason: 'test-change' }, { trafficBillingMode: 'usage' as const }
  ]) {
    await prisma.instance.update({ where: { id: identity.instance.id }, data: change })
    assert.equal(await claimWithSnapshot(), false, 'changed identity or billing snapshot must reject old authorization')
    await prisma.instance.update({ where: { id: identity.instance.id }, data: {
      userId: snapshot.expectedUserId, hostId: snapshot.expectedHostId, incusId: snapshot.expectedIncusId,
      version: snapshot.expectedVersion, packagePlanId: snapshot.expectedPackagePlanId, packageId: snapshot.expectedPackageId,
      suspendReason: snapshot.expectedSuspendReason, billingMode: snapshot.expectedBillingMode, trafficBillingMode: 'package'
    } })
  }
  const unauthorized = { ...snapshot, actorUserId: owner.id, actorRole: 'user' as const, scope: 'host-only' as const, expectedHostUserId: customer.id }
  assert.equal(await claimInstanceForDelete(identity.instance.id, 'running', { authorization: unauthorized }), false)

  // The host owner row must remain locked from permission revalidation until
  // claim commits, not merely be checked before the transaction begins.
  const hostActor = await prisma.user.create({ data: { username: `del_host_actor_${suffix}`, passwordHash: 'test-only', role: 'user' } })
  await prisma.host.update({ where: { id: identity.host.id }, data: { userId: hostActor.id } })
  const oldHostOwner = await authorizationSnapshot(identity.instance.id, hostActor.id, 'user', 'host-only')
  let releaseHost!: () => void
  let hostChanged!: () => void
  const hostChangedPromise = new Promise<void>(resolve => { hostChanged = resolve })
  const allowHostCommit = new Promise<void>(resolve => { releaseHost = resolve })
  const ownershipChange = prisma.$transaction(async tx => {
    await tx.host.update({ where: { id: identity.host.id }, data: { userId: customer.id } })
    hostChanged()
    await allowHostCommit
  })
  await hostChangedPromise
  const oldOwnerClaim = claimInstanceForDelete(identity.instance.id, 'running', { authorization: oldHostOwner })
  await new Promise(resolve => setTimeout(resolve, 50))
  releaseHost()
  await ownershipChange
  assert.equal(await oldOwnerClaim, false, 'old host owner cannot claim after host ownership changes')
  assert.equal((await prisma.instance.findUniqueOrThrow({ where: { id: identity.instance.id } })).status, 'running')

  // A policy flip is independently versioned from the instance. It must be
  // re-read under the package row lock, even when instance.version is unchanged.
  const policyFixture = await makeFixture(`del_policy_${suffix}`, 'offline')
  await prisma.instance.update({ where: { id: policyFixture.instance.id }, data: { packagePlanId: null } })
  const freeOwnerAuth = await authorizationSnapshot(policyFixture.instance.id, customer.id, 'user')
  await prisma.package.update({ where: { id: pkg.id }, data: { allowInstanceDeletion: false } })
  assert.equal(await claimInstanceForDelete(policyFixture.instance.id, 'running', { authorization: freeOwnerAuth }), false, 'changed package policy rejects owner claim')
  await prisma.package.update({ where: { id: pkg.id }, data: { allowInstanceDeletion: true } })

  const revokedAdmin = await prisma.user.create({ data: { username: `del_revoked_admin_${suffix}`, passwordHash: 'test-only', role: 'admin' } })
  const adminSnapshot = await authorizationSnapshot(identity.instance.id, revokedAdmin.id, 'admin')
  await prisma.user.update({ where: { id: revokedAdmin.id }, data: { role: 'user' } })
  assert.equal(await claimInstanceForDelete(identity.instance.id, 'running', { authorization: adminSnapshot }), false, 'revoked admin role is rechecked')
  const userSnapshot = await authorizationSnapshot(identity.instance.id, customer.id, 'user')
  await prisma.user.update({ where: { id: customer.id }, data: { status: 'banned' } })
  assert.equal(await claimInstanceForDelete(identity.instance.id, 'running', { authorization: userSnapshot }), false, 'banned user cannot claim')
  await prisma.user.update({ where: { id: customer.id }, data: { status: 'active' } })
  const activeActorSnapshot = await authorizationSnapshot(identity.instance.id, customer.id, 'user')
  let releaseActor!: () => void
  let actorBanned!: () => void
  const actorBannedPromise = new Promise<void>(resolve => { actorBanned = resolve })
  const allowActorCommit = new Promise<void>(resolve => { releaseActor = resolve })
  const actorBan = prisma.$transaction(async tx => {
    await tx.user.update({ where: { id: customer.id }, data: { status: 'banned' } })
    actorBanned()
    await allowActorCommit
  })
  await actorBannedPromise
  const bannedActorClaim = claimInstanceForDelete(identity.instance.id, 'running', { authorization: activeActorSnapshot })
  await new Promise(resolve => setTimeout(resolve, 50))
  releaseActor()
  await actorBan
  assert.equal(await bannedActorClaim, false, 'actor authorization is re-read after concurrent ban commits')
  await prisma.user.update({ where: { id: customer.id }, data: { status: 'active' } })

  const taskFixture = await makeFixture(`del_task_${suffix}`, 'offline')
  const taskData = { instanceId: taskFixture.instance.id, hostId: taskFixture.host.id, userId: customer.id, taskType: 'start' as const }
  const task = await createInstanceTask(taskData)
  assert.equal(await claim(taskFixture.instance.id), false, 'pending instance task blocks deletion claim')
  await prisma.instanceTask.update({ where: { id: task.id }, data: { status: 'FAILED' } })
  assert.equal(await claim(taskFixture.instance.id), true)
  await assert.rejects(createInstanceTask(taskData), /INSTANCE_UNAVAILABLE_FOR_TASK/)
  await assert.rejects(createRestoreTask({ instanceId: taskFixture.instance.id, hostId: taskFixture.host.id, userId: customer.id, backupId: null, tempInstanceName: 'temp', originalInstanceName: 'original', originalIncusId: 'original' }), /INSTANCE_UNAVAILABLE_FOR_TASK/)
  await assert.rejects(createBackupUploadTask({ instanceId: taskFixture.instance.id, hostId: taskFixture.host.id, userId: customer.id, backupId: 0, storageConfigId: 0 }), /INSTANCE_UNAVAILABLE_FOR_TASK/)
  const race = await makeFixture(`del_race_${suffix}`, 'offline')
  const raceResults = await Promise.allSettled([
    claim(race.instance.id),
    createInstanceTask({ instanceId: race.instance.id, hostId: race.host.id, userId: customer.id, taskType: 'start' })
  ])
  const claimedRace = raceResults[0].status === 'fulfilled' && raceResults[0].value === true
  const taskRace = raceResults[1].status === 'fulfilled'
  assert.notEqual(claimedRace && taskRace, true, 'concurrent task and deletion cannot both win')

  const free = await makeFreeFixture(`del_free_single_${suffix}`)
  const freeBalance = await balance()
  const responses = await Promise.all(Array.from({ length: 2 }, () => app.inject({ method: 'POST', url: `/api/instances/${free.instance.id}/destroy`, headers: { 'x-test-user': 'customer' } })))
  assert.deepEqual(responses.map(response => response.statusCode).sort(), [202, 409])
  const freePending = responses.find(response => response.statusCode === 202)!.json()
  assert.equal(freePending.pending, true)
  assert.equal(freePending.success, false)
  assert.equal(freePending.status, 'deleting')
  assert.equal(await balance(), freeBalance)
  assert.equal((await prisma.host.findUniqueOrThrow({ where: { id: free.host.id } })).cpuUsed, 10)
  assert.equal(await prisma.userDestroyRecord.count({ where: { instanceId: free.instance.id } }), 0)
  const batchA = await makeFreeFixture(`del_free_batch_a_${suffix}`)
  const batchB = await makeFreeFixture(`del_free_batch_b_${suffix}`)
  const batchResponse = await app.inject({ method: 'POST', url: '/api/instances/batch/destroy', headers: { 'x-test-user': 'customer' }, payload: { instanceIds: [batchA.instance.id, batchB.instance.id, 2147483647] } })
  assert.equal(batchResponse.statusCode, 200, batchResponse.body)
  const batch = batchResponse.json()
  assert.equal(batch.pendingCount, 2)
  assert.equal(batch.successCount, 0)
  assert.equal(batch.failedCount, 1)
  assert.equal(batch.results.filter((item: any) => item.pending && item.status === 'deleting' && !item.success).length, 2)
  assert.equal(await balance(), freeBalance)
  for (const fixture of [batchA, batchB]) {
    assert.equal((await prisma.host.findUniqueOrThrow({ where: { id: fixture.host.id } })).cpuUsed, 10)
    assert.equal(await prisma.userDestroyRecord.count({ where: { instanceId: fixture.instance.id } }), 0)
  }
  await prisma.host.update({ where: { id: free.host.id }, data: { status: 'online' } })
  assert.ok(await processPendingInstanceDeletion(free.instance.id, remote))
  assert.equal((await prisma.instance.findUniqueOrThrow({ where: { id: free.instance.id } })).status, 'deleted')
  const freeHost = await prisma.host.findUniqueOrThrow({ where: { id: free.host.id } })
  assert.deepEqual([freeHost.cpuUsed, freeHost.memoryUsed, freeHost.diskUsed, freeHost.natPortsUsedCount], [0, 0, 0, 0])
  assert.equal(await processPendingInstanceDeletion(free.instance.id, remote), null)
  assert.equal(await balance(), freeBalance)
  assert.equal(await prisma.userDestroyRecord.count({ where: { instanceId: free.instance.id } }), 0)
  await app.close()
  console.log('pending deletion PostgreSQL integration tests passed')
} finally {
  await prisma.$disconnect()
}
process.exit(0)
