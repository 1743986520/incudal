import assert from 'node:assert/strict'

// These fixtures mutate only their own rows in a deliberately named test DB.
const testUrl = process.env.DATABASE_URL ?? ''
let validLocalUrl = false
try {
  const url = new URL(testUrl)
  const octets = url.hostname.split('.').map(Number)
  const validIpv4 = octets.length === 4 && octets.every(n => Number.isInteger(n) && n >= 0 && n <= 255)
  const privateAddress = validIpv4 && (octets[0] === 10 || (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) || (octets[0] === 192 && octets[1] === 168) || octets[0] === 127)
  const port = Number(url.port || '5432')
  validLocalUrl = ['postgres:', 'postgresql:'].includes(url.protocol) && (url.hostname === 'localhost' || privateAddress)
    && url.pathname === '/incudal_deletion_test' && Number.isInteger(port) && port >= 1 && port <= 65535
} catch { /* invalid URL */ }
if (process.env.INSTANCE_DELETION_TEST_ALLOW !== '1' || testUrl !== process.env.INSTANCE_DELETION_TEST_DATABASE_URL || !validLocalUrl) {
  throw new Error('This fixture test only runs against the dedicated local deletion test database')
}
const { prisma } = await import('../src/db/prisma.js')
const { claimInstanceForAdminDelete } = await import('../src/routes/admin-billing.js')
const { claimInstanceForUserDestroy } = await import('../src/routes/instance-destroy.js')
const { claimLegacyDeletionWithoutProxySites } = await import('../src/services/legacy-deletion-proxy-guard.js')
const { withInstanceAndDomainRemoteOperationLock } = await import('../src/services/instance-remote-operation-lock.js')
const tag = `${Date.now()}_${Math.floor(Math.random() * 100000)}`
const admin = await prisma.user.create({ data: { username: `legacy_admin_${tag}`, passwordHash: 'test-only', role: 'admin' } })
const user = await prisma.user.create({ data: { username: `legacy_user_${tag}`, passwordHash: 'test-only', balance: 50 } })
const other = await prisma.user.create({ data: { username: `legacy_other_${tag}`, passwordHash: 'test-only' } })
const hostA = await prisma.host.create({ data: { userId: admin.id, name: `legacy_a_${tag}`, url: 'https://127.0.0.1:1' } })
const hostB = await prisma.host.create({ data: { userId: admin.id, name: `legacy_b_${tag}`, url: 'https://127.0.0.1:1' } })
const pkg = await prisma.package.create({ data: { userId: admin.id, name: `legacy_pkg_${tag}`, cpuMax: 100, memoryMax: 1024, diskMax: 2048 } })
const plan = await prisma.packagePlan.create({ data: { packageId: pkg.id, name: 'paid', cpu: 10, memory: 256, disk: 512, portLimit: 2, snapshotLimit: 1, backupLimit: 1, siteLimit: 1, trafficLimit: 1000n, price: 100 } })
let sequence = 0
async function fixture() {
  const name = `legacy_instance_${tag}_${++sequence}`
  return prisma.instance.create({ data: { incusId: name, name, userId: user.id, hostId: hostA.id, packageId: pkg.id, packagePlanId: plan.id, image: 'test', status: 'running', cpu: 10, memory: 256, disk: 512, monthlyTrafficUsed: 100n } })
}
async function snapshot(id: number) {
  return prisma.instance.findUniqueOrThrow({ where: { id }, include: { package: { select: { allowInstanceDeletion: true, destroyTrafficLimit: true } } } })
}
const actor = { id: user.id, role: 'user' as const }
const userClaim = (row: Awaited<ReturnType<typeof snapshot>>) => claimInstanceForUserDestroy(row, actor, row.monthlyTrafficUsed, 'user_destroy', false)
try {
  for (const field of ['userId', 'hostId', 'incusId', 'version', 'packageId', 'packagePlanId', 'billingMode', 'suspendReason'] as const) {
    const row = await fixture()
    const expected = await snapshot(row.id)
    const changed = {
      userId: other.id, hostId: hostB.id, incusId: `${row.incusId}-new`, version: row.version + 1,
      packageId: null, packagePlanId: null, billingMode: 'hourly' as const, suspendReason: 'changed'
    }[field]
    await prisma.instance.update({ where: { id: row.id }, data: { [field]: changed } })
    assert.equal(await claimInstanceForAdminDelete(expected, admin.id, { deletionBillingPending: true, deletionBillingMode: 'privileged_delete' }), false, `admin must reject stale ${field}`)
    assert.equal(await userClaim(expected), false, `user must reject stale ${field}`)
    assert.equal((await prisma.instance.findUniqueOrThrow({ where: { id: row.id } })).status, 'running')
  }
  const traffic = await fixture()
  const staleTraffic = await snapshot(traffic.id)
  await prisma.instance.update({ where: { id: traffic.id }, data: { monthlyTrafficUsed: { increment: 1 } } })
  assert.equal(await userClaim(staleTraffic), false, 'traffic changed after the eligibility check')
  const limit = await fixture()
  const stalePolicy = await snapshot(limit.id)
  await prisma.package.update({ where: { id: pkg.id }, data: { allowInstanceDeletion: false } })
  assert.equal(await userClaim(stalePolicy), false, 'revoked package deletion policy')
  await prisma.package.update({ where: { id: pkg.id }, data: { allowInstanceDeletion: true, destroyTrafficLimit: { increment: 1n } } })
  assert.equal(await userClaim(stalePolicy), false, 'changed traffic threshold')
  const bannedRow = await fixture()
  const bannedSnapshot = await snapshot(bannedRow.id)
  await prisma.user.update({ where: { id: user.id }, data: { status: 'banned' } })
  assert.equal(await userClaim(bannedSnapshot), false, 'banned owner cannot claim')
  await prisma.user.update({ where: { id: user.id }, data: { status: 'active' } })
  await prisma.user.update({ where: { id: admin.id }, data: { role: 'user' } })
  assert.equal(await claimInstanceForAdminDelete(bannedSnapshot, admin.id), false, 'revoked admin cannot claim')
  await prisma.user.update({ where: { id: admin.id }, data: { role: 'admin' } })
  const transferred = await fixture()
  const transferSnapshot = await snapshot(transferred.id)
  await prisma.instanceTransfer.create({ data: { instanceId: transferred.id, fromUserId: user.id, toUserId: other.id, snapshot: {} } })
  assert.equal(await userClaim(transferSnapshot), false, 'pending transfer blocks user claim')
  assert.equal(await claimInstanceForAdminDelete(transferSnapshot, admin.id), false, 'pending transfer blocks admin claim')
  const concurrent = await fixture()
  const concurrentSnapshot = await snapshot(concurrent.id)
  const outcomes = await Promise.all([userClaim(concurrentSnapshot), userClaim(concurrentSnapshot)])
  assert.equal(outcomes.filter(Boolean).length, 1, 'exactly one concurrent claim wins')
  assert.equal((await prisma.instance.findUniqueOrThrow({ where: { id: concurrent.id } })).status, 'deleting')
  assert.equal(Number((await prisma.user.findUniqueOrThrow({ where: { id: user.id } })).balance), 50, 'claims never move funds')
  const adminSuccess = await fixture()
  const adminSnapshot = await snapshot(adminSuccess.id)
  assert.equal(await claimInstanceForAdminDelete(adminSnapshot, admin.id, { deletionBillingPending: true, deletionBillingMode: 'privileged_delete' }), true)
  assert.equal(await claimInstanceForAdminDelete(adminSnapshot, admin.id, { deletionBillingPending: true, deletionBillingMode: 'privileged_delete' }), false)
  // Caddy creation and the legacy claim must serialize on the same instance lock.
  const guarded = await fixture()
  const guardedSnapshot = await snapshot(guarded.id)
  const domain = `legacy-guard-${tag.replace('_', '-')}.example.test`
  let resumeCreation!: () => void
  let creationEntered!: () => void
  const creationStarted = new Promise<void>(resolve => { creationEntered = resolve })
  const releaseCreation = new Promise<void>(resolve => { resumeCreation = resolve })
  const creating = withInstanceAndDomainRemoteOperationLock(guarded.id, domain, async () => {
    creationEntered()
    await releaseCreation
    await prisma.proxySite.create({ data: { instanceId: guarded.id, hostId: hostA.id, domain, targetPort: 80 } })
  })
  await creationStarted
  assert.equal(await claimLegacyDeletionWithoutProxySites(guarded.id, () => userClaim(guardedSnapshot)), 'busy')
  resumeCreation()
  assert.equal((await creating).acquired, true)
  assert.equal(await claimLegacyDeletionWithoutProxySites(guarded.id, () => userClaim(guardedSnapshot)), 'sites')
  assert.equal((await prisma.instance.findUniqueOrThrow({ where: { id: guarded.id } })).status, 'running')
  await prisma.proxySite.deleteMany({ where: { instanceId: guarded.id } })

  let resumeClaim!: () => void
  let claimEntered!: () => void
  const claimStarted = new Promise<void>(resolve => { claimEntered = resolve })
  const releaseClaim = new Promise<void>(resolve => { resumeClaim = resolve })
  const claiming = claimLegacyDeletionWithoutProxySites(guarded.id, async () => {
    claimEntered()
    await releaseClaim
    return userClaim(guardedSnapshot)
  })
  await claimStarted
  assert.deepEqual(await withInstanceAndDomainRemoteOperationLock(guarded.id, domain, async () => true), { acquired: false })
  resumeClaim()
  assert.equal(await claiming, 'claimed')
  assert.equal((await prisma.instance.findUniqueOrThrow({ where: { id: guarded.id } })).status, 'deleting')
  assert.equal(await claimLegacyDeletionWithoutProxySites(guarded.id, () => userClaim(guardedSnapshot)), 'conflict')
  console.log('legacy Caddy guard concurrent PostgreSQL tests passed')
  console.log('legacy deletion claim PostgreSQL integration tests passed')
} finally {
  await prisma.$disconnect()
}
process.exit(0)
