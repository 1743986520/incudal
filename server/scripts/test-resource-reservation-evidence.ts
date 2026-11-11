import assert from 'node:assert/strict'

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
const { recordNewInstanceReservation, readReservationEvidenceForUpdate, recordReservationRelease } = await import('../src/db/resource-reservation-evidence.js')
const { failCreatingInstanceAndRollbackResources } = await import('../src/db/billing-operations.js')
const { claimInstanceAndReserveResources } = await import('../src/db/quota-operations.js')
const { processPendingInstanceDeletion } = await import('../src/services/pending-instance-deletion.js')
const tag = `${Date.now()}_${Math.floor(Math.random() * 100000)}`
const user = await prisma.user.create({ data: { username: `reservation_user_${tag}`, passwordHash: 'test-only' } })
let seq = 0
async function fixture(withEvidence = true) {
  const suffix = `${tag}_${++seq}`
  const host = await prisma.host.create({ data: { userId: user.id, name: `reservation_host_${suffix}`, url: 'https://127.0.0.1:1', cpuAllowanceMax: 1000, memoryMax: 4096, natPortStart: 10000, natPortEnd: 10100 } })
  await prisma.storagePool.create({ data: { hostId: host.id, name: 'test', driver: 'dir' } })
  const instance = await prisma.$transaction(async tx => {
    await tx.host.update({ where: { id: host.id }, data: { cpuUsed: { increment: 10 }, memoryUsed: { increment: 256 }, diskUsed: { increment: 512 }, natPortsUsedCount: { increment: 2 } } })
    const row = await tx.instance.create({ data: { incusId: `res-${suffix}`, name: `res-${suffix}`, userId: user.id, hostId: host.id, image: 'test', status: 'creating', cpu: 10, memory: 256, disk: 512, portLimit: 2 } })
    if (withEvidence) await recordNewInstanceReservation(tx, { instanceId: row.id, hostId: host.id, cpu: 10, memory: 256, disk: 512, portCount: 2 })
    return row
  })
  return { host, instance, resources: { hostId: host.id, cpu: 10, memory: 256, disk: 512, portCount: 2 } }
}
async function evidence(instanceId: number) {
  return prisma.$transaction(tx => readReservationEvidenceForUpdate(tx, instanceId))
}
try {
  const a = await fixture()
  assert.equal((await evidence(a.instance.id)).state, 'reserved')
  const initialHost = await prisma.host.findUniqueOrThrow({ where: { id: a.host.id } })
  assert.equal(initialHost.reservationEpoch, 1n)
  assert.equal(await failCreatingInstanceAndRollbackResources(a.instance.id, a.resources), true)
  assert.equal((await evidence(a.instance.id)).state, 'released')
  assert.equal(await failCreatingInstanceAndRollbackResources(a.instance.id, a.resources), false)
  let host = await prisma.host.findUniqueOrThrow({ where: { id: a.host.id } })
  assert.deepEqual([host.cpuUsed, host.memoryUsed, host.diskUsed, host.natPortsUsedCount], [0, 0, 0, 0])
  assert.equal(host.reservationEpoch, 2n)
  assert.equal(await claimInstanceAndReserveResources({ instanceId: a.instance.id, userId: user.id, ...a.resources }), true)
  const retry = await evidence(a.instance.id)
  assert.equal(retry.state, 'reserved')
  assert.equal(retry.state === 'reserved' && retry.generation, 2)
  host = await prisma.host.findUniqueOrThrow({ where: { id: a.host.id } })
  assert.equal(host.reservationEpoch, 3n)

  const unrelated = await fixture()
  await prisma.host.update({ where: { id: unrelated.host.id }, data: { cpuUsed: { increment: 1 } } })
  assert.equal((await evidence(unrelated.instance.id)).state, 'unknown', 'any later host counter change invalidates the epoch')
  const dimensions = await fixture()
  await prisma.instance.update({ where: { id: dimensions.instance.id }, data: { portLimit: 3 } })
  assert.equal((await evidence(dimensions.instance.id)).state, 'unknown', 'untracked instance dimension change invalidates evidence')
  const legacy = await fixture(false)
  assert.equal((await evidence(legacy.instance.id)).state, 'unknown', 'historical instances without a record remain unknown')

  const rollback = await fixture()
  await prisma.host.update({ where: { id: rollback.host.id }, data: { cpuUsed: 0 } })
  await assert.rejects(failCreatingInstanceAndRollbackResources(rollback.instance.id, rollback.resources), /counters are lower/)
  assert.equal((await prisma.instance.findUniqueOrThrow({ where: { id: rollback.instance.id } })).status, 'creating')
  assert.equal((await evidence(rollback.instance.id)).state, 'unknown')

  const mismatch = await fixture()
  await prisma.$transaction(async tx => {
    const before = await readReservationEvidenceForUpdate(tx, mismatch.instance.id)
    await tx.host.update({ where: { id: mismatch.host.id }, data: { cpuUsed: { decrement: 1 } } })
    await recordReservationRelease(tx, before, { ...mismatch.resources, instanceId: mismatch.instance.id, cpu: 1 })
  })
  assert.equal((await evidence(mismatch.instance.id)).state, 'unknown', 'mismatched debit must never become released evidence')

  const noDebit = await fixture()
  await prisma.$transaction(async tx => {
    const before = await readReservationEvidenceForUpdate(tx, noDebit.instance.id)
    await recordReservationRelease(tx, before, { ...noDebit.resources, instanceId: noDebit.instance.id })
  })
  assert.equal((await evidence(noDebit.instance.id)).state, 'reserved', 'no counter change cannot fabricate release evidence')

  const lockFixture = await fixture()
  let releaseLock!: () => void
  let lockAcquired!: () => void
  const waitForRelease = new Promise<void>(resolve => { releaseLock = resolve })
  const locked = new Promise<void>(resolve => { lockAcquired = resolve })
  const transaction = prisma.$transaction(async tx => {
    const before = await readReservationEvidenceForUpdate(tx, lockFixture.instance.id)
    assert.equal(before.state, 'reserved')
    lockAcquired()
    await waitForRelease
    await tx.host.update({ where: { id: lockFixture.host.id }, data: {
      cpuUsed: { decrement: 10 }, memoryUsed: { decrement: 256 },
      diskUsed: { decrement: 512 }, natPortsUsedCount: { decrement: 2 }
    } })
    await recordReservationRelease(tx, before, { ...lockFixture.resources, instanceId: lockFixture.instance.id })
  })
  await locked
  const competingUpdate = Promise.resolve(prisma.host.update({ where: { id: lockFixture.host.id }, data: { cpuUsed: { increment: 1 } } }))
  const race = await Promise.race([competingUpdate.then(() => 'updated'), new Promise(resolve => setTimeout(() => resolve('blocked'), 200))])
  assert.equal(race, 'blocked', 'host counter writer waits for evidence transaction')
  releaseLock()
  await transaction
  await competingUpdate
  assert.equal((await evidence(lockFixture.instance.id)).state, 'unknown', 'subsequent host mutation invalidates released evidence')

  const concurrent = await fixture()
  const results = await Promise.allSettled([
    failCreatingInstanceAndRollbackResources(concurrent.instance.id, concurrent.resources),
    failCreatingInstanceAndRollbackResources(concurrent.instance.id, concurrent.resources)
  ])
  assert.equal(results.filter(result => result.status === 'fulfilled' && result.value === true).length, 1)
  const ch = await prisma.host.findUniqueOrThrow({ where: { id: concurrent.host.id } })
  assert.deepEqual([ch.cpuUsed, ch.memoryUsed, ch.diskUsed, ch.natPortsUsedCount], [0, 0, 0, 0])
  assert.equal((await evidence(concurrent.instance.id)).state, 'released')

  const pending = await fixture()
  await prisma.host.update({ where: { id: pending.host.id }, data: { status: 'online' } })
  await prisma.instance.update({ where: { id: pending.instance.id }, data: { status: 'deleting', deletionOriginalStatus: 'running' } })
  const remote = { async ensureDeleted() {}, async deleteProxySite() {} }
  assert.ok(await processPendingInstanceDeletion(pending.instance.id, remote))
  assert.equal((await evidence(pending.instance.id)).state, 'released')
  assert.equal(await processPendingInstanceDeletion(pending.instance.id, remote), null)
  const finishedHost = await prisma.host.findUniqueOrThrow({ where: { id: pending.host.id } })
  assert.deepEqual([finishedHost.cpuUsed, finishedHost.memoryUsed, finishedHost.diskUsed, finishedHost.natPortsUsedCount], [0, 0, 0, 0])

  for (const stale of [false, true]) {
    const unknown = await fixture(stale)
    await prisma.host.update({ where: { id: unknown.host.id }, data: {
      status: 'online', ...(stale ? { cpuUsed: { increment: 1 } } : {})
    } })
    await prisma.instance.update({ where: { id: unknown.instance.id }, data: { status: 'deleting', deletionOriginalStatus: 'running' } })
    const before = await prisma.host.findUniqueOrThrow({ where: { id: unknown.host.id } })
    await assert.rejects(processPendingInstanceDeletion(unknown.instance.id, remote), /reservation evidence is unavailable or stale/)
    const after = await prisma.host.findUniqueOrThrow({ where: { id: unknown.host.id } })
    assert.deepEqual([after.cpuUsed, after.memoryUsed, after.diskUsed, after.natPortsUsedCount],
      [before.cpuUsed, before.memoryUsed, before.diskUsed, before.natPortsUsedCount], 'unknown reservations never debit aggregate counters')
    const row = await prisma.instance.findUniqueOrThrow({ where: { id: unknown.instance.id } })
    assert.equal(row.status, 'deleting')
    assert.equal(row.deletionRemoteDeleted, true, 'confirmed remote deletion survives the rolled-back finalization')
  }
  console.log('resource reservation evidence PostgreSQL integration tests passed')
} finally {
  await prisma.$disconnect()
}
process.exit(0)
