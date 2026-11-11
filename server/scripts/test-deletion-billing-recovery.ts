import assert from 'node:assert/strict'

const url = process.env.DATABASE_URL ?? ''
let valid = false
try {
  const u = new URL(url)
  const o = u.hostname.split('.').map(Number)
  const ipv4 = o.length === 4 && o.every(n => Number.isInteger(n) && n >= 0 && n <= 255)
  const privateIp = ipv4 && (o[0] === 127 || o[0] === 10 || (o[0] === 172 && o[1] >= 16 && o[1] <= 31) || (o[0] === 192 && o[1] === 168))
  valid = ['postgres:', 'postgresql:'].includes(u.protocol) && (u.hostname === 'localhost' || privateIp) && u.pathname === '/incudal_deletion_test'
} catch { /* invalid URL */ }
if (!valid || process.env.INSTANCE_DELETION_TEST_ALLOW !== '1' || url !== process.env.INSTANCE_DELETION_TEST_DATABASE_URL) {
  throw new Error('This fixture test only runs against the dedicated local deletion test database')
}
const { prisma } = await import('../src/db/prisma.js')
const { recoverDeletionBilling } = await import('../src/services/deletion-billing-recovery.js')
const { withInstanceRemoteOperationLock } = await import('../src/services/instance-remote-operation-lock.js')
const { getRemoteOperationAbortSignal } = await import('../src/services/remote-operation-abort.js')
const tag = `${Date.now()}_${Math.floor(Math.random() * 100000)}`
const user = await prisma.user.create({ data: { username: `recovery_user_${tag}`, passwordHash: 'test-only', balance: 10 } })
const host = await prisma.host.create({ data: { name: `recovery_host_${tag}`, userId: user.id, url: 'https://127.0.0.1:1', status: 'online' } })
let seq = 0
async function fixture() {
  const name = `recovery_${tag}_${++seq}`
  return prisma.instance.create({ data: { name, incusId: name, image: 'test', userId: user.id, hostId: host.id,
    status: 'deleted', cpu: 1, memory: 128, disk: 512, deletionBillingPending: true,
    deletionRemoteDeleted: false, deletionBillingMode: 'privileged_delete', deletionRefundableValue: 0 } })
}
let remoteCalls = 0
try {
  const instance = await fixture()
  let release!: () => void
  let entered!: () => void
  const active = new Promise<void>(resolve => { entered = resolve })
  const wait = new Promise<void>(resolve => { release = resolve })
  const claim = withInstanceRemoteOperationLock(instance.id, async () => { entered(); await wait })
  await active
  const remote = { async ensureDeleted() { remoteCalls++ } }
  assert.equal(await recoverDeletionBilling(instance.id, remote), 'busy')
  assert.equal(remoteCalls, 0, 'legacy recovery cannot race a live delete claimant')
  release()
  await claim
  assert.equal(await recoverDeletionBilling(instance.id, remote), 'settled')
  assert.equal(remoteCalls, 1)
  assert.equal(await recoverDeletionBilling(instance.id, remote), 'skipped')
  assert.equal(remoteCalls, 1, 'settlement is not repeated')

  const changed = await fixture()
  let remoteEntered!: () => void
  let finishRemote!: () => void
  const remoteStarted = new Promise<void>(resolve => { remoteEntered = resolve })
  const remoteWait = new Promise<void>(resolve => { finishRemote = resolve })
  const recovery = recoverDeletionBilling(changed.id, { async ensureDeleted() { remoteEntered(); await remoteWait } })
  await remoteStarted
  await prisma.instance.update({ where: { id: changed.id }, data: { status: 'deleting', deletionOriginalStatus: 'running' } })
  finishRemote()
  assert.equal(await recovery, 'skipped', 'a changed claim must not be marked or settled')
  const row = await prisma.instance.findUniqueOrThrow({ where: { id: changed.id } })
  assert.equal(row.deletionRemoteDeleted, false)
  assert.equal(row.deletionBillingPending, true)
  assert.equal(Number((await prisma.user.findUniqueOrThrow({ where: { id: user.id } })).balance), 10)

  const interrupted = await fixture()
  let remoteEnteredAgain!: () => void
  const startedAgain = new Promise<void>(resolve => { remoteEnteredAgain = resolve })
  const interruption = recoverDeletionBilling(interrupted.id, { async ensureDeleted() {
    const signal = getRemoteOperationAbortSignal()
    assert.ok(signal)
    remoteEnteredAgain()
    await new Promise<void>(resolve => signal.addEventListener('abort', () => resolve(), { once: true }))
  } }).then(() => null, (error: unknown) => error)
  await startedAgain
  const holders = await prisma.$queryRaw<Array<{ pid: number }>>`
    SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND classid = 4112::oid AND objid = ${interrupted.id}::oid AND granted
  `
  assert.equal(holders.length, 1)
  await prisma.$queryRaw`SELECT pg_terminate_backend(${holders[0].pid})`
  const failure = await interruption
  assert.ok(failure instanceof Error)
  assert.match(failure.message, /lock connection failed/)
  const afterLoss = await prisma.instance.findUniqueOrThrow({ where: { id: interrupted.id } })
  assert.equal(afterLoss.deletionRemoteDeleted, false, 'lost session cannot confirm an in-flight remote result')
  assert.equal(afterLoss.deletionBillingPending, true)
  assert.equal(Number((await prisma.user.findUniqueOrThrow({ where: { id: user.id } })).balance), 10)
  assert.equal(await recoverDeletionBilling(interrupted.id, remote), 'settled', 'a later recovery safely resumes after lock loss')

  const confirmed = await fixture()
  await prisma.instance.update({ where: { id: confirmed.id }, data: { deletionRemoteDeleted: true } })
  await prisma.host.update({ where: { id: host.id }, data: { status: 'offline' } })
  const beforeRemoteCalls = remoteCalls
  assert.equal(await recoverDeletionBilling(confirmed.id, remote), 'settled', 'a previously confirmed deletion can settle while the host is offline')
  assert.equal(remoteCalls, beforeRemoteCalls, 'confirmed remote deletion must not be reissued')
  for (const changes of [
    { billingMode: 'hourly' as const, deletionBillingMode: 'hourly_close' },
    { deletionBillingMode: 'user_destroy' },
    { trafficBillingMode: 'usage' as const }
  ]) {
    for (const deletionRemoteDeleted of [false, true]) {
      const uncertain = await fixture()
      await prisma.instance.update({ where: { id: uncertain.id }, data: { ...changes, deletionRemoteDeleted } })
      assert.equal(await recoverDeletionBilling(uncertain.id, remote), 'skipped')
      assert.equal((await prisma.instance.findUniqueOrThrow({ where: { id: uncertain.id } })).deletionBillingPending, true)
      assert.equal(remoteCalls, beforeRemoteCalls, 'unknown billing must not issue a remote delete')
    }
  }
  console.log('deletion billing recovery locking PostgreSQL integration tests passed')
} finally { await prisma.$disconnect() }
process.exit(0)
