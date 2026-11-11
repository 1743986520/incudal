import assert from 'node:assert/strict'

const url = process.env.DATABASE_URL ?? ''
let valid = false
try {
  const parsed = new URL(url)
  valid = ['postgres:', 'postgresql:'].includes(parsed.protocol) && parsed.pathname === '/incudal_deletion_test'
    && ['localhost', '127.0.0.1'].includes(parsed.hostname)
} catch { /* invalid URL */ }
if (!valid || process.env.INSTANCE_DELETION_TEST_ALLOW !== '1' || url !== process.env.INSTANCE_DELETION_TEST_DATABASE_URL) {
  throw new Error('Requires the dedicated local deletion test database')
}

const { prisma } = await import('../src/db/prisma.js')
const { cleanOldLogs, OPERATOR_RETIRED_HOST_DELETION_ACTION } = await import('../src/db/logs.js')
const { recoverDeletionBilling, deletionBillingRecoveryWhere } = await import('../src/services/deletion-billing-recovery.js')
const { processPendingInstanceDeletion, pendingDeletionRecoveryWhere } = await import('../src/services/pending-instance-deletion.js')
const tag = `${Date.now()}_${Math.floor(Math.random() * 100000)}`
const user = await prisma.user.create({ data: { username: `retired_fixture_${tag}`, passwordHash: 'test-only', balance: 10 } })
const host = await prisma.host.create({ data: { userId: user.id, name: `retired_fixture_${tag}`, countryCode: 'zz', url: 'https://127.0.0.1:1', status: 'online' } })
const mk = async (index: number, status: 'deleted' | 'deleting') => prisma.instance.create({ data: {
  userId: user.id, hostId: host.id, name: `retired_${tag}_${index}`, incusId: `retired_${tag}_${index}`,
  image: 'test', status, deletionOriginalStatus: 'running', deletionBillingPending: true,
  deletionBillingMode: 'privileged_delete', deletionRemoteDeleted: false, deletionRefundableValue: 0,
  cpu: 1, memory: 64, disk: 128
} })
const retired = await mk(1, 'deleted')
const normal = await mk(2, 'deleted')
const reopened = await mk(3, 'deleting')
try {
  for (const instance of [retired, reopened]) {
    await prisma.log.create({ data: { instanceId: instance.id, userId: null, module: 'instance', action: OPERATOR_RETIRED_HOST_DELETION_ACTION, content: '{}', result: 'success' } })
    await prisma.retiredInstanceTombstone.create({ data: { instanceId: instance.id, hostId: host.id, sourceDigest: 'fixture', retirementDigest: 'fixture' } })
  }
  const ids = [retired.id, normal.id, reopened.id]
  const recoverable = await prisma.instance.findMany({ where: { ...deletionBillingRecoveryWhere, id: { in: ids } }, select: { id: true } })
  assert.deepEqual(recoverable.map(row => row.id), [normal.id])
  assert.equal(await prisma.instance.count({ where: { ...pendingDeletionRecoveryWhere, id: reopened.id } }), 0)
  let calls = 0
  const sentinel = new Error('synthetic remote operation')
  const remote = { ensureDeleted: async () => { calls++; throw sentinel } }
  assert.equal(await recoverDeletionBilling(retired.id, remote), 'skipped')
  assert.equal(calls, 0)
  await prisma.instance.update({ where: { id: retired.id }, data: { deletionRemoteDeleted: true } })
  assert.equal(await recoverDeletionBilling(retired.id, remote), 'skipped', 'a later remote flag change must not trigger automatic settlement')
  assert.equal(calls, 0)
  await prisma.instance.update({ where: { id: retired.id }, data: { deletionRemoteDeleted: false } })
  await assert.rejects(recoverDeletionBilling(normal.id, remote), error => error === sentinel)
  assert.equal(calls, 1)
  const pendingRemote = { ensureDeleted: async () => { calls++; throw sentinel }, deleteProxySite: async () => { throw sentinel } }
  assert.equal(await processPendingInstanceDeletion(reopened.id, pendingRemote), null)
  assert.equal(calls, 1)
  const after = await prisma.instance.findUniqueOrThrow({ where: { id: retired.id } })
  assert.equal(after.deletionRemoteDeleted, false)
  assert.equal(after.deletionBillingPending, true)
  assert.equal(Number((await prisma.user.findUniqueOrThrow({ where: { id: user.id } })).balance), 10)
  const rollback = new Error('rollback retention fixture')
  await assert.rejects(prisma.$transaction(async tx => {
    await tx.log.updateMany({ where: { instanceId: retired.id, action: OPERATOR_RETIRED_HOST_DELETION_ACTION }, data: { createdAt: new Date(0) } })
    await cleanOldLogs(90, tx)
    assert.equal(await tx.log.count({ where: { instanceId: retired.id, action: OPERATOR_RETIRED_HOST_DELETION_ACTION } }), 1)
    throw rollback
  }), error => error === rollback)
  await prisma.log.deleteMany({ where: { instanceId: { in: [retired.id, reopened.id] }, action: OPERATOR_RETIRED_HOST_DELETION_ACTION } })
  assert.equal(await recoverDeletionBilling(retired.id, remote), 'skipped', 'tombstone fence survives removal of audit log')
  assert.equal(await processPendingInstanceDeletion(reopened.id, pendingRemote), null)
  assert.equal(calls, 1)
  console.log('retired host billing and pending recovery fencing tests passed')
} finally { await prisma.$disconnect() }
process.exit(0)
