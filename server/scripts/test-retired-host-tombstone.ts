import assert from 'node:assert/strict'

// Refuse to run against any production or nondedicated database.
const url = process.env.DATABASE_URL ?? ''
const parsed = new URL(url)
if (!['postgres:', 'postgresql:'].includes(parsed.protocol) || parsed.pathname !== '/incudal_deletion_test'
  || !['localhost', '127.0.0.1', '::1'].includes(parsed.hostname)
  || process.env.INSTANCE_DELETION_TEST_ALLOW !== '1' || process.env.INSTANCE_DELETION_TEST_DATABASE_URL !== url) {
  throw new Error('Requires the dedicated local deletion test database')
}

const { prisma } = await import('../src/db/prisma.js')
const { deleteHost, HostDeletionBlockedError } = await import('../src/db/hosts.js')
const tag = `${Date.now()}_${Math.floor(Math.random() * 100000)}`
const owner = await prisma.user.create({ data: { username: `retired_guard_${tag}`, passwordHash: 'test-only', balance: 123 } })
const host = await prisma.host.create({ data: { userId: owner.id, name: `retired_guard_${tag}`, url: 'https://127.0.0.1:1' } })
const instance = await prisma.instance.create({ data: { name: `retired_guard_${tag}`, incusId: `retired_guard_${tag}`,
  image: 'test', userId: owner.id, hostId: host.id, status: 'deleting', deletionBillingPending: true,
  deletionBillingMode: 'privileged_delete', cpu: 1, memory: 128, disk: 512 } })
const port = await prisma.portMapping.create({ data: { hostId: host.id, instanceId: instance.id, publicPort: 12345, privatePort: 22 } })
let activeHostId: number | undefined
let activeInstanceId: number | undefined
try {
  let signalLocked!: () => void
  const locked = new Promise<void>(resolve => { signalLocked = resolve })
  let releaseLocked!: () => void
  const release = new Promise<void>(resolve => { releaseLocked = resolve })
  const retire = prisma.$transaction(async tx => {
    await tx.$queryRaw`SELECT id FROM hosts WHERE id = ${host.id} FOR UPDATE`
    await tx.$queryRaw`SELECT id FROM instances WHERE id = ${instance.id} FOR UPDATE`
    await tx.retiredInstanceTombstone.create({ data: { instanceId: instance.id, hostId: host.id,
      sourceDigest: 'a'.repeat(64), retirementDigest: 'b'.repeat(64), originalBillingMode: 'privileged_delete' } })
    await tx.instance.update({ where: { id: instance.id }, data: { status: 'deleted', deletionBillingMode: 'manual_retired_host' } })
    signalLocked()
    await release
  }, { timeout: 10000 })
  await locked
  let finished = false
  const deletion = deleteHost(host.id).finally(() => { finished = true })
  await new Promise(resolve => setTimeout(resolve, 200))
  assert.equal(finished, false, 'host deletion must wait for retirement host lock')
  releaseLocked()
  await retire
  await assert.rejects(deletion, error => error instanceof HostDeletionBlockedError && error.reason === 'retired_reconciliation')
  await assert.rejects(prisma.instance.delete({ where: { id: instance.id } }))
  await assert.rejects(prisma.host.delete({ where: { id: host.id } }))
  await assert.rejects(prisma.user.delete({ where: { id: owner.id } }))
  assert.ok(await prisma.portMapping.findUnique({ where: { id: port.id } }))
  assert.equal((await prisma.instance.findUniqueOrThrow({ where: { id: instance.id } })).deletionRemoteDeleted, false)
  assert.equal(Number((await prisma.user.findUniqueOrThrow({ where: { id: owner.id } })).balance), 123)
  assert.equal(await prisma.retiredInstanceTombstone.count({ where: { instanceId: instance.id } }), 1)

  const activeHost = await prisma.host.create({ data: { userId: owner.id, name: `active_guard_${tag}`, url: 'https://127.0.0.1:1' } })
  activeHostId = activeHost.id
  const activeInstance = await prisma.instance.create({ data: { name: `active_guard_${tag}`, incusId: `active_guard_${tag}`,
    image: 'test', userId: owner.id, hostId: activeHost.id, status: 'running', cpu: 1, memory: 128, disk: 512 } })
  activeInstanceId = activeInstance.id
  const activePort = await prisma.portMapping.create({ data: { hostId: activeHost.id, instanceId: activeInstance.id, publicPort: 12346, privatePort: 22 } })
  await assert.rejects(deleteHost(activeHost.id), error => error instanceof HostDeletionBlockedError && error.reason === 'active_instances')
  assert.ok(await prisma.portMapping.findUnique({ where: { id: activePort.id } }))
  console.log('retired host tombstone, FK restrictions, host atomicity and lock concurrency passed')
} finally {
  // All IDs here were created solely by this test against the dedicated DB.
  await prisma.retiredInstanceTombstone.deleteMany({ where: { instanceId: instance.id } })
  await prisma.portMapping.deleteMany({ where: { instanceId: { in: [instance.id, ...(activeInstanceId ? [activeInstanceId] : [])] } } })
  await prisma.instance.deleteMany({ where: { id: { in: [instance.id, ...(activeInstanceId ? [activeInstanceId] : [])] } } })
  await prisma.host.deleteMany({ where: { id: { in: [host.id, ...(activeHostId ? [activeHostId] : [])] } } })
  await prisma.user.deleteMany({ where: { id: owner.id } })
  await prisma.$disconnect()
}
process.exit(0)
