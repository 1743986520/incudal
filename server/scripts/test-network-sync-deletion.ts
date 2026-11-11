import assert from 'node:assert/strict'

const testUrl = process.env.DATABASE_URL ?? ''
const allowedUrl = /^postgresql:\/\/postgres@(?:localhost|127\.0\.0\.1|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}):\d{1,5}\/incudal_deletion_test$/
if (process.env.INSTANCE_DELETION_TEST_ALLOW !== '1' || testUrl !== process.env.INSTANCE_DELETION_TEST_DATABASE_URL || !allowedUrl.test(testUrl)) {
  throw new Error('This fixture test requires the dedicated local deletion test database and explicit opt-in')
}

const { prisma } = await import('../src/db/prisma.js')
const { persistResolvedInstanceNetworkAddresses } = await import('../src/lib/instance-network-sync.js')
const { INSTANCE_OPERATION_LOCK_NAMESPACE, advisoryTransactionLock } = await import('../src/db/advisory-locks.js')
const suffix = `${Date.now()}_${Math.floor(Math.random() * 100000)}`
const user = await prisma.user.create({ data: { username: `network_owner_${suffix}`, passwordHash: 'test-only' } })
const host = await prisma.host.create({ data: { userId: user.id, name: `network_host_${suffix}`, url: 'https://127.0.0.1:1', status: 'offline' } })
const instance = await prisma.instance.create({ data: {
  incusId: `network_${suffix}`, name: `network_${suffix}`, userId: user.id, hostId: host.id,
  image: 'test', status: 'running', cpu: 10, memory: 256, disk: 512, ipv4: '10.0.0.2', networkMode: 'nat'
} })
const snapshot = { id: instance.id, hostId: host.id, networkMode: 'nat', ipv4: '10.0.0.2', ipv6: null }
const resolved = { ipv4: '10.0.0.3', ipv6: null, ipv4Device: 'eth0', ipv6Device: 'eth1', configuredIpv6: null, observedIpv6: null }

try {
  let entered!: () => void
  let release!: () => void
  const enteredPromise = new Promise<void>(resolve => { entered = resolve })
  const hold = new Promise<void>(resolve => { release = resolve })
  const claim = prisma.$transaction(async tx => {
    await advisoryTransactionLock(tx, INSTANCE_OPERATION_LOCK_NAMESPACE, instance.id)
    await tx.instance.update({ where: { id: instance.id }, data: { status: 'deleting' } })
    entered()
    await hold
  })
  await enteredPromise
  try {
    await assert.rejects(persistResolvedInstanceNetworkAddresses(snapshot, resolved), /advisory transaction lock is busy/i)
  } finally {
    release()
    await claim
  }

  const ignored = await persistResolvedInstanceNetworkAddresses(snapshot, resolved)
  assert.equal(ignored.ipv4Changed, false)
  assert.equal((await prisma.instance.findUniqueOrThrow({ where: { id: instance.id } })).ipv4, '10.0.0.2')
  assert.equal(await prisma.ipAddress.count({ where: { instanceId: instance.id } }), 0)

  await prisma.instance.update({ where: { id: instance.id }, data: { status: 'running' } })
  const applied = await persistResolvedInstanceNetworkAddresses(snapshot, resolved)
  assert.equal(applied.ipv4Changed, true)
  assert.equal((await prisma.instance.findUniqueOrThrow({ where: { id: instance.id } })).ipv4, '10.0.0.3')
  assert.equal(await prisma.ipAddress.count({ where: { instanceId: instance.id, address: '10.0.0.3' } }), 1)

  const stale = await persistResolvedInstanceNetworkAddresses(snapshot, { ...resolved, ipv4: '10.0.0.4' })
  assert.equal(stale.ipv4Changed, false)
  assert.equal((await prisma.instance.findUniqueOrThrow({ where: { id: instance.id } })).ipv4, '10.0.0.3')
  console.log('network sync deletion race integration tests passed')
} finally {
  await prisma.$disconnect()
}
process.exit(0)
