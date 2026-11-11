import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'

const url = process.env.DATABASE_URL ?? ''
let local = false
try {
  const parsed = new URL(url)
  const parts = parsed.hostname.split('.').map(Number)
  const ipv4 = parts.length === 4 && parts.every(n => Number.isInteger(n) && n >= 0 && n <= 255)
  const privateIp = ipv4 && (parts[0] === 127 || parts[0] === 10 || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) || (parts[0] === 192 && parts[1] === 168))
  local = ['postgres:', 'postgresql:'].includes(parsed.protocol) && (parsed.hostname === 'localhost' || privateIp) && parsed.pathname === '/incudal_deletion_test'
} catch { /* invalid URL */ }
if (!local || process.env.INSTANCE_DELETION_TEST_ALLOW !== '1' || url !== process.env.INSTANCE_DELETION_TEST_DATABASE_URL) {
  throw new Error('This fixture test only runs against the dedicated local deletion test database')
}
const { prisma } = await import('../src/db/prisma.js')
const { claimExpiredInstanceForDeletion, getSuspendedInstancesOlderThan } = await import('../src/db/instance-suspend.js')
const { processPendingInstanceDeletion } = await import('../src/services/pending-instance-deletion.js')
const { reconcileDeletionReservation } = await import('../src/services/deletion-reservation-reconciliation.js')
const tag = `${Date.now()}_${Math.floor(Math.random() * 100000)}`
const user = await prisma.user.create({ data: { username: `expiry_user_${tag}`, passwordHash: 'test-only', role: 'admin' } })
const host = await prisma.host.create({ data: { userId: user.id, name: `expiry_host_${tag}`, url: 'https://127.0.0.1:1', status: 'offline', cpuUsed: 10, memoryUsed: 256, diskUsed: 512, natPortsUsedCount: 2 } })
const suspendedAt = new Date(Date.now() - 7 * 86400000)
const instance = await prisma.instance.create({ data: { incusId: `expiry_${tag}`, name: `expiry_${tag}`, userId: user.id, hostId: host.id, image: 'test', status: 'suspended', suspendReason: 'expired', suspendedAt, cpu: 10, memory: 256, disk: 512, portLimit: 2 } })
await prisma.ipAddress.create({ data: { address: '10.254.0.1', type: 'inet4', isPrimary: true, isCustom: false, device: 'eth0', hostId: host.id, instanceId: instance.id } })
let remoteCalls = 0
const remote = { async ensureDeleted() { remoteCalls++ }, async deleteProxySite() { throw new Error('unexpected proxy site') } }
try {
  const claims = await Promise.allSettled([
    claimExpiredInstanceForDeletion(instance.id, instance.version, suspendedAt),
    claimExpiredInstanceForDeletion(instance.id, instance.version, suspendedAt)
  ])
  assert.equal(claims.filter(result => result.status === 'fulfilled' && result.value !== null).length, 1)
  assert.equal((await prisma.instance.findUniqueOrThrow({ where: { id: instance.id } })).status, 'deleting')
  assert.equal(await prisma.ipAddress.count({ where: { instanceId: instance.id } }), 1, 'claim cannot trigger early address release')
  assert.equal((await getSuspendedInstancesOlderThan(3)).some(row => row.id === instance.id), false)
  await assert.rejects(processPendingInstanceDeletion(instance.id, remote), /unavailable/)
  assert.equal(remoteCalls, 0)
  assert.equal(await prisma.ipAddress.count({ where: { instanceId: instance.id } }), 1)
  await prisma.host.update({ where: { id: host.id }, data: { status: 'online' } })
  await assert.rejects(processPendingInstanceDeletion(instance.id, remote), /reservation evidence is unavailable or stale/)
  const pending = await prisma.instance.findUniqueOrThrow({ where: { id: instance.id } })
  assert.equal(pending.deletionRemoteDeleted, true)
  assert.equal(pending.status, 'deleting')
  assert.equal(await prisma.ipAddress.count({ where: { instanceId: instance.id } }), 1)
  const currentHost = await prisma.host.findUniqueOrThrow({ where: { id: host.id } })
  assert.deepEqual([currentHost.cpuUsed, currentHost.memoryUsed, currentHost.diskUsed, currentHost.natPortsUsedCount], [10, 256, 512, 2])
  assert.equal(await reconcileDeletionReservation(instance.id, user.id, {
    requestId: randomUUID(), state: 'reserved', evidenceReference: `ticket-${tag}`,
    reason: 'Verified independent reservation record',
    expected: { instanceVersion: pending.version, hostId: host.id, cpu: 10, memory: 256, disk: 512, portCount: 2, hostEpoch: currentHost.reservationEpoch.toString() }
  }), 'recorded')
  assert.ok(await processPendingInstanceDeletion(instance.id, remote))
  assert.equal(remoteCalls, 1, 'remote deletion is not repeated after confirmation')
  assert.equal((await prisma.instance.findUniqueOrThrow({ where: { id: instance.id } })).status, 'deleted')
  assert.equal(await prisma.ipAddress.count({ where: { instanceId: instance.id } }), 0)
  const finalHost = await prisma.host.findUniqueOrThrow({ where: { id: host.id } })
  assert.deepEqual([finalHost.cpuUsed, finalHost.memoryUsed, finalHost.diskUsed, finalHost.natPortsUsedCount], [0, 0, 0, 0])
  console.log('expiry pending deletion PostgreSQL regression passed')
} finally { await prisma.$disconnect() }
process.exit(0)
