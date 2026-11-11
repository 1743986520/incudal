import assert from 'node:assert/strict'

const databaseUrl = process.env.DATABASE_URL ?? ''
let valid = false
try {
  const u = new URL(databaseUrl)
  const p = u.hostname.split('.').map(Number)
  const ipv4 = p.length === 4 && p.every(n => Number.isInteger(n) && n >= 0 && n <= 255)
  const privateIp = ipv4 && (p[0] === 127 || p[0] === 10 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168))
  valid = ['postgres:', 'postgresql:'].includes(u.protocol) && (u.hostname === 'localhost' || privateIp) && u.pathname === '/incudal_deletion_test'
} catch { /* invalid URL */ }
if (!valid || process.env.INSTANCE_DELETION_TEST_ALLOW !== '1' || databaseUrl !== process.env.INSTANCE_DELETION_TEST_DATABASE_URL) {
  throw new Error('This fixture test only runs against the dedicated local deletion test database')
}
const { prisma } = await import('../src/db/prisma.js')
const { processPendingInstanceDeletion } = await import('../src/services/pending-instance-deletion.js')
const { getRemoteOperationAbortSignal } = await import('../src/services/remote-operation-abort.js')
const { recordNewInstanceReservation } = await import('../src/db/resource-reservation-evidence.js')
const tag = `${Date.now()}_${Math.floor(Math.random() * 100000)}`
const user = await prisma.user.create({ data: { username: `abort_user_${tag}`, passwordHash: 'test-only' } })
const host = await prisma.host.create({ data: { userId: user.id, name: `abort_host_${tag}`, url: 'https://127.0.0.1:1', status: 'online', cpuAllowanceMax: 1000, memoryMax: 4096, natPortStart: 10000, natPortEnd: 10100, cpuUsed: 10, memoryUsed: 128, diskUsed: 512, natPortsUsedCount: 2 } })
const instance = await prisma.$transaction(async tx => {
  const row = await tx.instance.create({ data: { incusId: `abort_${tag}`, name: `abort_${tag}`, userId: user.id, hostId: host.id, image: 'test', status: 'deleting', deletionOriginalStatus: 'running', cpu: 10, memory: 128, disk: 512, portLimit: 2 } })
  await recordNewInstanceReservation(tx, { instanceId: row.id, hostId: host.id, cpu: 10, memory: 128, disk: 512, portCount: 2 })
  return row
})
let entered!: () => void
const enteredPromise = new Promise<void>(resolve => { entered = resolve })
try {
  const processing = processPendingInstanceDeletion(instance.id, {
    async ensureDeleted() {
      const signal = getRemoteOperationAbortSignal()
      assert.ok(signal, 'the remote operation receives the lock abort signal')
      entered()
      await new Promise<void>(resolve => {
        if (signal.aborted) resolve()
        else signal.addEventListener('abort', () => resolve(), { once: true })
      })
    },
    async deleteProxySite() { throw new Error('unexpected site cleanup') }
  })
  // Attach the rejection immediately; Node must not report an unhandled rejection.
  const result = processing.then(() => null, (error: unknown) => error)
  await enteredPromise
  const holders = await prisma.$queryRaw<Array<{ pid: number }>>`
    SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND classid = 4112::oid AND objid = ${instance.id}::oid AND granted
  `
  assert.equal(holders.length, 1)
  const terminated = await prisma.$queryRaw<Array<{ killed: boolean }>>`SELECT pg_terminate_backend(${holders[0].pid}) AS killed`
  assert.equal(terminated[0]?.killed, true)
  const outcome = await result
  assert.ok(outcome instanceof Error)
  assert.match(outcome.message, /lock connection failed/)
  const row = await prisma.instance.findUniqueOrThrow({ where: { id: instance.id } })
  assert.equal(row.status, 'deleting')
  assert.equal(row.deletionRemoteDeleted, false, 'a remote response after lock loss must not be accepted')
  const after = await prisma.host.findUniqueOrThrow({ where: { id: host.id } })
  assert.deepEqual([after.cpuUsed, after.memoryUsed, after.diskUsed, after.natPortsUsedCount], [10, 128, 512, 2])
  console.log('pending deletion lock-loss PostgreSQL regression passed')
} finally { await prisma.$disconnect() }
process.exit(0)
