import assert from 'node:assert/strict'

const url = process.env.DATABASE_URL ?? ''
let safe = false
try {
  const u = new URL(url), p = u.hostname.split('.').map(Number)
  const ip = p.length === 4 && p.every(n => Number.isInteger(n) && n >= 0 && n <= 255)
  safe = ['postgres:', 'postgresql:'].includes(u.protocol) && u.pathname === '/incudal_deletion_test' &&
    (u.hostname === 'localhost' || (ip && (p[0] === 127 || p[0] === 10 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168))))
} catch { /* invalid URL */ }
if (!safe || process.env.INSTANCE_DELETION_TEST_ALLOW !== '1' || process.env.INSTANCE_DELETION_TEST_DATABASE_URL !== url) throw new Error('Only the dedicated local deletion database is allowed')
const { prisma } = await import('../src/db/prisma.js')
const { settleInstance, payPendingTrafficBillAndUnsuspend } = await import('../src/services/traffic-billing-scheduler.js')
const { advisoryTransactionLock, INSTANCE_OPERATION_LOCK_NAMESPACE } = await import('../src/db/advisory-locks.js')
const tag = `${Date.now()}_${Math.floor(Math.random() * 100000)}`
const user = await prisma.user.create({ data: { username: `traffic_lock_${tag}`, passwordHash: 'test-only', balance: 10 } })
const host = await prisma.host.create({ data: { userId: user.id, name: `traffic_lock_${tag}`, url: 'https://127.0.0.1:1' } })
let sequence = 0
async function fixture(status: 'running' | 'suspended') {
  const name = `traffic_${status}_${tag}_${++sequence}`
  return prisma.instance.create({ data: { name, incusId: name, image: 'test', userId: user.id, hostId: host.id,
    status, suspendReason: status === 'suspended' ? 'traffic_billing_insufficient_balance' : null, cpu: 10, memory: 128, disk: 512,
    trafficBillingMode: 'usage', trafficUnitPrice: 100, monthlyTrafficUsed: 2147483648n, monthlyTrafficLimit: 0n } })
}
try {
  for (const status of ['running', 'suspended'] as const) {
    const instance = await fixture(status)
    let ready!: () => void, release!: () => void
    const locked = new Promise<void>(resolve => { ready = resolve })
    const wait = new Promise<void>(resolve => { release = resolve })
    const claim = prisma.$transaction(async tx => {
      await advisoryTransactionLock(tx, INSTANCE_OPERATION_LOCK_NAMESPACE, instance.id)
      await tx.instance.update({ where: { id: instance.id }, data: { status: 'deleting', deletionOriginalStatus: status, version: { increment: 1 } } })
      ready(); await wait
    }, { timeout: 15000 })
    await locked
    const attempt = status === 'running' ? settleInstance(instance.id, new Date(), 'hourly') : payPendingTrafficBillAndUnsuspend(instance.id, user.id)
    await assert.rejects(attempt, /lock is busy/)
    release(); await claim
    if (status === 'running') assert.equal(await settleInstance(instance.id, new Date(), 'hourly'), null)
    else await assert.rejects(payPendingTrafficBillAndUnsuspend(instance.id, user.id), /INSTANCE_NOT_TRAFFIC_SUSPENDED/)
    assert.equal((await prisma.instance.findUniqueOrThrow({ where: { id: instance.id } })).status, 'deleting')
    assert.equal(await prisma.trafficBillingRecord.count({ where: { instanceId: instance.id } }), 0)
    assert.equal(Number((await prisma.user.findUniqueOrThrow({ where: { id: user.id } })).balance), 10)
  }
  const normal = await fixture('running')
  const now = new Date()
  assert.ok(await settleInstance(normal.id, now, 'hourly'))
  assert.equal(Number((await prisma.user.findUniqueOrThrow({ where: { id: user.id } })).balance), 8)
  assert.equal(await prisma.trafficBillingRecord.count({ where: { instanceId: normal.id, status: 'paid' } }), 1)
  assert.equal(await settleInstance(normal.id, now, 'hourly'), null)
  assert.equal(Number((await prisma.user.findUniqueOrThrow({ where: { id: user.id } })).balance), 8)
  console.log('traffic billing deletion-lock PostgreSQL regression passed')
} finally { await prisma.$disconnect() }
process.exit(0)
