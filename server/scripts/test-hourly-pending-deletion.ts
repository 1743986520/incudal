import assert from 'node:assert/strict'

// Refuse production or any non-dedicated database before importing Prisma.
const databaseUrl = process.env.DATABASE_URL ?? ''
let valid = false
try {
  const u = new URL(databaseUrl)
  const octets = u.hostname.split('.').map(Number)
  const ipv4 = octets.length === 4 && octets.every(n => Number.isInteger(n) && n >= 0 && n <= 255)
  const local = u.hostname === 'localhost' || (ipv4 && (octets[0] === 127 || octets[0] === 10 ||
    (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) || (octets[0] === 192 && octets[1] === 168)))
  valid = ['postgres:', 'postgresql:'].includes(u.protocol) && local && u.pathname === '/incudal_deletion_test'
} catch { /* invalid URL */ }
if (!valid || process.env.INSTANCE_DELETION_TEST_ALLOW !== '1' || databaseUrl !== process.env.INSTANCE_DELETION_TEST_DATABASE_URL) {
  throw new Error('This fixture test only runs against the dedicated local deletion test database')
}

const { prisma } = await import('../src/db/prisma.js')
const { activateHourlyBilling, pauseHourlyBilling, resumeHourlyBilling, settleHourlyInstance, settleSuspendedHourlyRuntime } = await import('../src/services/hourly-billing-scheduler.js')
const { advisoryTransactionLock, INSTANCE_OPERATION_LOCK_NAMESPACE } = await import('../src/db/advisory-locks.js')
const tag = `${Date.now()}_${Math.floor(Math.random() * 100000)}`
const user = await prisma.user.create({ data: { username: `hourly_delete_test_${tag}`, passwordHash: 'test-only', hourlyReservedBalance: 3 } })
const host = await prisma.host.create({ data: { userId: user.id, name: `hourly_test_${tag}`, url: 'https://127.0.0.1:1', status: 'offline', cpuAllowanceMax: 1000, memoryMax: 4096, natPortStart: 10000, natPortEnd: 10100 } })
const pricingSnapshot = {
  cpuUnitPercent: 5, memoryUnitMb: 64, diskUnitMb: 512,
  minCpu: 10, minMemoryMb: 128, minDiskMb: 512,
  cpuPricePerUnit: '0', memoryPricePerUnit: '0', diskPricePerUnit: '0', reserveQuantum: '0.01'
}
async function fixture(name: string, status: 'deleting' | 'deleted' | 'stopped') {
  const instance = await prisma.instance.create({ data: {
    incusId: `${name}_${tag}`, name, userId: user.id, hostId: host.id, image: 'test', status,
    billingMode: 'hourly', cpu: 10, memory: 128, disk: 512,
    ...(status === 'deleting' ? { deletionOriginalStatus: 'running' as const } : {})
  } })
  await prisma.hourlyBillingAccount.create({ data: {
    instanceId: instance.id, pricingSnapshot, status: 'active', prepaidBalance: 1,
    lastSettledAt: new Date(Date.now() - 60000), nextSettlementAt: new Date(Date.now() - 1000)
  } })
  return instance
}
try {
  const deleting = await fixture('deleting', 'deleting')
  const deleted = await fixture('deleted', 'deleted')
  const stopped = await fixture('stopped', 'stopped')
  const pausedDeleting = await fixture('paused_deleting', 'deleting')
  await prisma.hourlyBillingAccount.update({ where: { instanceId: pausedDeleting.id }, data: { status: 'paused', prepaidBalance: 0 } })
  const beforeActivation = await prisma.user.findUniqueOrThrow({ where: { id: user.id } })
  assert.equal(await activateHourlyBilling(pausedDeleting.id), false)
  const afterActivation = await prisma.hourlyBillingAccount.findUniqueOrThrow({ where: { instanceId: pausedDeleting.id } })
  assert.equal(afterActivation.status, 'paused')
  assert.equal(afterActivation.prepaidBalance.toString(), '0')
  assert.equal((await prisma.user.findUniqueOrThrow({ where: { id: user.id } })).balance.toString(), beforeActivation.balance.toString())
  await prisma.hourlyBillingAccount.update({ where: { instanceId: pausedDeleting.id }, data: { status: 'suspended', outstandingAmount: 1 } })
  await assert.rejects(resumeHourlyBilling(pausedDeleting.id, user.id), /INSTANCE_DELETION_IN_PROGRESS/)
  const afterResume = await prisma.hourlyBillingAccount.findUniqueOrThrow({ where: { instanceId: pausedDeleting.id } })
  assert.equal(afterResume.status, 'suspended')
  assert.equal(afterResume.outstandingAmount.toString(), '1')
  // An old suspension reason survives the transition to deleting. The
  // pre-deletion helper must not contact the unreachable host or settle it.
  await prisma.instance.update({ where: { id: pausedDeleting.id }, data: { suspendReason: 'hourly_billing_insufficient_balance' } })
  await settleSuspendedHourlyRuntime(pausedDeleting.id)
  assert.equal((await prisma.hourlyBillingAccount.findUniqueOrThrow({ where: { instanceId: pausedDeleting.id } })).outstandingAmount.toString(), '1')
  // The job's exact candidate selection must not pick up a pending deletion.
  const stale = await prisma.hourlyBillingAccount.findMany({ where: {
    instanceId: { in: [deleting.id, deleted.id, stopped.id] }, status: 'active',
    instance: { status: { notIn: ['running', 'deleting', 'deleted'] } }
  }, select: { instanceId: true } })
  assert.deepEqual(stale.map(row => row.instanceId), [stopped.id])
  await pauseHourlyBilling(deleting.id)
  await settleHourlyInstance(deleting.id)
  await settleHourlyInstance(deleting.id, new Date(), { force: true })
  await pauseHourlyBilling(deleted.id)
  await settleHourlyInstance(deleted.id)
  await settleHourlyInstance(deleted.id, new Date(), { force: true })
  const deletedAccount = await prisma.hourlyBillingAccount.findUniqueOrThrow({ where: { instanceId: deleted.id } })
  assert.equal(deletedAccount.status, 'active')
  assert.equal(deletedAccount.prepaidBalance.toString(), '1')
  let account = await prisma.hourlyBillingAccount.findUniqueOrThrow({ where: { instanceId: deleting.id } })
  assert.equal(account.status, 'active')
  assert.equal(account.prepaidBalance.toString(), '1')
  assert.equal(account.version, 0)
  assert.equal((await prisma.user.findUniqueOrThrow({ where: { id: user.id } })).hourlyReservedBalance.toString(), '3')
  assert.equal(await prisma.hourlyBillingRecord.count({ where: { instanceId: deleting.id } }), 0)

  // A stale scheduler must fail and retry instead of passing a concurrent claim.
  let release!: () => void
  let ready!: () => void
  const released = new Promise<void>(resolve => { release = resolve })
  const locked = new Promise<void>(resolve => { ready = resolve })
  const tx = prisma.$transaction(async db => {
    await advisoryTransactionLock(db, INSTANCE_OPERATION_LOCK_NAMESPACE, deleting.id)
    ready()
    await released
  })
  await locked
  await assert.rejects(pauseHourlyBilling(deleting.id), /Advisory transaction lock is busy/)
  release()
  await tx
  account = await prisma.hourlyBillingAccount.findUniqueOrThrow({ where: { instanceId: deleting.id } })
  assert.equal(account.status, 'active')
  assert.equal(account.prepaidBalance.toString(), '1')

  await pauseHourlyBilling(stopped.id)
  const stoppedAccount = await prisma.hourlyBillingAccount.findUniqueOrThrow({ where: { instanceId: stopped.id } })
  assert.equal(stoppedAccount.status, 'paused')
  assert.equal(stoppedAccount.prepaidBalance.toString(), '0')
  const currentUser = await prisma.user.findUniqueOrThrow({ where: { id: user.id } })
  assert.equal(currentUser.hourlyReservedBalance.toString(), '2')
  console.log('hourly pending-deletion scheduler PostgreSQL regression passed')
} finally {
  await prisma.$disconnect()
}
process.exit(0)
