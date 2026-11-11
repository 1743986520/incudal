import assert from 'node:assert/strict'

const databaseUrl = process.env.DATABASE_URL ?? ''
let valid = false
try {
  const u = new URL(databaseUrl)
  const parts = u.hostname.split('.').map(Number)
  const ipv4 = parts.length === 4 && parts.every(n => Number.isInteger(n) && n >= 0 && n <= 255)
  const privateIp = ipv4 && (parts[0] === 127 || parts[0] === 10 || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) || (parts[0] === 192 && parts[1] === 168))
  valid = ['postgres:', 'postgresql:'].includes(u.protocol) && (u.hostname === 'localhost' || privateIp) && u.pathname === '/incudal_deletion_test'
} catch { /* invalid URL */ }
if (!valid || process.env.INSTANCE_DELETION_TEST_ALLOW !== '1' || databaseUrl !== process.env.INSTANCE_DELETION_TEST_DATABASE_URL) {
  throw new Error('This fixture test only runs against the dedicated local deletion test database')
}
const { prisma } = await import('../src/db/prisma.js')
const { settleUserDestroyBilling } = await import('../src/db/billing-operations.js')
const { runWithRemoteOperationAbortSignal } = await import('../src/services/remote-operation-abort.js')
const tag = `${Date.now()}_${Math.floor(Math.random() * 100000)}`
const owner = await prisma.user.create({ data: { username: `destroy_owner_${tag}`, passwordHash: 'test-only', hostingBalance: 100 } })
const user = await prisma.user.create({ data: { username: `destroy_customer_${tag}`, passwordHash: 'test-only', balance: 0 } })
const host = await prisma.host.create({ data: { userId: owner.id, name: `destroy_host_${tag}`, url: 'https://127.0.0.1:1', cpuAllowanceMax: 1000, memoryMax: 4096, natPortStart: 10000, natPortEnd: 10100 } })
const now = Date.now(), day = 86400000
const requestedAt = new Date(now - 16 * day)
async function fixture(name: string, options: { remote?: boolean; mode?: 'user_destroy' | 'privileged_delete' } = {}) {
  const row = await prisma.instance.create({ data: {
    incusId: `${name}_${tag}`, name, userId: user.id, hostId: host.id, image: 'test', status: 'deleted',
    cpu: 10, memory: 128, disk: 512, deletionBillingPending: true,
    deletionRemoteDeleted: options.remote ?? true, deletionBillingMode: options.mode ?? 'user_destroy',
    deletionRefundableValue: 50, deletionRequestedAt: requestedAt
  } })
  await prisma.instanceBillingRecord.create({ data: {
    instanceId: row.id, userId: user.id, type: 'newPurchase', amount: 100,
    periodStart: new Date(now - 31 * day), periodEnd: new Date(now - day)
  } })
  return row
}
function params(instance: Awaited<ReturnType<typeof fixture>>, refundableValue = 50) {
  return { requestUserId: user.id, instance, refundableValue, feeWaiver: false }
}
try {
  const first = await fixture('normal')
  const results = await Promise.allSettled(Array.from({ length: 4 }, () => settleUserDestroyBilling(params(first, 100))))
  assert.equal(results.filter(r => r.status === 'fulfilled').length, 1, 'concurrent settlement must have one winner')
  const success = results.find(r => r.status === 'fulfilled')
  assert.ok(success && success.status === 'fulfilled')
  assert.equal(success.value.refundAmount, 50, 'settlement must not exceed persisted quote')
  assert.equal(success.value.feeAmount, 0)
  assert.equal((await prisma.user.findUniqueOrThrow({ where: { id: user.id } })).balance.toString(), '50')
  assert.equal((await prisma.user.findUniqueOrThrow({ where: { id: owner.id } })).hostingBalance.toString(), '50', 'host refund uses request-time service value even after expiration')
  assert.equal(await prisma.userDestroyRecord.count({ where: { instanceId: first.id } }), 1)
  assert.equal(await prisma.instanceBillingRecord.count({ where: { instanceId: first.id, type: 'refund' } }), 1)
  const retry = await settleUserDestroyBilling(params(first, 100))
  assert.equal(retry.refundAmount, 50)
  assert.equal((await prisma.user.findUniqueOrThrow({ where: { id: user.id } })).balance.toString(), '50')
  assert.equal((await prisma.user.findUniqueOrThrow({ where: { id: owner.id } })).hostingBalance.toString(), '50')

  const unavailable = await fixture('no_remote', { remote: false })
  await assert.rejects(settleUserDestroyBilling(params(unavailable)), /REMOTE_DELETION_NOT_CONFIRMED/)
  const badMode = await fixture('wrong_mode', { mode: 'privileged_delete' })
  await assert.rejects(settleUserDestroyBilling(params(badMode)), /DELETION_BILLING_STATE_INVALID/)
  const wrongOwner = await fixture('wrong_owner')
  await assert.rejects(settleUserDestroyBilling({ ...params(wrongOwner), requestUserId: owner.id }), /DELETION_BILLING_IDENTITY_CHANGED/)
  assert.equal(await prisma.userDestroyRecord.count({ where: { instanceId: { in: [unavailable.id, badMode.id, wrongOwner.id] } } }), 0)
  assert.equal((await prisma.user.findUniqueOrThrow({ where: { id: user.id } })).balance.toString(), '50')
  const subsequent = await fixture('subsequent')
  const feeResult = await settleUserDestroyBilling({ ...params(subsequent, 1), feeWaiver: true })
  assert.equal(feeResult.refundAmount, 45, 'the persisted quote and waiver, not stale caller arguments, determine settlement')
  assert.equal(feeResult.feeAmount, 5)
  assert.equal((await prisma.user.findUniqueOrThrow({ where: { id: user.id } })).balance.toString(), '95')
  assert.equal((await prisma.user.findUniqueOrThrow({ where: { id: owner.id } })).hostingBalance.toString(), '5')
  const missing = await fixture('missing_quote')
  await prisma.instance.update({ where: { id: missing.id }, data: { status: 'deleting', deletionRefundableValue: null } })
  await assert.rejects(settleUserDestroyBilling(params(missing)), /DELETION_BILLING_QUOTE_MISSING/)
  const legacy = await fixture('legacy_quote')
  await prisma.instance.update({ where: { id: legacy.id }, data: { deletionRequestedAt: null, deletionRefundableValue: null } })
  const legacyResult = await settleUserDestroyBilling(params(legacy, 20))
  assert.equal(legacyResult.refundAmount, 18, 'legacy rows without a persisted quote retain recovery behavior')

  // Abort after the refund row has been inserted but before transaction
  // completion; the transaction must roll back all money and marker changes.
  const aborted = await fixture('abort_during_refund')
  const functionName = `test_destroy_delay_${tag}`
  const triggerName = `test_destroy_delay_trigger_${tag}`
  await prisma.$executeRawUnsafe(`CREATE FUNCTION "${functionName}"() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.instance_id = ${aborted.id} AND NEW.type = 'refund' THEN PERFORM pg_sleep(2); END IF; RETURN NEW; END $$`)
  await prisma.$executeRawUnsafe(`CREATE TRIGGER "${triggerName}" AFTER INSERT ON instance_billing_records FOR EACH ROW EXECUTE FUNCTION "${functionName}"()`)
  try {
    const controller = new AbortController()
    const beforeUser = (await prisma.user.findUniqueOrThrow({ where: { id: user.id } })).balance.toString()
    const beforeOwner = (await prisma.user.findUniqueOrThrow({ where: { id: owner.id } })).hostingBalance.toString()
    const settlement = runWithRemoteOperationAbortSignal(controller.signal, () => settleUserDestroyBilling(params(aborted)))
      .then(() => null, (error: unknown) => error)
    let inTrigger = false
    for (let attempt = 0; attempt < 100 && !inTrigger; attempt++) {
      const waiting = await prisma.$queryRaw<Array<{ count: bigint }>>`
        SELECT count(*) AS count FROM pg_stat_activity WHERE datname = current_database() AND wait_event = 'PgSleep'
      `
      inTrigger = Number(waiting[0]?.count ?? 0) > 0
      if (!inTrigger) await new Promise(resolve => setTimeout(resolve, 50))
    }
    assert.ok(inTrigger, 'refund transaction reached its delayed insert')
    controller.abort(new Error('simulated lock loss during refund'))
    const error = await settlement
    assert.ok(error instanceof Error)
    assert.match(error.message, /simulated lock loss/)
    assert.equal((await prisma.user.findUniqueOrThrow({ where: { id: user.id } })).balance.toString(), beforeUser)
    assert.equal((await prisma.user.findUniqueOrThrow({ where: { id: owner.id } })).hostingBalance.toString(), beforeOwner)
    assert.equal(await prisma.instanceBillingRecord.count({ where: { instanceId: aborted.id, type: 'refund' } }), 0)
    assert.equal((await prisma.instance.findUniqueOrThrow({ where: { id: aborted.id } })).deletionBillingPending, true)
  } finally {
    await prisma.$executeRawUnsafe(`DROP TRIGGER "${triggerName}" ON instance_billing_records`)
    await prisma.$executeRawUnsafe(`DROP FUNCTION "${functionName}"()`)
  }
  console.log('user destroy settlement PostgreSQL regression passed')
} finally { await prisma.$disconnect() }
process.exit(0)
