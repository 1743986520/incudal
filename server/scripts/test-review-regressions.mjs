// Dependency-free behavioral regression checks against the actual TS functions.
// Run with Node 22.13+ (or 24): node --test scripts/test-review-regressions.mjs
import assert from 'node:assert/strict'
import test from 'node:test'
import { readFileSync } from 'node:fs'
import { stripTypeScriptTypes } from 'node:module'
import vm from 'node:vm'

function section(file, start, end) {
  const source = readFileSync(new URL(`../src/${file}`, import.meta.url), 'utf8')
  const a = source.indexOf(start)
  const b = source.indexOf(end, a)
  assert.ok(a >= 0 && b > a)
  return stripTypeScriptTypes(source.slice(a, b).replace(/^export /, ''))
}
function load(code, bindings) {
  const context = vm.createContext(bindings)
  vm.runInContext(code, context)
  return context
}
function matches(row, where) {
  return Object.entries(where).every(([key, value]) => {
    if (key === 'OR') return value.some(part => matches(row, part))
    if (key === 'host') return matches(row.host, value)
    if (value && typeof value === 'object') {
      return Object.entries(value).every(([op, target]) => {
        if (op === 'lt') return row[key] !== null && row[key] < target
        if (op === 'not') return row[key] !== target
        if (op === 'in') return target.includes(row[key])
        throw new Error(`Unsupported predicate ${op}`)
      })
    }
    return row[key] === value
  })
}
const selectCode = section('services/status-scheduler.ts', 'async function getInstancesToSync', '/**\n * 同步单个实例状态')
const syncCode = section('services/status-scheduler.ts', 'async function syncInstanceStatus', '/**\n * 执行状态同步任务')
const suspendCode = section('db/instance-suspend.ts', 'export async function suspendInstanceByExpiry', '/**\n * 封停实例（管理员')

test('200 eligible instances all receive synchronization; fresh rows do not block old rows', async () => {
  let now = Date.now()
  class Clock extends Date { static now() { return now } }
  const rows = Array.from({ length: 200 }, (_, i) => ({
    id: i + 1, status: i < 100 ? 'running' : 'stopped', host: { status: 'online' },
    updatedAt: new Date(now - 3600000 - i * 1000), lastSyncedAt: null
  }))
  const seen = new Set()
  const context = load(selectCode, {
    Date: Clock, SYNC_INTERVAL_RUNNING_MS: 120000, SYNC_INTERVAL_STOPPED_MS: 600000,
    prisma: { instance: { findMany: async query => rows.filter(row => matches(row, query.where)).sort((a, b) => {
      for (const order of query.orderBy) {
        const [key, rule] = Object.entries(order)[0]
        if (a[key] === null && b[key] !== null) return -1
        if (b[key] === null && a[key] !== null) return 1
        const delta = Number(a[key]) - Number(b[key])
        if (delta) return (rule === 'desc' ? -1 : 1) * delta
      }
      return 0
    }).slice(0, query.take) } }
  })
  for (let round = 0; round < 8; round++) {
    for (const row of await context.getInstancesToSync(50)) {
      seen.add(row.id)
      row.updatedAt = new Date(now)
      row.lastSyncedAt = new Date(now)
    }
    now += 60000
  }
  assert.equal(seen.size, 200)
})

for (const remote of ['stopped', 'running', 'not found']) {
  test(`late ${remote} report cannot overwrite suspension or alter hourly billing`, async () => {
    const row = { id: 1, status: 'suspended', version: 2 }
    let billingCalls = 0
    const context = load(syncCode, {
      Date, console, INSTANCE_TIMEOUT_MS: 10000, isHostHealthy: () => true,
      recordHostSuccess() {}, recordHostError() {},
      db: { getHostById: async () => ({ id: 1 }) }, getIncusClient: async () => ({}),
      getInstanceState: async () => { if (remote === 'not found') throw new Error('Instance not found'); return { status: remote } },
      withTimeout: async promise => promise, mapInstanceStatus: value => value,
      prisma: { instance: { updateMany: async ({ where, data }) => {
        if (!matches(row, where)) return { count: 0 }
        Object.assign(row, data); return { count: 1 }
      } } },
      pauseHourlyBilling: async () => { billingCalls++ }, activateHourlyBilling: async () => { billingCalls++ },
      closeHourlyBilling: async () => { billingCalls++ }, sendNotification: async () => {}
    })
    const result = await context.syncInstanceStatus({ id: 1, version: 1, status: 'running', host: { id: 1 }, user: { id: 1 }, billingMode: 'hourly' })
    assert.equal(row.status, 'suspended')
    assert.equal(row.version, 2)
    assert.equal(result.changed, false)
    assert.equal(billingCalls, 0)
  })
}

function expiryHarness(status = 'running', reason = null) {
  let row = { id: 1, version: 1, status, suspendReason: reason, billingMode: 'package', packagePlanId: 1,
    expiresAt: new Date(Date.now() - 86400000), suspendedAt: status === 'suspended' ? new Date(1000) : null }
  const tx = { instance: {
    findUnique: async () => structuredClone(row),
    updateMany: async ({ where, data }) => {
      if (!matches(row, where)) return { count: 0 }
      row = { ...row, ...data, version: row.version + 1 }; return { count: 1 }
    }
  } }
  const context = load(suspendCode, {
    Date, INSTANCE_OPERATION_LOCK_NAMESPACE: 4106, advisoryTransactionLock: async () => {},
    prisma: { $transaction: async fn => {
      const before = structuredClone(row)
      try { return await fn(tx) } catch (error) { row = before; throw error }
    } }
  })
  return { context, row: () => row }
}

test('failed stop rolls back suspension and next attempt can succeed', async () => {
  const h = expiryHarness()
  await assert.rejects(h.context.suspendInstanceByExpiry(1, async () => { throw new Error('offline') }), /offline/)
  assert.equal(h.row().status, 'running')
  assert.equal(await h.context.suspendInstanceByExpiry(1, async () => {}), true)
  assert.equal(h.row().status, 'suspended')
})

test('scheduler propagates host failure into suspension transaction', async () => {
  const h = expiryHarness()
  const processCode = section('services/billing-scheduler.ts', 'async function processExpirySuspend', '// ==================== 到期删除任务')
  const context = load(processCode, {
    console: { log() {}, error() {} }, suspendInstanceByExpiry: h.context.suspendInstanceByExpiry,
    db: { getHostById: async () => { throw new Error('offline') } },
    sendNotification: async () => { throw new Error('must not notify success') }, createLog: async () => {}
  })
  await context.processExpirySuspend({ id: 1, hostId: 1 })
  assert.equal(h.row().status, 'running')
})

test('legacy expired suspension retries stop without resetting date or notification; manual suspension is untouched', async () => {
  for (const reason of ['expired', 'manual']) {
    const h = expiryHarness('suspended', reason)
    let stops = 0
    assert.equal(await h.context.suspendInstanceByExpiry(1, async () => { stops++ }), false)
    assert.equal(stops, reason === 'expired' ? 1 : 0)
    assert.equal(h.row().suspendedAt.getTime(), 1000)
    assert.equal(h.row().version, 1)
  }
})

test('traffic redemption preserves unlimited and increments zero/finite limits', async () => {
  const code = section('routes/checkin.ts', 'const trafficBytes = BigInt(codeValue)', 'databaseApplied = true')
  for (const [before, expected] of [[null, null], ['0', 10n * 1024n ** 3n], ['123', 123n + 10n * 1024n ** 3n]]) {
    let actual
    const context = load(`async function redeem() { ${code} }`, {
      codeValue: 10, instanceId: 1, instance: { monthly_traffic_limit: before },
      db: { updateInstanceResources: async (_id, data) => { actual = data.monthlyTrafficLimit } }
    })
    await context.redeem()
    assert.equal(actual, expected)
  }
})

test('expiry selector includes legacy expired suspension but excludes manual suspension and renewed instances', async () => {
  const code = section('db/instance-suspend.ts', 'export async function getExpiredUnsuspendedInstances', '/**\n * 更新到期通知时间')
  const old = new Date(Date.now() - 86400000)
  const base = { billingMode: 'package', packagePlanId: 1, expiresAt: old }
  const rows = [
    { ...base, id: 1, status: 'running' },
    { ...base, id: 2, status: 'suspended', suspendReason: 'expired' },
    { ...base, id: 3, status: 'suspended', suspendReason: 'manual' },
    { ...base, id: 4, status: 'running', expiresAt: new Date(Date.now() + 86400000) },
    { ...base, id: 5, status: 'deleted', suspendReason: 'expired' }
  ]
  const context = load(code, { Date, prisma: { instance: { findMany: async ({ where }) => rows.filter(row => matches(row, where)) } } })
  assert.deepEqual((await context.getExpiredUnsuspendedInstances()).map(row => row.id), [1, 2])
})

test('traffic compensation restores null instead of setting zero', async () => {
  const code = section('routes/checkin.ts', 'await db.updateInstanceResources(instanceId, {\n            monthlyTrafficLimit:', "} else if (codeType === 'p' && databaseApplied)").replace(/\}\s*$/, '')
  for (const before of [null, '0', '123']) {
    let actual
    const context = load(`async function compensate() { ${code} }`, {
      instanceId: 1, instance: { monthly_traffic_limit: before },
      db: { updateInstanceResources: async (_id, data) => { actual = data.monthlyTrafficLimit } }
    })
    await context.compensate()
    assert.equal(actual, before === null ? null : BigInt(before))
  }
})
