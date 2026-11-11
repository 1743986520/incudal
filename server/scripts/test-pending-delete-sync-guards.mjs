import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import ts from 'typescript'

const hosts = (await readFile(new URL('../src/routes/hosts.ts', import.meta.url), 'utf8')).replace(/\r\n/g, '\n')
const sync = hosts.slice(hosts.indexOf('  // 批量同步实例状态（仅节点所有者）'), hosts.indexOf('    // 如果有实例被标记为删除', hosts.indexOf('  // 批量同步实例状态（仅节点所有者）')))
assert.match(sync, /status: \{ notIn: \['deleted', 'deleting', 'creating'\] \}/)
const update = sync.slice(sync.indexOf('        if (currentStatus !== incusStatus) {'), sync.indexOf('        // 同步内网 IPv4'))
assert.ok(update)
assert.match(sync, /reconcileMissingInstanceStatus\(instance, client, err\)/)

const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor
function compile(fragment) {
  const js = ts.transpile(`for (let once = 0; once < 1; once++) { ${fragment} }`, { target: ts.ScriptTarget.ES2022 })
  return new AsyncFunction('ctx', `with (ctx) { ${js} }`)
}
const runUpdate = compile(update)
function context(actualStatus, actualVersion) {
  const record = { status: actualStatus, version: actualVersion }
  let billingCalls = 0
  const ctx = {
    currentStatus: 'running', incusStatus: 'stopped', statusChanged: false, changedCount: 0,
    instance: { id: 1, name: 'test', status: 'running', version: 4, billingMode: 'hourly' },
    results: [],
    prisma: { instance: { updateMany: async ({ where, data }) => {
      if (record.status !== where.status || record.version !== where.version) return { count: 0 }
      record.status = data.status
      record.version += data.version.increment
      return { count: 1 }
    } } },
    closeHourlyBilling: async () => { billingCalls++ }
  }
  return { ctx, record, get billingCalls() { return billingCalls } }
}
for (const run of [runUpdate]) {
  for (const [status, version] of [['deleting', 4], ['running', 5]]) {
    const state = context(status, version)
    await run(state.ctx)
    assert.deepEqual(state.record, { status, version }, 'stale sync must not overwrite a changed instance')
    assert.equal(state.ctx.results[0]?.success, false)
    assert.equal(state.billingCalls, 0, 'stale sync must not close billing')
  }
}
{
  const state = context('running', 4)
  await runUpdate(state.ctx)
  assert.deepEqual(state.record, { status: 'stopped', version: 5 })
  assert.equal(state.ctx.statusChanged, true)
}
const admin = (await readFile(new URL('../src/routes/admin-billing.ts', import.meta.url), 'utf8')).replace(/\r\n/g, '\n')
const start = admin.indexOf('  // ==================== 管理员手动延期')
const extend = admin.slice(start, admin.indexOf('  // ====================', start + 10))
assert.match(extend, /instance\.status === 'deleting'/)
assert.equal((extend.match(/where: \{ id: instanceId, version: instance\.version, status: \{ notIn: \['deleted', 'deleting'\] \} \}/g) || []).length, 2, 'paid and free extensions both recheck state transactionally')
console.log('Pending deletion sync and extension regression tests passed')
