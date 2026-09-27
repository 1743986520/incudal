// Dependency-free checks of the actual authorization and transaction bodies.
// Run with Node 22.13+ or 24: node --test server/scripts/test-permission-regressions.mjs
import assert from 'node:assert/strict'
import test from 'node:test'
import { readFileSync } from 'node:fs'
import { stripTypeScriptTypes } from 'node:module'
import vm from 'node:vm'
const read = path => readFileSync(new URL(`../src/${path}`, import.meta.url), 'utf8')
const authSource = read('plugins/auth-decorators.ts').replace(/^import .*$/gm, '').replace(/^export /gm, '')
async function authenticate(method, currentUser, invalidated = false) {
  const handlers = {}
  const context = vm.createContext({
    prisma: { user: { findUnique: async () => currentUser } },
    isAccessTokenInvalidated: async () => invalidated,
    sharedGet: () => { throw new Error('Authorization must not read stale cache') }
  })
  vm.runInContext(stripTypeScriptTypes(authSource), context)
  await context.registerAuthDecorators({ decorate: (name, fn) => { handlers[name] = fn } })
  const request = { user: { id: 1, iat: 100, role: 'admin', status: 'active' }, jwtVerify: async () => {} }
  const reply = { status: 200, code(value) { this.status = value; return this }, send(body) { this.body = body; return this } }
  await handlers[method](request, reply)
  return { request, reply }
}
for (const [name, method, user, revoked, expected] of [
  ['demoted administrator loses access despite old JWT role', 'authenticateAdmin', { role: 'user', status: 'active' }, false, 403],
  ['banned account cannot authenticate', 'authenticate', { role: 'user', status: 'banned' }, false, 401],
  ['deleted account cannot authenticate', 'authenticate', null, false, 401],
  ['revoked token cannot authenticate', 'authenticateAdmin', { role: 'admin', status: 'active' }, true, 401],
  ['current administrator retains access', 'authenticateAdmin', { role: 'admin', status: 'active' }, false, 200],
  ['administrator remains excluded from user-only APIs', 'authenticateUser', { role: 'admin', status: 'active' }, false, 403],
  ['demoted account can use regular-user APIs', 'authenticateUser', { role: 'user', status: 'active' }, false, 200]
]) test(name, async () => assert.equal((await authenticate(method, user, revoked)).reply.status, expected))

const routes = read('routes/users.ts')
function transactionCode(kind) {
  const marker = kind === 'role' ? 'roleUpdate = await prisma.$transaction(' : 'user = await prisma.$transaction('
  const start = routes.indexOf(marker)
  const end = routes.indexOf('\n      })\n    } catch', start)
  assert.ok(start >= 0 && end > start)
  return stripTypeScriptTypes(`async function run() { return ${routes.slice(start + marker.indexOf('await '), end + '\n      })'.length)} }`)
}
function harness(kind, options = {}) {
  let state = { target: { id: 2, role: options.targetRole || 'user', status: 'active', banReason: 'old', username: 'target' }, tokens: 2, invalidated: false }
  const tx = {
    user: {
      findUnique: async ({ where }) => where.id === 1 ? { role: options.actorRole || 'admin', status: 'active' } : { ...state.target },
      update: async ({ data }) => Object.assign(state.target, data),
      count: async () => 2
    },
    refreshToken: { deleteMany: async () => { const count = state.tokens; state.tokens = 0; return { count } } },
    tokenInvalidation: { upsert: async () => { if (options.failRevocation) throw new Error('database unavailable'); state.invalidated = true } }
  }
  const context = vm.createContext({
    request: { user: { id: 1 } }, userId: 2, role: 'admin', status: options.status || 'banned', reason: 'abuse',
    invalidatedAt: 100, userLevelSessionId: '__USER_LEVEL__', USER_ADMIN_ROLE_LOCK_NAMESPACE: 1,
    tryAdvisoryTransactionLock: async () => !options.busy,
    prisma: { $transaction: async fn => {
      const before = structuredClone(state)
      try { return await fn(tx) } catch (error) { state = before; throw error }
    } }
  })
  vm.runInContext(transactionCode(kind), context)
  return { run: () => context.run(), state: () => state }
}
for (const kind of ['role', 'status']) {
  test(`${kind} changes reject an actor demoted after authentication`, async () => {
    const h = harness(kind, { actorRole: 'user' })
    await assert.rejects(h.run(), /ADMIN_PERMISSION_REVOKED/)
    assert.equal(h.state().tokens, 2)
    assert.equal(h.state().target.status, 'active')
  })
  test(`${kind} changes refuse concurrent permission mutations`, async () => {
    const h = harness(kind, { busy: true })
    await assert.rejects(h.run(), /USER_ADMIN_ROLE_LOCK_BUSY/)
    assert.equal(h.state().tokens, 2)
  })
  test(`${kind} changes roll back if credential revocation fails`, async () => {
    const h = harness(kind, { failRevocation: true })
    await assert.rejects(h.run(), /database unavailable/)
    assert.equal(h.state().target.role, 'user')
    assert.equal(h.state().target.status, 'active')
    assert.equal(h.state().tokens, 2)
  })
}
test('ban rechecks the target role inside the transaction', async () => {
  const h = harness('status', { targetRole: 'admin' })
  await assert.rejects(h.run(), /CANNOT_BAN_ADMIN/)
  assert.equal(h.state().target.status, 'active')
})
test('ban commits account state and both credential revocations together', async () => {
  const h = harness('status'); await h.run()
  assert.equal(h.state().target.status, 'banned')
  assert.equal(h.state().tokens, 0)
  assert.equal(h.state().invalidated, true)
})
test('unban clears the old ban reason', async () => {
  const h = harness('status', { status: 'active' }); await h.run()
  assert.equal(h.state().target.banReason, null)
})
