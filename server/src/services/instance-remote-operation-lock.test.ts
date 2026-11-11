import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { test } from 'node:test'
import { Pool } from 'pg'
import { createServer, type Socket } from 'node:net'

const testDatabaseUrl = process.env.INSTANCE_LOCK_TEST_DATABASE_URL
const instanceId = 1700000000 + Math.floor(Math.random() * 1000000)
let allowSessionTermination = false
try {
  const url = new URL(testDatabaseUrl ?? '')
  const octets = url.hostname.split('.').map(Number)
  const validIpv4 = octets.length === 4 && octets.every(n => Number.isInteger(n) && n >= 0 && n <= 255)
  const privateAddress = validIpv4 && (octets[0] === 10 || (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) || (octets[0] === 192 && octets[1] === 168) || octets[0] === 127)
  const port = Number(url.port || '5432')
  allowSessionTermination = process.env.INSTANCE_DELETION_TEST_ALLOW === '1'
    && process.env.INSTANCE_LOCK_TEST_ALLOW === '1'
    && testDatabaseUrl === process.env.DATABASE_URL
    && testDatabaseUrl === process.env.INSTANCE_DELETION_TEST_DATABASE_URL
    && ['postgres:', 'postgresql:'].includes(url.protocol)
    && (url.hostname === 'localhost' || privateAddress)
    && url.pathname === '/incudal_deletion_test' && Number.isInteger(port) && port >= 1 && port <= 65535
} catch { /* invalid or absent URL: skip this destructive fixture */ }

test('unexpected lock-session termination aborts the active operation', {
  skip: !allowSessionTermination
}, async () => {
  const { withInstanceRemoteOperationLock } = await import('./instance-remote-operation-lock.js')
  const { getRemoteOperationAbortSignal } = await import('./remote-operation-abort.js')
  const otherPool = new Pool({ connectionString: testDatabaseUrl })
  let entered!: () => void
  const active = new Promise<void>(resolve => { entered = resolve })
  const operation = withInstanceRemoteOperationLock(instanceId + 1, async () => {
    const signal = getRemoteOperationAbortSignal()!
    entered()
    await new Promise<void>(resolve => signal.addEventListener('abort', () => resolve(), { once: true }))
    signal.throwIfAborted()
  })
  try {
    await active
    const result = await otherPool.query<{ pid: number }>(
      `SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND classid = 4112 AND objid = $1 AND granted`,
      [instanceId + 1]
    )
    assert.equal(result.rowCount, 1)
    await otherPool.query('SELECT pg_terminate_backend($1)', [result.rows[0]!.pid])
    await assert.rejects(operation, /lock connection failed/)
  } finally {
    await otherPool.end()
  }
})

test('outer lock loss aborts an in-flight Caddy request inside a nested domain lock', {
  skip: !allowSessionTermination
}, async () => {
  const { withInstanceRemoteOperationLock, withDomainRemoteOperationLock } = await import('./instance-remote-operation-lock.js')
  const { CaddyClient } = await import('../lib/caddy-client.js')
  const otherPool = new Pool({ connectionString: testDatabaseUrl })
  let socket: Socket | undefined
  let connected!: () => void
  const connection = new Promise<void>(resolve => { connected = resolve })
  // A test-only TCP listener accepts TLS but never completes the handshake;
  // no Caddy request is sent to any external service.
  const server = createServer(client => { socket = client; connected() })
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  const address = server.address()
  assert.ok(address && typeof address !== 'string')
  const client = new CaddyClient({ host: '127.0.0.1', port: address.port, username: 'test', password: 'test' })
  const operation = withInstanceRemoteOperationLock(instanceId + 2, async () => {
    const inner = await withDomainRemoteOperationLock('nested.example.test', async () => client.deleteSite('nested.example.test'))
    assert.equal(inner.acquired, true)
  })
  let timeout: ReturnType<typeof setTimeout> | undefined
  try {
    await connection
    const result = await otherPool.query<{ pid: number }>(
      `SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND classid = 4112 AND objid = $1 AND granted`,
      [instanceId + 2]
    )
    assert.equal(result.rowCount, 1)
    await otherPool.query('SELECT pg_terminate_backend($1)', [result.rows[0]!.pid])
    await assert.rejects(Promise.race([
      operation,
      new Promise<never>((_, reject) => { timeout = setTimeout(() => reject(new Error('abort did not propagate')), 5000) })
    ]), error => error instanceof Error && !error.message.includes('abort did not propagate'))
  } finally {
    if (timeout) clearTimeout(timeout)
    socket?.destroy()
    await new Promise<void>(resolve => server.close(() => resolve()))
    await otherPool.end()
  }
})

test('remote operation lock excludes a pending deletion session and releases on errors', { skip: !testDatabaseUrl }, async () => {
  const originalDatabaseUrl = process.env.DATABASE_URL
  process.env.DATABASE_URL = testDatabaseUrl
  const { withInstanceRemoteOperationLock, withInstanceAndDomainRemoteOperationLock, withDomainRemoteOperationLock } = await import('./instance-remote-operation-lock.js')
  if (originalDatabaseUrl === undefined) delete process.env.DATABASE_URL
  else process.env.DATABASE_URL = originalDatabaseUrl
  const otherPool = new Pool({ connectionString: testDatabaseUrl })
  const connection = await otherPool.connect()
  try {
    await connection.query('SELECT pg_advisory_lock($1, $2)', [4112, instanceId])
    let ran = false
    assert.deepEqual(await withInstanceRemoteOperationLock(instanceId, async () => { ran = true }), { acquired: false })
    assert.equal(ran, false)
    await connection.query('SELECT pg_advisory_unlock($1, $2)', [4112, instanceId])

    await assert.rejects(withInstanceRemoteOperationLock(instanceId, async () => { throw new Error('remote failure') }), /remote failure/)
    const probe = await connection.query<{ locked: boolean }>('SELECT pg_try_advisory_lock($1, $2) AS locked', [4112, instanceId])
    assert.equal(probe.rows[0]?.locked, true)
    await connection.query('SELECT pg_advisory_unlock($1, $2)', [4112, instanceId])

    let release!: () => void
    let entered!: () => void
    const enteredPromise = new Promise<void>(resolve => { entered = resolve })
    const hold = new Promise<void>(resolve => { release = resolve })
    const operation = withInstanceRemoteOperationLock(instanceId, async () => { entered(); await hold; return 'done' })
    await enteredPromise
    const busy = await connection.query<{ locked: boolean }>('SELECT pg_try_advisory_lock($1, $2) AS locked', [4112, instanceId])
    assert.equal(busy.rows[0]?.locked, false)
    release()
    assert.deepEqual(await operation, { acquired: true, value: 'done' })

    // Different instances with the same domain, including legacy-ID collision
    // domains, cannot mutate Caddy concurrently. Independent domains still can.
    let finishDomain!: () => void
    let startedDomain!: () => void
    const domainEntered = new Promise<void>(resolve => { startedDomain = resolve })
    const domainWait = new Promise<void>(resolve => { finishDomain = resolve })
    const domainOwner = withInstanceAndDomainRemoteOperationLock(instanceId, 'a.b-c.example', async () => {
      startedDomain()
      await domainWait
    })
    await domainEntered
    assert.deepEqual(await withInstanceAndDomainRemoteOperationLock(instanceId + 1, 'a.b-c.example', async () => true), { acquired: false })
    assert.deepEqual(await withInstanceAndDomainRemoteOperationLock(instanceId + 1, 'a-b.c.example', async () => true), { acquired: false })
    assert.deepEqual(await withDomainRemoteOperationLock('A.B-C.EXAMPLE', async () => true), { acquired: false })
    assert.deepEqual(await withInstanceAndDomainRemoteOperationLock(instanceId + 1, 'other.example', async () => true), { acquired: true, value: true })
    finishDomain()
    assert.equal((await domainOwner).acquired, true)
    assert.deepEqual(await withDomainRemoteOperationLock('a-b.c.example', async () => true), { acquired: true, value: true })
    await assert.rejects(withInstanceAndDomainRemoteOperationLock(instanceId, 'a.example', async () => { throw new Error('failed update') }), /failed update/)
    assert.deepEqual(await withDomainRemoteOperationLock('a.example', async () => true), { acquired: true, value: true })
    assert.deepEqual(await withInstanceRemoteOperationLock(instanceId, async () => true), { acquired: true, value: true })
  } finally {
    connection.release()
    await otherPool.end()
  }
})

test('snapshot routes and scheduled snapshots re-read instance state under the lock', async () => {
  const routes = await readFile(new URL('../routes/snapshots.ts', import.meta.url), 'utf8')
  for (const [startMarker, endMarker] of [
    ['  // 创建快照', '  // 删除快照'],
    ['  // 删除快照', '  // 恢复快照'],
    ['  // 恢复快照', '  // 获取自动快照策略']
  ]) {
    const start = routes.indexOf(startMarker)
    const route = routes.slice(start, routes.indexOf(endMarker, start))
    const lock = route.indexOf('withInstanceRemoteOperationLock(instanceIdNum')
    assert.ok(lock >= 0)
    assert.ok(route.indexOf('getInstanceWithPermission(', lock) > lock)
    assert.ok(route.indexOf("instance.status === 'deleted'", lock) > lock)
  }
  const scheduler = await readFile(new URL('./auto-policy-scheduler.ts', import.meta.url), 'utf8')
  const wrapper = scheduler.slice(scheduler.indexOf('async function executeAutoSnapshot(policy:'), scheduler.indexOf(' * 运行自动快照任务'))
  assert.ok(wrapper.indexOf('withInstanceRemoteOperationLock(') < wrapper.indexOf('prisma.instance.findUnique('))
  assert.match(wrapper, /\['running', 'stopped'\]\.includes\(current\.status\)/)
})
