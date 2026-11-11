import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { test } from 'node:test'
import type { Host } from '../types/database.js'

// These tests inject all external operations; the URL is never connected to.
process.env.DATABASE_URL ||= 'postgresql://test:test@127.0.0.1:1/test'
const { removeTaskProxyRoutes, taskCaddyConfiguration } = await import('./instance-task-proxy-cleanup.js')
const host = { id: 10 } as Host
const site = { id: 3, instanceId: 4, hostId: 10, domain: 'example.test' }

test('route removal requires enabled Caddy, an address and credentials', () => {
  const configured = { ...host, caddy_enabled: true, ip_address: '10.0.0.1', caddy_username: 'test', caddy_password: 'test' }
  assert.equal(taskCaddyConfiguration(configured).host, '10.0.0.1')
  for (const changed of [
    { caddy_enabled: false }, { ip_address: null }, { caddy_username: null }, { caddy_password: null }
  ]) assert.throws(() => taskCaddyConfiguration({ ...configured, ...changed }), /cannot be confirmed/)
})

test('task cleanup verifies each site under its domain lock before removing its route', async () => {
  const operations: string[] = []
  await removeTaskProxyRoutes(4, host, {
    listSites: async () => [site],
    getSite: async () => { operations.push('read'); return site },
    withDomainLock: async (domain, operation) => { operations.push(`lock:${domain}`); await operation(); operations.push('unlock'); return { acquired: true } },
    deleteSite: async (_, domain) => { operations.push(`delete:${domain}`) }
  })
  assert.deepEqual(operations, ['lock:example.test', 'read', 'delete:example.test', 'unlock'])
})

test('task cleanup fails closed for changed identity, a busy domain, or an uncertain Caddy delete', async () => {
  for (const changed of [null, { ...site, instanceId: 5 }, { ...site, hostId: 11 }, { ...site, domain: 'other.test' }]) {
    let deleted = false
    await assert.rejects(removeTaskProxyRoutes(4, host, {
      listSites: async () => [site], getSite: async () => changed,
      withDomainLock: async (_, operation) => { await operation(); return { acquired: true } },
      deleteSite: async () => { deleted = true }
    }), /identity changed/)
    assert.equal(deleted, false)
  }
  await assert.rejects(removeTaskProxyRoutes(4, host, {
    listSites: async () => [site], getSite: async () => site,
    withDomainLock: async () => ({ acquired: false }), deleteSite: async () => {}
  }), /operation is in progress/)
  await assert.rejects(removeTaskProxyRoutes(4, host, {
    listSites: async () => [site], getSite: async () => site,
    withDomainLock: async (_, operation) => { await operation(); return { acquired: true } },
    deleteSite: async () => { throw new Error('unconfirmed') }
  }), /unconfirmed/)
})

test('recreate and change-host hold the instance lock through route removal and database cleanup', async () => {
  const worker = await readFile(new URL('../workers/instanceTaskWorker.ts', import.meta.url), 'utf8')
  for (const name of ['recreateProxyCleanup', 'changeHostProxyCleanup']) {
    const start = worker.indexOf(`const ${name} = await withInstanceRemoteOperationLock`)
    const end = worker.indexOf(`if (!${name}.acquired)`, start)
    assert.ok(start >= 0 && end > start)
    const body = worker.slice(start, end)
    assert.ok(body.indexOf('await removeTaskProxyRoutes(') >= 0)
    assert.ok(body.indexOf('proxySite.deleteMany(') > body.indexOf('await removeTaskProxyRoutes('))
  }
})

test('all six proxy mutations check active tasks while holding the remote-operation lock', async () => {
  const routes = await readFile(new URL('../routes/proxy-sites.ts', import.meta.url), 'utf8')
  const sections = routes.split('const locked = await withInstanceAndDomainRemoteOperationLock(').slice(1)
  assert.equal(sections.length, 6)
  for (const section of sections) {
    assert.ok(section.indexOf('getActiveTaskForInstance(instanceId)') >= 0)
    assert.ok(section.indexOf('getActiveTaskForInstance(instanceId)') < section.indexOf('if (!locked.acquired)'))
  }
})
