import assert from 'node:assert/strict'
import { test } from 'node:test'
import { CaddyApiError, CaddyClient } from './caddy-client.js'

type RequestCall = { method: string; path: string }
function fakeClient(legacyRoute: unknown, legacyError?: Error) {
  const calls: RequestCall[] = []
  const client = Object.create(CaddyClient.prototype) as CaddyClient
  ;(client as unknown as { request: (method: string, path: string) => Promise<unknown> }).request = async (method, path) => {
    calls.push({ method, path })
    if (calls.length === 1) throw new CaddyApiError(404, 'not found')
    if (method === 'GET' && legacyError) throw legacyError
    if (method === 'GET') return legacyRoute
    return {}
  }
  return { client, calls }
}

test('legacy Caddy route may be removed only when its host match proves ownership', async () => {
  const domain = 'a.b-c.example'
  for (const badRoute of [
    { match: [{ host: ['a-b.c.example'] }] },
    { match: [{ host: [domain, 'a-b.c.example'] }] },
    { match: [{ host: ['*.example'] }] },
    { match: [{}] }, {}, null
  ]) {
    const { client, calls } = fakeClient(badRoute)
    await assert.rejects(client.deleteSite(domain), /Cannot verify legacy Caddy route ownership/)
    assert.equal(calls.length, 2)
    assert.equal(calls[1]?.method, 'GET')
    assert.equal(calls[1]?.path, '/id/site-a-b-c-example')
  }
  const { client, calls } = fakeClient({ match: [{ host: [domain.toUpperCase()], protocol: 'http' }] })
  await client.deleteSite(domain)
  assert.equal(calls[2]?.method, 'DELETE')
  assert.equal(calls[2]?.path, '/id/site-a-b-c-example')
})

test('absence is idempotent but text containing 404 and unrelated failures are not', async () => {
  const absent = fakeClient(null, new CaddyApiError(404, 'not found'))
  await absent.client.deleteSite('a.example')
  assert.equal(absent.calls.length, 2)
  for (const error of [new Error('404 not found'), new CaddyApiError(503, 'upstream 404')]) {
    const probe = fakeClient(null, error)
    await assert.rejects(probe.client.deleteSite('a.example'))
    assert.equal(probe.calls.length, 2)
  }
})


test('modern route removal still verifies and cleans a coexisting legacy route', async () => {
  const client = Object.create(CaddyClient.prototype) as CaddyClient
  const calls: RequestCall[] = []
  ;(client as unknown as { request: (method: string, path: string) => Promise<unknown> }).request = async (method, path) => {
    calls.push({ method, path })
    if (method === 'GET') return { match: [{ host: ['a.example'] }] }
    return {}
  }
  await client.deleteSite('a.example')
  assert.deepEqual(calls.map(call => call.method), ['DELETE', 'GET', 'DELETE'])
  assert.equal(calls[2]?.path, '/id/site-a-example')
})
