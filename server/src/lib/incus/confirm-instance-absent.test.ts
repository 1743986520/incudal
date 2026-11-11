import assert from 'node:assert/strict'
import { test } from 'node:test'
import { IncusApiError, type IncusClient } from './incus-client.js'
import { confirmInstanceAbsent } from './confirm-instance-absent.js'

const path = '/1.0/instances/example'
const apiError = (statusCode: number, method = 'GET', requestPath = path) =>
  new IncusApiError('not found', { statusCode, method, path: requestPath })

function clientReturning(result: unknown, fails = false) {
  let calls = 0
  const client = { request: async (method: string, requestPath: string) => {
    calls++
    assert.equal(method, 'GET')
    assert.equal(requestPath, path)
    if (fails) throw result
    return result
  } } as unknown as Pick<IncusClient, 'request'>
  return { client, get calls() { return calls } }
}

test('only an exact, independently verified instance GET 404 proves absence', async () => {
  for (const initial of [apiError(404), apiError(404, 'GET', `${path}/state`)]) {
    const probe = clientReturning(apiError(404), true)
    assert.equal(await confirmInstanceAbsent(probe.client, 'example', initial), true)
    assert.equal(probe.calls, 1)
  }
  for (const initial of [new Error('instance not found'), apiError(503), apiError(404, 'POST'), apiError(404, 'GET', '/1.0/operations/example')]) {
    const probe = clientReturning(apiError(404), true)
    assert.equal(await confirmInstanceAbsent(probe.client, 'example', initial), false)
    assert.equal(probe.calls, 0)
  }
  for (const [result, fails] of [[{}, false], [apiError(503), true], [new Error('not found'), true], [apiError(404, 'GET', `${path}/state`), true]] as const) {
    const probe = clientReturning(result, fails)
    assert.equal(await confirmInstanceAbsent(probe.client, 'example', apiError(404, 'GET', `${path}/state`)), false)
    assert.equal(probe.calls, 1)
  }
})
