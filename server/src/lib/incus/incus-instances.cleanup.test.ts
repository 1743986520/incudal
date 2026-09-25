import assert from 'node:assert/strict'
import test from 'node:test'
import { IncusApiError, type IncusClient } from './incus-client.js'
import { ensureInstanceDeleted, waitForProvisioningInstanceResolution } from './incus-instances.js'

function fakeClient(handler: (method: string, path: string) => Promise<unknown>): IncusClient {
  return { request: handler } as unknown as IncusClient
}

test('ensureInstanceDeleted confirms a successful deletion with 404', async () => {
  const calls: string[] = []
  let deleted = false

  const client = fakeClient(async (method, path) => {
    calls.push(`${method} ${path}`)

    if (method === 'DELETE' && path === '/1.0/instances/demo') {
      deleted = true
      return {}
    }
    if (method === 'GET' && path === '/1.0/instances/demo') {
      if (deleted) {
        throw new IncusApiError('Instance not found', { statusCode: 404, method, path })
      }
      return { name: 'demo' }
    }
    if (path === '/1.0/instances/demo/state') return { status: 'Stopped' }

    throw new Error(`Unexpected request: ${method} ${path}`)
  })

  await ensureInstanceDeleted(client, 'demo')

  assert.deepEqual(calls, [
    'GET /1.0/instances/demo',
    'GET /1.0/instances/demo/state',
    'DELETE /1.0/instances/demo',
    'GET /1.0/instances/demo'
  ])
})

test('ensureInstanceDeleted keeps unknown Incus errors as failures', async () => {
  const client = fakeClient(async () => {
    throw new Error('connect ETIMEDOUT')
  })

  await assert.rejects(
    () => ensureInstanceDeleted(client, 'demo'),
    /connect ETIMEDOUT/
  )
})

test('waitForProvisioningInstanceResolution treats a running instance as a successful provision', async () => {
  const client = fakeClient(async (method, path) => {
    assert.equal(method, 'GET')
    assert.equal(path, '/1.0/instances/demo')
    return { name: 'demo', status: 'Running' }
  })

  await assert.deepEqual(
    await waitForProvisioningInstanceResolution(client, 'demo'),
    { kind: 'present', status: 'running' }
  )
})

test('waitForProvisioningInstanceResolution only accepts absence after active operations are gone', async () => {
  let operationActive = true
  const client = fakeClient(async (method, path) => {
    if (path === '/1.0/instances/demo') {
      throw new IncusApiError('Instance not found', { statusCode: 404, method, path })
    }
    if (path === '/1.0/operations?recursion=1') {
      const operations = operationActive
        ? [{ id: '/1.0/operations/1', status: 'Running', status_code: 103, resources: { instances: ['/1.0/instances/demo'] } }]
        : []
      operationActive = false
      return operations
    }
    throw new Error(`Unexpected request: ${method} ${path}`)
  })

  await assert.deepEqual(
    await waitForProvisioningInstanceResolution(client, 'demo'),
    { kind: 'absent' }
  )
})
