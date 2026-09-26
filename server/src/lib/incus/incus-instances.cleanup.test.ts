import assert from 'node:assert/strict'
import test from 'node:test'
import { IncusApiError, type IncusClient } from './incus-client.js'
import { createInstance, ensureInstanceDeleted, waitForCreatedInstance, waitForProvisioningInstanceResolution } from './incus-instances.js'

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

test('create waits long enough for remote image pulls and VM creation', async () => {
  const client = { request: async (method: string, path: string, body: unknown, timeout: number) => {
    assert.equal(method, 'POST')
    assert.equal(path, '/1.0/instances')
    assert.deepEqual(body, { name: 'demo' })
    assert.equal(timeout, 15 * 60 * 1000)
    return {}
  } } as unknown as IncusClient
  await createInstance(client, { name: 'demo' })
})

test('create retry waits for the new instance to appear before start', async () => {
  let checks = 0
  const client = fakeClient(async (method, path) => {
    assert.equal(method, 'GET')
    assert.equal(path, '/1.0/instances/demo')
    if (++checks < 3) throw new IncusApiError('Instance not found', { statusCode: 404, method, path })
    return { name: 'demo', status: 'Stopped' }
  })
  assert.equal(await waitForCreatedInstance(client, 'demo', 100, 1), 'Stopped')
  assert.equal(checks, 3)
})

test('create retry waits through a transitional instance state', async () => {
  let checks = 0
  const client = fakeClient(async () => ({ name: 'demo', status: ++checks === 1 ? 'Creating' : 'Running' }))
  assert.equal(await waitForCreatedInstance(client, 'demo', 100, 1), 'Running')
  assert.equal(checks, 2)
})

test('create retry reports a still missing instance and does not start it', async () => {
  const client = fakeClient(async (method, path) => {
    throw new IncusApiError('Instance not found', { statusCode: 404, method, path })
  })
  await assert.rejects(() => waitForCreatedInstance(client, 'demo', 0), /was not found after creation/)
})

test('create retry does not treat an Incus error as a missing instance', async () => {
  const client = fakeClient(async () => {
    throw new IncusApiError('Storage pool is unavailable', {
      statusCode: 503, method: 'GET', path: '/1.0/instances/demo'
    })
  })
  await assert.rejects(() => waitForCreatedInstance(client, 'demo', 100, 1), /Storage pool is unavailable/)
})
