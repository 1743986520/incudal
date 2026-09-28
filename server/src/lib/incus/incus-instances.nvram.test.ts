import assert from 'node:assert/strict'
import test from 'node:test'
import type { IncusClient } from './incus-client.js'
import { isMissingVmNvramError, startInstanceWithNvramRepair } from './incus-instances.js'

test('missing VM NVRAM detection only matches the Incus missing-file failure', () => {
  assert.equal(isMissingVmNvramError(new Error(
    'Failed copying NVRAM file: open /var/lib/incus/virtual-machines/demo/qemu.nvram: no such file or directory'
  )), true)
  assert.equal(isMissingVmNvramError(new Error(
    'Failed opening NVRAM file: open /var/lib/incus/virtual-machines/demo/qemu.nvram: no such file or directory'
  )), true)
  assert.equal(isMissingVmNvramError(new Error('Failed to start VM: permission denied')), false)
})

test('start repairs missing VM NVRAM and retries exactly once', async () => {
  const calls: Array<{ method: string; path: string; body: unknown; timeout: number | undefined }> = []
  let startAttempts = 0
  const client = {
    request: async (method: string, path: string, body: unknown, timeout?: number) => {
      calls.push({ method, path, body, timeout })

      if (method === 'PUT' && path === '/1.0/instances/demo/state') {
        startAttempts++
        if (startAttempts === 1) {
          throw new Error(
            'Failed copying NVRAM file: open /var/lib/incus/virtual-machines/demo/qemu.nvram: no such file or directory'
          )
        }

        return { status: 'Running' }
      }

      if (method === 'POST' && path === '/1.0/instances/demo/debug/repair') return {}
      throw new Error(`Unexpected request: ${method} ${path}`)
    }
  } as unknown as IncusClient

  const result = await startInstanceWithNvramRepair(client, 'demo')

  assert.equal(result.repairedNvram, true)
  assert.deepEqual(result.result, { status: 'Running' })
  assert.equal(startAttempts, 2)
  assert.deepEqual(calls[1], {
    method: 'POST',
    path: '/1.0/instances/demo/debug/repair',
    body: { action: 'rebuild-nvram' },
    timeout: 2 * 60 * 1000
  })
})

test('start does not repair or retry unrelated Incus errors', async () => {
  let attempts = 0
  const client = {
    request: async () => {
      attempts++
      throw new Error('connect ETIMEDOUT')
    }
  } as unknown as IncusClient

  await assert.rejects(() => startInstanceWithNvramRepair(client, 'demo'), /connect ETIMEDOUT/)
  assert.equal(attempts, 1)
})
