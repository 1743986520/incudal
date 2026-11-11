import assert from 'node:assert/strict'
import { test } from 'node:test'
import { CaddyClient } from '../lib/caddy-client.js'
import { getRemoteOperationAbortSignal, runWithRemoteOperationAbortSignal, throwIfRemoteOperationAborted } from './remote-operation-abort.js'

test('lock abort propagates through nested scopes and does not escape them', async () => {
  const outer = new AbortController()
  const inner = new AbortController()
  const reason = new Error('lock lost')
  await runWithRemoteOperationAbortSignal(outer.signal, async () => {
    await runWithRemoteOperationAbortSignal(inner.signal, async () => {
      assert.equal(getRemoteOperationAbortSignal()?.aborted, false)
      outer.abort(reason)
      assert.equal(getRemoteOperationAbortSignal()?.aborted, true)
      assert.throws(throwIfRemoteOperationAborted, /lock lost/)
    })
  })
  assert.equal(getRemoteOperationAbortSignal(), undefined)
  await assert.rejects(runWithRemoteOperationAbortSignal(outer.signal, async () => {}), /lock lost/)
})

test('Caddy does not issue a request after lock abort', async () => {
  const controller = new AbortController()
  const client = new CaddyClient({ host: '127.0.0.1', port: 1, username: 'test', password: 'test' })
  await runWithRemoteOperationAbortSignal(controller.signal, async () => {
    controller.abort(new Error('lock lost'))
    await assert.rejects(client.deleteSite('example.test'), /lock lost/)
  })
})
