import assert from 'node:assert/strict'
import test from 'node:test'

import {
  getIncusExecutionGuard,
  runWithIncusExecutionGuard,
  throwIfIncusExecutionAborted
} from './incus-execution-guard.js'

test('execution guard is scoped to the worker async context', async () => {
  const controller = new AbortController()
  let checks = 0

  await runWithIncusExecutionGuard({
    signal: controller.signal,
    assertActive: async () => { checks++ }
  }, async () => {
    assert.equal(getIncusExecutionGuard()?.signal, controller.signal)
    await getIncusExecutionGuard()?.assertActive()
  })

  assert.equal(checks, 1)
  assert.equal(getIncusExecutionGuard(), undefined)
})

test('aborted execution guard fences later stages', async () => {
  const controller = new AbortController()
  const reason = new Error('lease lost')

  await assert.rejects(
    runWithIncusExecutionGuard({
      signal: controller.signal,
      assertActive: async () => undefined
    }, async () => {
      controller.abort(reason)
      throwIfIncusExecutionAborted()
    }),
    reason
  )
})
