import assert from 'node:assert/strict'
import { test } from 'node:test'
import { reloadOnceForChunkError } from '../src/utils/chunkReload.js'

test('stale chunk reload is bounded within the cooldown', () => {
  const originalStorage = globalThis.sessionStorage
  const originalWindow = globalThis.window
  const originalNow = Date.now
  const values = new Map<string, string>()
  let reloads = 0
  let now = 1_000_000

  Object.defineProperty(globalThis, 'sessionStorage', {
    configurable: true,
    value: {
      getItem: (key: string) => values.get(key) ?? null,
      setItem: (key: string, value: string) => { values.set(key, value) }
    }
  })
  Object.defineProperty(globalThis, 'window', {
    configurable: true,
    value: { location: { reload: () => { reloads++ } } }
  })
  Date.now = () => now

  try {
    reloadOnceForChunkError()
    reloadOnceForChunkError()
    assert.equal(reloads, 1)

    now += 60_000
    reloadOnceForChunkError()
    assert.equal(reloads, 2)
  } finally {
    Date.now = originalNow
    Object.defineProperty(globalThis, 'sessionStorage', { configurable: true, value: originalStorage })
    Object.defineProperty(globalThis, 'window', { configurable: true, value: originalWindow })
  }
})
