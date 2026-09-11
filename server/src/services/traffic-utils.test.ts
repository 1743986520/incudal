import assert from 'node:assert/strict'
import test from 'node:test'
import { calculateIncrement, isTransientEmptyCounterSample } from './traffic-utils.js'

test('calculateIncrement uses the normal monotonic delta', () => {
    assert.equal(calculateIncrement(150n, 100n), 50n)
})

test('calculateIncrement starts a new baseline without billing the reset value', () => {
    assert.equal(calculateIncrement(25n, 100n), 0n)
})

test('calculateIncrement does not create traffic for unchanged counters', () => {
    assert.equal(calculateIncrement(100n, 100n), 0n)
})

test('detects an empty sample after a valid traffic baseline', () => {
    assert.equal(isTransientEmptyCounterSample(0n, 0n, 100n, 200n), true)
    assert.equal(isTransientEmptyCounterSample(0n, 0n, 0n, 0n), false)
    assert.equal(isTransientEmptyCounterSample(1n, 0n, 100n, 200n), false)
})
