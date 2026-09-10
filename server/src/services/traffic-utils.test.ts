import assert from 'node:assert/strict'
import test from 'node:test'
import { calculateIncrement } from './traffic-utils.js'

test('calculateIncrement uses the normal monotonic delta', () => {
    assert.equal(calculateIncrement(150n, 100n), 50n)
})

test('calculateIncrement bills bytes accumulated after a counter reset', () => {
    assert.equal(calculateIncrement(25n, 100n), 25n)
})

test('calculateIncrement does not create traffic for unchanged counters', () => {
    assert.equal(calculateIncrement(100n, 100n), 0n)
})
