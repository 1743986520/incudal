import assert from 'node:assert/strict'
import test from 'node:test'
import { getTrafficCountersFromState } from './incus-traffic.js'

test('does not mix fallback interfaces with canonical Incus NICs', () => {
    const counters = getTrafficCountersFromState('vm-test', {
        network: {
            eth0: { counters: { bytes_received: '100', bytes_sent: '200' } },
            enp6s0: { counters: { bytes_received: '300', bytes_sent: '400' } },
            docker0: { counters: { bytes_received: '500', bytes_sent: '600' } }
        }
    })

    assert.deepEqual(counters, { rxBytes: 100n, txBytes: 200n })
})
