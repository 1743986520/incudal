import assert from 'node:assert/strict'
import test from 'node:test'
import { getTrafficCountersFromState } from './incus-traffic.js'

test('counts all external NICs when Incus mixes device and guest interface names', () => {
    const counters = getTrafficCountersFromState('vm-test', {
        network: {
            eth0: { counters: { bytes_received: '100', bytes_sent: '200' } },
            enp6s0: { counters: { bytes_received: '300', bytes_sent: '400' } },
            docker0: { counters: { bytes_received: '500', bytes_sent: '600' } }
        }
    })

    assert.deepEqual(counters, { rxBytes: 400n, txBytes: 600n })
})
