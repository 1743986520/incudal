import assert from 'node:assert/strict'
import test from 'node:test'

import { calculateAllocatedHostResources } from './host-resource-usage.js'

test('counts every instance that still owns host resources', () => {
  const usage = calculateAllocatedHostResources([
    { status: 'creating', cpu: 15, memory: 128, disk: 512 },
    { status: 'running', cpu: 20, memory: 256, disk: 1024 },
    { status: 'stopped', cpu: 25, memory: 512, disk: 2048 },
    { status: 'suspended', cpu: 30, memory: 1024, disk: 4096 },
    { status: 'error', cpu: 100, memory: 2048, disk: 8192 },
    { status: 'deleted', cpu: 100, memory: 2048, disk: 8192 }
  ])

  assert.deepEqual(usage, {
    cpuUsed: 90,
    memoryUsed: 1920,
    diskUsed: 7680
  })
})
