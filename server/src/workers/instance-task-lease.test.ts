import assert from 'node:assert/strict'
import test from 'node:test'

import {
  canRecoverInstanceTask,
  hasActiveInstanceTaskLease,
  finishInstanceTaskExecution,
  renewInstanceTaskLease,
  updateInstanceTaskExecutionData,
  updateInstanceTaskExecutionProgress
} from './instance-task-lease.js'

test('an active execution lease cannot be recovered even after fifteen minutes or with force', () => {
  const now = new Date('2026-09-08T12:30:00.000Z')
  const task = {
    status: 'PROCESSING' as const,
    createdAt: new Date('2026-09-08T12:00:00.000Z'),
    startedAt: new Date('2026-09-08T12:00:00.000Z'),
    leaseExpiresAt: new Date('2026-09-08T12:31:00.000Z')
  }

  assert.equal(canRecoverInstanceTask(task, now, false), false)
  assert.equal(canRecoverInstanceTask(task, now, true), false)
})

test('an expired execution lease remains quarantined without explicit admin confirmation', () => {
  const now = new Date('2026-09-08T12:30:00.000Z')
  const task = {
    status: 'PROCESSING' as const,
    createdAt: new Date('2026-09-08T12:00:00.000Z'),
    startedAt: new Date('2026-09-08T12:00:00.000Z'),
    leaseExpiresAt: new Date('2026-09-08T12:29:59.000Z')
  }
  assert.equal(canRecoverInstanceTask(task, now, false), false)
  assert.equal(canRecoverInstanceTask(task, now, true), true)
})

test('a processing task without a lease remains quarantined for non-admin recovery', () => {
  const now = new Date('2026-09-08T12:30:00.000Z')
  const task = {
    status: 'PROCESSING' as const,
    createdAt: new Date('2026-09-08T12:00:00.000Z'),
    startedAt: new Date('2026-09-08T12:00:00.000Z'),
    leaseExpiresAt: null
  }
  assert.equal(canRecoverInstanceTask(task, now, false), false)
  assert.equal(canRecoverInstanceTask(task, now, true), true)
})

test('a pending task still observes the fifteen minute recovery window', () => {
  const now = new Date('2026-09-08T12:30:00.000Z')
  const recent = {
    status: 'PENDING' as const,
    createdAt: new Date('2026-09-08T12:20:00.000Z'),
    startedAt: null,
    leaseExpiresAt: null
  }
  assert.equal(canRecoverInstanceTask(recent, now, false), false)
  assert.equal(canRecoverInstanceTask(recent, now, true), true)
})

test('active lease check uses the same token and unexpired lease fence', async () => {
  let where: unknown
  const client = {
    instanceTask: {
      count: async (args: { where: unknown }) => {
        where = args.where
        return 1
      }
    }
  }
  const now = new Date('2026-09-08T12:30:00.000Z')
  assert.equal(await hasActiveInstanceTaskLease(client, 9, 'owned-token', now), true)
  assert.deepEqual(where, {
    id: 9,
    status: 'PROCESSING',
    executionToken: 'owned-token',
    leaseExpiresAt: { gt: now }
  })
})

test('completion uses status and execution token CAS', async () => {
  let where: unknown
  const client = {
    instanceTask: {
      updateMany: async (args: { where: unknown }) => {
        where = args.where
        return { count: 0 }
      }
    }
  }

  const now = new Date('2026-09-08T12:30:00.000Z')
  const updated = await finishInstanceTaskExecution(client, 42, 'new-token', 'COMPLETED', {
    finishedAt: now
  }, now)

  assert.equal(updated, false)
  assert.deepEqual(where, {
    id: 42,
    status: 'PROCESSING',
    executionToken: 'new-token',
    leaseExpiresAt: { gt: now }
  })
})

test('heartbeat and progress updates cannot mutate a recovered generation', async () => {
  const calls: Array<{ where: unknown; data: unknown }> = []
  const client = {
    instanceTask: {
      updateMany: async (args: { where: unknown; data: unknown }) => {
        calls.push(args)
        return { count: 0 }
      }
    }
  }

  const now = new Date('2026-09-08T12:32:00.000Z')
  assert.equal(await renewInstanceTaskLease(client, 7, 'old-token', now), false)
  assert.equal(await updateInstanceTaskExecutionProgress(client, 7, 'old-token', 'rebuilding', now), false)
  assert.equal(await updateInstanceTaskExecutionData(client, 7, 'old-token', { newInstanceId: 99 }, now), false)
  assert.deepEqual(calls.map(call => call.where), [
    { id: 7, status: 'PROCESSING', executionToken: 'old-token', leaseExpiresAt: { gt: now } },
    { id: 7, status: 'PROCESSING', executionToken: 'old-token', leaseExpiresAt: { gt: now } },
    { id: 7, status: 'PROCESSING', executionToken: 'old-token', leaseExpiresAt: { gt: now } }
  ])
})
