import assert from 'node:assert/strict'
import test from 'node:test'

import {
  assertCurrentInstanceOwner,
  executeTransferTransaction,
  rollbackProcessingTransfer
} from '../src/db/transfer-safety.js'

const execution = {
  transferId: 3,
  instanceId: 41,
  fromUserId: 7,
  toUserId: 9,
  newInstanceName: 'moved',
  newIncusId: 'u9-new',
  oldIncusId: 'u7-old',
  instanceVersion: 4,
  claimToken: 'claim-3'
}

const lock = { $queryRaw: async () => [{ locked: true }] }

test('creation revalidates the current instance owner inside the transaction', async () => {
  const calls: unknown[] = []
  const tx = { instance: { findFirst: async (args: unknown) => { calls.push(args); return null } } }
  await assert.rejects(assertCurrentInstanceOwner(tx as never, 41, 7), /TRANSFER_INSTANCE_OWNER_CHANGED/)
  assert.deepEqual(calls, [{ where: { id: 41, userId: 7 }, select: { id: true } }])
})

test('execution rejects a transfer unless processing and all identity fields match', async () => {
  let instanceUpdated = false
  const tx = {
    ...lock,
    instanceTransfer: { findFirst: async () => null },
    instance: { updateMany: async () => { instanceUpdated = true; return { count: 1 } } },
    instanceBillingRecord: { create: async () => ({ id: 1 }) }
  }
  await assert.rejects(executeTransferTransaction(tx as never, execution), /TRANSFER_EXECUTION_CONFLICT/)
  assert.equal(instanceUpdated, false)
})

test('execution conditionally changes only an instance still owned by the sender', async () => {
  const calls: unknown[] = []
  const tx = {
    ...lock,
    instanceTransfer: {
      findFirst: async (args: unknown) => { calls.push(['findTransfer', args]); return { id: 3, fee: null, fromUserId: 7 } },
      updateMany: async (args: unknown) => { calls.push(['acceptTransfer', args]); return { count: 1 } }
    },
    instance: { updateMany: async (args: unknown) => { calls.push(['updateInstance', args]); return { count: 1 } } },
    instanceBillingRecord: { create: async () => ({ id: 1 }) }
  }
  await executeTransferTransaction(tx as never, execution)
  assert.deepEqual(calls[0], ['findTransfer', {
    where: { id: 3, status: 'processing', claimToken: 'claim-3', instanceId: 41, fromUserId: 7, toUserId: 9, oldIncusId: 'u7-old', newIncusId: 'u9-new', instanceVersion: 4 },
    select: { id: true, fee: true, fromUserId: true }
  }])
  assert.deepEqual(calls[1], ['updateInstance', {
    where: { id: 41, userId: 7, incusId: 'u7-old', version: 4 },
    data: { userId: 9, name: 'moved', incusId: 'u9-new', displayOrder: 0, version: { increment: 1 } }
  }])
  assert.equal((calls[2] as unknown[])[0], 'acceptTransfer')
})

test('execution aborts when the conditional owner update loses the race', async () => {
  const tx = {
    ...lock,
    instanceTransfer: { findFirst: async () => ({ id: 3, fee: null, fromUserId: 7 }), updateMany: async () => ({ count: 1 }) },
    instance: { updateMany: async () => ({ count: 0 }) },
    instanceBillingRecord: { create: async () => ({ id: 1 }) }
  }
  await assert.rejects(executeTransferTransaction(tx as never, execution), /TRANSFER_INSTANCE_OWNER_CHANGED/)
})

test('transfer fee billing is keyed by transfer id', async () => {
  let billingArgs: unknown
  const tx = {
    ...lock,
    instanceTransfer: { findFirst: async () => ({ id: 3, fee: { greaterThan: () => true }, fromUserId: 7 }), updateMany: async () => ({ count: 1 }) },
    instance: { updateMany: async () => ({ count: 1 }) },
    instanceBillingRecord: { create: async (args: unknown) => { billingArgs = args; return { id: 1 } } }
  }
  await executeTransferTransaction(tx as never, execution)
  assert.equal((billingArgs as { data: { transferId: number } }).data.transferId, 3)
})

test('failure rollback changes only the matching processing claim back to pending', async () => {
  let args: unknown
  const client = { instanceTransfer: { updateMany: async (value: unknown) => { args = value; return { count: 0 } } } }
  const changed = await rollbackProcessingTransfer(client as never, 3, 'claim-3')
  assert.equal(changed, false)
  assert.deepEqual(args, {
    where: { id: 3, status: 'processing', claimToken: 'claim-3' },
    data: {
      status: 'pending', claimToken: null, claimExpiresAt: null, phase: null,
      oldIncusId: null, newIncusId: null, instanceVersion: null,
      cleanupSnapshot: undefined
    }
  })
})
