import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { Decimal } from '@prisma/client/runtime/client'

import {
  claimTransferTransaction,
  debitTransferFee,
  executeTransferTransaction,
  rollbackProcessingTransfer,
  settleTransferWithRefund,
  shouldSuppressMissingIncusDeletion
} from '../src/db/transfer-safety.js'

test('transfer routes wire claims and atomic refund settlement into every transition', () => {
  const source = readFileSync(new URL('../src/routes/transfers.ts', import.meta.url), 'utf8')
  const accept = source.slice(source.indexOf("('/:id/accept'"), source.indexOf("('/:id/reject'"))
  const reject = source.slice(source.indexOf("('/:id/reject'"), source.indexOf("('/:id/cancel'"))
  const cancel = source.slice(source.indexOf("('/:id/cancel'"), source.indexOf("('/:id/push'"))
  const push = source.slice(source.indexOf("('/:id/push'"))

  for (const route of [accept, push]) {
    assert.match(route, /claimTransferTransaction\(tx,/)
    assert.match(route, /claimToken:\s*token/)
    assert.match(route, /leaseUntil:/)
    assert.match(route, /const oldIncusId = claim\.oldIncusId/)
    assert.match(route, /const instanceVersion = claim\.instanceVersion/)
    assert.doesNotMatch(route, /data:\s*\{\s*status:\s*'processing'/)
    assert.match(route, /rollbackProcessingTransfer\(prisma, transferId, token\)/)
  }
  for (const route of [reject, cancel]) {
    assert.match(route, /settleTransferWithRefund\(tx,/)
    assert.doesNotMatch(route, /refundTransferFee/)
  }
})

test('claim takes the unified instance lock, rejects active tasks, freezes cleanup ids and persists an opaque lease', async () => {
  const calls: any[] = []
  const tx: any = {
    $queryRaw: async () => [{ locked: true }],
    instanceTask: { count: async (a: any) => (calls.push(['tasks', a]), 0) },
    instance: { findFirst: async (a: any) => (calls.push(['instance', a]), { id: 41, incusId: 'old', version: 7 }) },
    proxySite: { findMany: async () => [{ id: 1 }] },
    portMapping: { findMany: async () => [{ id: 2 }] },
    snapshot: { findMany: async () => [{ id: 3 }] },
    backup: { findMany: async () => [{ id: 4 }] },
    snapshotPolicy: { findMany: async () => [{ id: 5 }] },
    backupPolicy: { findMany: async () => [{ id: 6 }] },
    instanceTransfer: { updateMany: async (a: any) => (calls.push(['claim', a]), { count: 1 }) }
  }
  const claim = await claimTransferTransaction(tx, { transferId: 9, instanceId: 41, actorUserId: 8, actorRole: 'receiver', claimToken: 'fresh-token', newIncusId: 'new', leaseUntil: new Date('2030-01-01') })
  assert.equal(claim.oldIncusId, 'old')
  assert.equal(claim.instanceVersion, 7)
  const update = calls.find(c => c[0] === 'claim')[1]
  assert.equal(update.where.status, 'pending')
  assert.equal(update.data.claimToken, 'fresh-token')
  assert.equal(update.data.phase, 'claimed')
  assert.deepEqual(update.data.cleanupSnapshot, { proxySiteIds: [1], portMappingIds: [2], snapshotIds: [3], backupIds: [4], snapshotPolicyIds: [5], backupPolicyIds: [6] })
})

test('fee debit stays Decimal and uses atomic decrement after user serialization', async () => {
  const calls: any[] = []
  const tx: any = {
    $queryRaw: async () => [{ locked: true }],
    user: {
      findUnique: async () => ({ balance: new Decimal('10.00') }),
      update: async (a: any) => calls.push(a)
    },
    balanceLog: { create: async (a: any) => calls.push(a) }
  }
  await debitTransferFee(tx, { transferId: 9, userId: 7, instanceId: 41, instanceName: 'i', fee: new Decimal('2.50') })
  assert.deepEqual(calls[0].data, { balance: { decrement: new Decimal('2.50') } })
  assert.equal(calls[1].data.balanceBefore.toString(), '10')
  assert.equal(calls[1].data.balanceAfter.toString(), '7.5')
  assert.equal(calls[1].data.transferId, 9)
})

test('reject transition and idempotent refund are one token-free transaction operation', async () => {
  const calls: any[] = []
  const tx: any = {
    $queryRaw: async () => [{ locked: true }],
    instanceTransfer: {
      findFirst: async () => ({ id: 9, fromUserId: 7, instanceId: 41, fee: new Decimal('2.50'), refundedAt: null, instance: { name: 'i' } }),
      updateMany: async (a: any) => (calls.push(['transfer', a]), { count: 1 })
    },
    user: { findUnique: async () => ({ balance: new Decimal('7.50') }), update: async (a: any) => calls.push(['user', a]) },
    balanceLog: { create: async (a: any) => calls.push(['log', a]) }
  }
  const changed = await settleTransferWithRefund(tx, { transferId: 9, actorUserId: 8, outcome: 'rejected', reason: 'no' })
  assert.equal(changed, true)
  assert.deepEqual(calls.find(c => c[0] === 'user')[1].data, { balance: { increment: new Decimal('2.50') } })
  assert.equal(calls.find(c => c[0] === 'log')[1].data.transferId, 9)
  assert.ok(calls.find(c => c[0] === 'transfer')[1].data.refundedAt instanceof Date)
})

test('execute and rollback require the current non-reusable claim token and old generation', async () => {
  const seen: any[] = []
  const tx: any = {
    $queryRaw: async () => [{ locked: true }],
    instanceTransfer: { findFirst: async (a: any) => (seen.push(a), null), updateMany: async () => ({ count: 0 }) },
    instance: { updateMany: async () => ({ count: 0 }) },
    instanceBillingRecord: { create: async () => ({}) }
  }
  await assert.rejects(executeTransferTransaction(tx, { transferId: 9, instanceId: 41, fromUserId: 7, toUserId: 8, newInstanceName: 'n', newIncusId: 'new', oldIncusId: 'old', instanceVersion: 7, claimToken: 'old-token' }), /TRANSFER_EXECUTION_CONFLICT/)
  assert.equal(seen[0].where.claimToken, 'old-token')
  const changed = await rollbackProcessingTransfer(tx, 9, 'old-token')
  assert.equal(changed, false)
})

test('status sync suppresses deleted during an active rename lease', () => {
  assert.equal(shouldSuppressMissingIncusDeletion({ status: 'processing', claimToken: 't', phase: 'renaming', claimExpiresAt: new Date(Date.now() + 60_000) }), true)
  assert.equal(shouldSuppressMissingIncusDeletion(null), false)
})
