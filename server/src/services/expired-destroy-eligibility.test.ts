import assert from 'node:assert/strict'
import { test } from 'node:test'
import { Prisma } from '@prisma/client'
import { canFinalizeExpiredUserDestroy } from './expired-destroy-eligibility.js'

test('only the already-expired fixed-plan exemption can skip final traffic review', () => {
  const base = { deletionBillingMode: 'user_destroy', deletionBillingPending: true, deletionOriginalStatus: 'suspended',
    deletionRequestedAt: new Date('2026-01-02T00:00:00Z'), deletionRequestedById: 7, deletionRefundableValue: new Prisma.Decimal(0),
    userId: 7, suspendReason: 'expired', expiresAt: new Date('2026-01-01T00:00:00Z'), packagePlanId: 1,
    billingMode: 'package', trafficBillingMode: 'package' }
  assert.equal(canFinalizeExpiredUserDestroy(base), true)
  for (const changed of [
    { deletionBillingMode: 'privileged_delete' }, { deletionBillingPending: false }, { deletionOriginalStatus: 'running' },
    { deletionRequestedAt: null }, { deletionRequestedById: 8 }, { deletionRefundableValue: null },
    { deletionRefundableValue: new Prisma.Decimal('0.01') }, { suspendReason: 'manual' }, { expiresAt: null },
    { expiresAt: new Date('2026-01-03T00:00:00Z') }, { packagePlanId: null }, { billingMode: 'hourly' },
    { trafficBillingMode: 'usage' }
  ]) assert.equal(canFinalizeExpiredUserDestroy({ ...base, ...changed }), false, JSON.stringify(changed))
})
