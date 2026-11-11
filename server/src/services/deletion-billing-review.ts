import { prisma } from '../db/prisma.js'
import { DELETION_BILLING_REVIEW_ACTION } from '../db/logs.js'
import { advisoryTransactionLock, INSTANCE_OPERATION_LOCK_NAMESPACE } from '../db/advisory-locks.js'

export type BillingReviewCategory = 'hourly' | 'usage' | 'user_destroy'
export interface BillingReviewInput {
  requestId: string
  category: BillingReviewCategory
  evidenceReference: string
  note: string
  expected: { instanceVersion: number; hostId: number; incusId: string; requestedAt: string }
}
export class BillingReviewError extends Error {
  constructor(readonly code: string) { super(code) }
}

/** Records an operator's evidence reference, not a billing decision. In
 * particular, this never stops an instance, debits, refunds, or releases it. */
export async function recordDeletionBillingReview(instanceId: number, actorId: number, input: BillingReviewInput): Promise<'recorded' | 'already_recorded'> {
  if (!input || typeof input !== 'object' || typeof input.requestId !== 'string'
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(input.requestId)
    || !['hourly', 'usage', 'user_destroy'].includes(input.category)
    || typeof input.evidenceReference !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:/-]{7,127}$/.test(input.evidenceReference)
    || typeof input.note !== 'string' || input.note !== input.note.trim() || input.note.length < 12 || input.note.length > 500
    || !input.expected || !Number.isSafeInteger(input.expected.instanceVersion) || input.expected.instanceVersion < 0
    || !Number.isSafeInteger(input.expected.hostId) || input.expected.hostId <= 0
    || typeof input.expected.incusId !== 'string' || input.expected.incusId.length < 1 || input.expected.incusId.length > 255
    || typeof input.expected.requestedAt !== 'string' || !Number.isFinite(Date.parse(input.expected.requestedAt))) {
    throw new BillingReviewError('INVALID_REVIEW_INPUT')
  }
  const payload = { instanceId, actorId, requestId: input.requestId.toLowerCase(), category: input.category,
    evidenceReference: input.evidenceReference, note: input.note,
    expected: { instanceVersion: input.expected.instanceVersion, hostId: input.expected.hostId, incusId: input.expected.incusId, requestedAt: input.expected.requestedAt } }
  return prisma.$transaction(async tx => {
    await advisoryTransactionLock(tx, INSTANCE_OPERATION_LOCK_NAMESPACE, instanceId)
    const actors = await tx.$queryRaw<Array<{ role: string; status: string }>>`SELECT "role", "status" FROM "users" WHERE "id" = ${actorId} FOR UPDATE`
    if (actors[0]?.role !== 'admin' || actors[0]?.status !== 'active') throw new BillingReviewError('FORBIDDEN')
    const prior = await tx.log.findFirst({ where: { instanceId, action: DELETION_BILLING_REVIEW_ACTION, content: { contains: `"requestId":"${payload.requestId}"` } } })
    if (prior) {
      if (prior.userId !== actorId || prior.content !== JSON.stringify(payload)) throw new BillingReviewError('REVIEW_REQUEST_CONFLICT')
      return 'already_recorded'
    }
    const current = await tx.instance.findUnique({ where: { id: instanceId }, select: { status: true, version: true, hostId: true, incusId: true,
      deletionRequestedAt: true, billingMode: true, trafficBillingMode: true, deletionBillingMode: true } })
    if (!current) throw new BillingReviewError('INSTANCE_NOT_FOUND')
    if (current.status !== 'deleting' || current.version !== input.expected.instanceVersion || current.hostId !== input.expected.hostId
      || current.incusId !== input.expected.incusId || !current.deletionRequestedAt || current.deletionRequestedAt.toISOString() !== input.expected.requestedAt) throw new BillingReviewError('REVIEW_SNAPSHOT_STALE')
    const relevant = input.category === 'hourly' ? current.billingMode === 'hourly'
      : input.category === 'usage' ? current.trafficBillingMode === 'usage' : current.deletionBillingMode === 'user_destroy'
    if (!relevant) throw new BillingReviewError('REVIEW_CATEGORY_MISMATCH')
    await tx.log.create({ data: { userId: actorId, instanceId, module: 'billing', action: DELETION_BILLING_REVIEW_ACTION, content: JSON.stringify(payload), result: 'success' } })
    return 'recorded'
  })
}

export async function listDeletionBillingReviews(instanceId: number) {
  const logs = await prisma.log.findMany({ where: { instanceId, action: DELETION_BILLING_REVIEW_ACTION },
    select: { id: true, userId: true, content: true, createdAt: true }, orderBy: { id: 'desc' }, take: 20 })
  return logs.map(log => ({ id: log.id, actorId: log.userId, createdAt: log.createdAt,
    ...JSON.parse(log.content) as { category: BillingReviewCategory; evidenceReference: string; note: string } }))
}
