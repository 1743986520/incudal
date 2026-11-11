import type { FastifyInstance } from 'fastify'
import { prisma } from '../db/prisma.js'
import { AdvisoryLockBusyError } from '../db/advisory-locks.js'
import { getDeletionReservationReconciliationSnapshot, reconcileDeletionReservation, ReservationReconciliationError, type ReservationReconciliationInput } from '../services/deletion-reservation-reconciliation.js'
import { BillingReviewError, listDeletionBillingReviews, recordDeletionBillingReview, type BillingReviewInput } from '../services/deletion-billing-review.js'

export default async function deletionReservationReconciliationRoutes(app: FastifyInstance): Promise<void> {
  const path = '/api/admin/instances/:id/deletion-reservation-reconciliation'
  app.get(path, { onRequest: [app.authenticate, app.requireAdmin] }, async (request, reply) => {
    const actor = await prisma.user.findUnique({ where: { id: request.user.id }, select: { role: true, status: true } })
    if (actor?.role !== 'admin' || actor.status !== 'active') return reply.code(403).send({ code: 'FORBIDDEN' })
    const instanceId = Number((request.params as { id: string }).id)
    if (!Number.isSafeInteger(instanceId) || instanceId <= 0 || instanceId > 2147483647) return reply.code(400).send({ code: 'INVALID_INSTANCE_ID' })
    const snapshot = await getDeletionReservationReconciliationSnapshot(instanceId)
    return snapshot ?? reply.code(404).send({ code: 'INSTANCE_NOT_FOUND' })
  })
  app.post(path, { onRequest: [app.authenticate, app.requireAdmin], config: { rateLimit: { max: 10, timeWindow: '1 minute' } } }, async (request, reply) => {
    const instanceId = Number((request.params as { id: string }).id)
    if (!Number.isSafeInteger(instanceId) || instanceId <= 0 || instanceId > 2147483647) return reply.code(400).send({ code: 'INVALID_INSTANCE_ID' })
    try {
      const result = await reconcileDeletionReservation(instanceId, request.user.id, request.body as ReservationReconciliationInput)
      return { result }
    } catch (error) {
      if (error instanceof AdvisoryLockBusyError) return reply.code(409).send({ code: 'INSTANCE_OPERATION_IN_PROGRESS' })
      if (error instanceof ReservationReconciliationError) {
        const code = error.code === 'FORBIDDEN' ? 403 : error.code === 'INVALID_RECONCILIATION_INPUT' ? 400 : error.code === 'INSTANCE_NOT_FOUND' ? 404 : 409
        return reply.code(code).send({ code: error.code })
      }
      throw error
    }
  })
  const reviewPath = '/api/admin/instances/:id/deletion-billing-review'
  app.get(reviewPath, { onRequest: [app.authenticate, app.requireAdmin] }, async (request, reply) => {
    const actor = await prisma.user.findUnique({ where: { id: request.user.id }, select: { role: true, status: true } })
    if (actor?.role !== 'admin' || actor.status !== 'active') return reply.code(403).send({ code: 'FORBIDDEN' })
    const instanceId = Number((request.params as { id: string }).id)
    if (!Number.isSafeInteger(instanceId) || instanceId <= 0 || instanceId > 2147483647) return reply.code(400).send({ code: 'INVALID_INSTANCE_ID' })
    return { reviews: await listDeletionBillingReviews(instanceId) }
  })
  app.post(reviewPath, { onRequest: [app.authenticate, app.requireAdmin], config: { rateLimit: { max: 10, timeWindow: '1 minute' } } }, async (request, reply) => {
    const instanceId = Number((request.params as { id: string }).id)
    if (!Number.isSafeInteger(instanceId) || instanceId <= 0 || instanceId > 2147483647) return reply.code(400).send({ code: 'INVALID_INSTANCE_ID' })
    try {
      return { result: await recordDeletionBillingReview(instanceId, request.user.id, request.body as BillingReviewInput) }
    } catch (error) {
      if (error instanceof AdvisoryLockBusyError) return reply.code(409).send({ code: 'INSTANCE_OPERATION_IN_PROGRESS' })
      if (error instanceof BillingReviewError) {
        const status = error.code === 'FORBIDDEN' ? 403 : error.code === 'INVALID_REVIEW_INPUT' ? 400 : error.code === 'INSTANCE_NOT_FOUND' ? 404 : 409
        return reply.code(status).send({ code: error.code })
      }
      throw error
    }
  })
}
