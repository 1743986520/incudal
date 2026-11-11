import { prisma } from '../db/prisma.js'
import { DELETION_RESERVATION_RECONCILIATION_ACTION } from '../db/logs.js'
import { advisoryTransactionLock, INSTANCE_OPERATION_LOCK_NAMESPACE } from '../db/advisory-locks.js'

const AUDIT_ACTION = DELETION_RESERVATION_RECONCILIATION_ACTION
const NAT_MODES = ['nat', 'nat_ipv6', 'nat_ipv6_nat', 'ipv6_nat', 'ipv6_only']

export interface ReservationReconciliationInput {
  requestId: string
  state: 'reserved' | 'released'
  evidenceReference: string
  reason: string
  expected: { instanceVersion: number; hostId: number; cpu: number; memory: number; disk: number; portCount: number; hostEpoch: string }
}

export class ReservationReconciliationError extends Error {
  constructor(readonly code: string) { super(code) }
}

function validateInput(input: ReservationReconciliationInput): void {
  if (!input || typeof input !== 'object' || typeof input.requestId !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(input.requestId)
    || !['reserved', 'released'].includes(input.state)
    || typeof input.evidenceReference !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:/-]{7,127}$/.test(input.evidenceReference)
    || typeof input.reason !== 'string' || input.reason.trim() !== input.reason || input.reason.length < 12 || input.reason.length > 500
    || !input.expected || typeof input.expected !== 'object' || typeof input.expected.hostEpoch !== 'string'
    || !/^(0|[1-9][0-9]{0,18})$/.test(input.expected.hostEpoch)) throw new ReservationReconciliationError('INVALID_RECONCILIATION_INPUT')
  for (const value of [input.expected.instanceVersion, input.expected.hostId, input.expected.cpu, input.expected.memory, input.expected.disk, input.expected.portCount]) {
    if (!Number.isSafeInteger(value) || value < 0 || value > 2147483647) throw new ReservationReconciliationError('INVALID_RECONCILIATION_INPUT')
  }
  if (input.expected.hostId === 0 || BigInt(input.expected.hostEpoch) > 9223372036854775807n) throw new ReservationReconciliationError('INVALID_RECONCILIATION_INPUT')
}

function normalized(instanceId: number, actorId: number, input: ReservationReconciliationInput) {
  // Keep the identities in the immutable content even if the optional log
  // foreign keys are later nulled by an unrelated physical deletion.
  return { instanceId, actorId, requestId: input.requestId.toLowerCase(), state: input.state, evidenceReference: input.evidenceReference, reason: input.reason,
    expected: { instanceVersion: input.expected.instanceVersion, hostId: input.expected.hostId, cpu: input.expected.cpu,
      memory: input.expected.memory, disk: input.expected.disk, portCount: input.expected.portCount, hostEpoch: input.expected.hostEpoch } }
}

/** The operator must independently verify the reservation and cite evidence.
 * The aggregate host counters by themselves are never treated as evidence. */
export async function reconcileDeletionReservation(instanceId: number, actorId: number, input: ReservationReconciliationInput): Promise<'recorded' | 'already_recorded'> {
  validateInput(input)
  const payload = normalized(instanceId, actorId, input)
  return prisma.$transaction(async tx => {
    await advisoryTransactionLock(tx, INSTANCE_OPERATION_LOCK_NAMESPACE, instanceId)
    const actors = await tx.$queryRaw<Array<{ role: string; status: string }>>`
      SELECT "role", "status" FROM "users" WHERE "id" = ${actorId} FOR UPDATE
    `
    if (actors[0]?.role !== 'admin' || actors[0]?.status !== 'active') throw new ReservationReconciliationError('FORBIDDEN')

    // Scoped to instance and protected by its transaction lock. On retry this
    // audit survives the worker completing and remains the idempotency record.
    const audit = await tx.log.findFirst({ where: {
      instanceId, action: AUDIT_ACTION, content: { contains: `"requestId":"${payload.requestId}"` }
    } })
    if (audit) {
      if (audit.userId !== actorId || audit.content !== JSON.stringify(payload)) throw new ReservationReconciliationError('RECONCILIATION_REQUEST_CONFLICT')
      return 'already_recorded'
    }
    const rows = await tx.$queryRaw<Array<{ id: number }>>`SELECT "id" FROM "instances" WHERE "id" = ${instanceId} FOR UPDATE`
    if (!rows.length) throw new ReservationReconciliationError('INSTANCE_NOT_FOUND')
    const instance = await tx.instance.findUniqueOrThrow({ where: { id: instanceId }, select: {
      status: true, deletionRemoteDeleted: true, version: true, hostId: true, cpu: true, memory: true, disk: true, portLimit: true, networkMode: true
    } })
    if (instance.status !== 'deleting' || !instance.deletionRemoteDeleted) throw new ReservationReconciliationError('REMOTE_DELETION_NOT_CONFIRMED')
    const expected = payload.expected
    const portCount = NAT_MODES.includes(instance.networkMode) ? (instance.portLimit ?? 0) : 0
    if (instance.version !== expected.instanceVersion || instance.hostId !== expected.hostId || instance.cpu !== expected.cpu
      || instance.memory !== expected.memory || instance.disk !== expected.disk || portCount !== expected.portCount) {
      throw new ReservationReconciliationError('RECONCILIATION_SNAPSHOT_STALE')
    }
    const hosts = await tx.$queryRaw<Array<{ epoch: bigint; cpu: number; memory: number; disk: number; portCount: number }>>`
      SELECT "reservation_epoch" AS "epoch", "cpu_used" AS "cpu", "memory_used" AS "memory", "disk_used" AS "disk", "nat_ports_used_count" AS "portCount"
      FROM "hosts" WHERE "id" = ${instance.hostId} FOR UPDATE
    `
    const host = hosts[0]
    if (!host || host.epoch.toString() !== expected.hostEpoch) throw new ReservationReconciliationError('RECONCILIATION_SNAPSHOT_STALE')
    if (payload.state === 'reserved' && (host.cpu < instance.cpu || host.memory < instance.memory || host.disk < instance.disk || host.portCount < portCount)) {
      throw new ReservationReconciliationError('HOST_COUNTERS_INSUFFICIENT')
    }
    const old = await tx.instanceResourceReservation.findUnique({ where: { instanceId } })
    if (old && old.hostEpoch === host.epoch && old.state !== 'unknown') throw new ReservationReconciliationError('RESERVATION_EVIDENCE_ALREADY_CURRENT')
    await tx.instanceResourceReservation.upsert({
      where: { instanceId },
      create: { instanceId, hostId: instance.hostId, state: payload.state, generation: 1, hostEpoch: host.epoch,
        cpu: instance.cpu, memory: instance.memory, disk: instance.disk, portCount },
      update: { hostId: instance.hostId, state: payload.state, generation: { increment: 1 }, hostEpoch: host.epoch,
        cpu: instance.cpu, memory: instance.memory, disk: instance.disk, portCount }
    })
    await tx.log.create({ data: { userId: actorId, instanceId, module: 'instance', action: AUDIT_ACTION, content: JSON.stringify(payload), result: 'success' } })
    return 'recorded'
  })
}

export async function getDeletionReservationReconciliationSnapshot(instanceId: number) {
  const instance = await prisma.instance.findUnique({ where: { id: instanceId }, select: {
    id: true, name: true, incusId: true, status: true, deletionRemoteDeleted: true, deletionRequestedAt: true, version: true, hostId: true, cpu: true, memory: true,
    disk: true, portLimit: true, networkMode: true, billingMode: true, trafficBillingMode: true,
    deletionBillingMode: true, deletionBillingPending: true, deletionOriginalStatus: true, provisioningCleanupPending: true,
    host: { select: { status: true, reservationEpoch: true, cpuUsed: true, memoryUsed: true, diskUsed: true, natPortsUsedCount: true } },
    resourceReservation: { select: { state: true, hostEpoch: true, generation: true } }
  } })
  if (!instance) return null
  return { instance: { id: instance.id, name: instance.name, incusId: instance.incusId, deletionRequestedAt: instance.deletionRequestedAt?.toISOString() ?? null, status: instance.status, deletionRemoteDeleted: instance.deletionRemoteDeleted,
    version: instance.version, hostId: instance.hostId, cpu: instance.cpu, memory: instance.memory, disk: instance.disk,
    portCount: NAT_MODES.includes(instance.networkMode) ? (instance.portLimit ?? 0) : 0, networkMode: instance.networkMode,
    billingMode: instance.billingMode, trafficBillingMode: instance.trafficBillingMode, deletionBillingMode: instance.deletionBillingMode,
    deletionBillingPending: instance.deletionBillingPending, deletionOriginalStatus: instance.deletionOriginalStatus,
    provisioningCleanupPending: instance.provisioningCleanupPending },
    host: { status: instance.host.status, reservationEpoch: instance.host.reservationEpoch.toString(), cpuUsed: instance.host.cpuUsed, memoryUsed: instance.host.memoryUsed,
      diskUsed: instance.host.diskUsed, natPortsUsedCount: instance.host.natPortsUsedCount },
    reservation: instance.resourceReservation ? { ...instance.resourceReservation, hostEpoch: instance.resourceReservation.hostEpoch.toString() } : null }
}
