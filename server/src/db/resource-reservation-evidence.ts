import type { Prisma } from '@prisma/client'

export interface ReservationAmounts {
  instanceId: number
  hostId: number
  cpu: number
  memory: number
  disk: number
  portCount: number
}

export type ReservationEvidence =
  | { state: 'unknown' }
  | { state: 'reserved' | 'released'; generation: number; hostEpoch: bigint; amounts: ReservationAmounts;
      hostCounters: { cpu: number; memory: number; disk: number; portCount: number } }

/** Record evidence only in the same transaction that reserved the host and
 * created the instance. Historical rows deliberately have no evidence. */
export async function recordNewInstanceReservation(tx: Prisma.TransactionClient, amounts: ReservationAmounts): Promise<void> {
  const [host, instance] = await Promise.all([
    tx.host.findUniqueOrThrow({ where: { id: amounts.hostId }, select: { reservationEpoch: true } }),
    tx.instance.findUniqueOrThrow({ where: { id: amounts.instanceId }, select: { hostId: true, cpu: true, memory: true, disk: true } })
  ])
  if (instance.hostId !== amounts.hostId || instance.cpu !== amounts.cpu || instance.memory !== amounts.memory || instance.disk !== amounts.disk) {
    throw new Error('RESERVATION_INSTANCE_MISMATCH')
  }
  await tx.instanceResourceReservation.create({
    data: { ...amounts, state: 'reserved', generation: 1, hostEpoch: host.reservationEpoch }
  })
}

/** Locks the host until transaction commit, so an epoch check remains true
 * through a subsequent counter mutation. A missing, invalidated, mismatched or
 * stale record is unknown, never inferred from the instance status. */
export async function readReservationEvidenceForUpdate(tx: Prisma.TransactionClient, instanceId: number): Promise<ReservationEvidence> {
  const reservation = await tx.instanceResourceReservation.findUnique({ where: { instanceId } })
  if (!reservation || reservation.state === 'unknown') return { state: 'unknown' }
  const hosts = await tx.$queryRaw<Array<{ epoch: bigint; cpu: number; memory: number; disk: number; portCount: number }>>`
    SELECT "reservation_epoch" AS "epoch", "cpu_used" AS "cpu", "memory_used" AS "memory",
      "disk_used" AS "disk", "nat_ports_used_count" AS "portCount"
    FROM "hosts" WHERE "id" = ${reservation.hostId} FOR UPDATE
  `
  const instance = await tx.instance.findUnique({ where: { id: instanceId }, select: { hostId: true, cpu: true, memory: true, disk: true } })
  if (!instance || hosts[0]?.epoch !== reservation.hostEpoch || instance.hostId !== reservation.hostId
    || instance.cpu !== reservation.cpu || instance.memory !== reservation.memory || instance.disk !== reservation.disk
    || (reservation.state !== 'reserved' && reservation.state !== 'released')) return { state: 'unknown' }
  return {
    state: reservation.state,
    generation: reservation.generation,
    hostEpoch: reservation.hostEpoch,
    hostCounters: { cpu: hosts[0]!.cpu, memory: hosts[0]!.memory, disk: hosts[0]!.disk, portCount: hosts[0]!.portCount },
    amounts: {
      instanceId, hostId: reservation.hostId, cpu: reservation.cpu,
      memory: reservation.memory, disk: reservation.disk, portCount: reservation.portCount
    }
  }
}

/** Only promote an existing, current reservation to released when the exact
 * recorded amounts were in fact decremented in the same DB transaction. */
export async function recordReservationRelease(
  tx: Prisma.TransactionClient,
  before: ReservationEvidence,
  actual: ReservationAmounts
): Promise<void> {
  if (before.state !== 'reserved') return
  const a = before.amounts
  if (a.instanceId !== actual.instanceId || a.hostId !== actual.hostId || a.cpu !== actual.cpu
    || a.memory !== actual.memory || a.disk !== actual.disk || a.portCount !== actual.portCount) return
  const host = await tx.host.findUniqueOrThrow({ where: { id: actual.hostId }, select: { reservationEpoch: true, cpuUsed: true, memoryUsed: true, diskUsed: true, natPortsUsedCount: true } })
  const changed = actual.cpu !== 0 || actual.memory !== 0 || actual.disk !== 0 || actual.portCount !== 0
  if (host.reservationEpoch !== before.hostEpoch + (changed ? 1n : 0n)
    || host.cpuUsed !== before.hostCounters.cpu - actual.cpu
    || host.memoryUsed !== before.hostCounters.memory - actual.memory
    || host.diskUsed !== before.hostCounters.disk - actual.disk
    || host.natPortsUsedCount !== before.hostCounters.portCount - actual.portCount) return
  await tx.instanceResourceReservation.updateMany({
    where: { instanceId: actual.instanceId, state: 'reserved', generation: before.generation, hostEpoch: before.hostEpoch },
    data: { state: 'released', hostEpoch: host.reservationEpoch }
  })
}

/** A retry can become known-reserved only if the prior release is still
 * provable. Unknown historical state remains unknown after another reserve. */
export async function recordReservationRetry(
  tx: Prisma.TransactionClient,
  before: ReservationEvidence,
  actual: ReservationAmounts
): Promise<void> {
  if (before.state !== 'released') return
  const a = before.amounts
  if (a.instanceId !== actual.instanceId || a.hostId !== actual.hostId || a.cpu !== actual.cpu
    || a.memory !== actual.memory || a.disk !== actual.disk || a.portCount !== actual.portCount) return
  const host = await tx.host.findUniqueOrThrow({ where: { id: actual.hostId }, select: { reservationEpoch: true, cpuUsed: true, memoryUsed: true, diskUsed: true, natPortsUsedCount: true } })
  const changed = actual.cpu !== 0 || actual.memory !== 0 || actual.disk !== 0 || actual.portCount !== 0
  if (host.reservationEpoch !== before.hostEpoch + (changed ? 1n : 0n)
    || host.cpuUsed !== before.hostCounters.cpu + actual.cpu
    || host.memoryUsed !== before.hostCounters.memory + actual.memory
    || host.diskUsed !== before.hostCounters.disk + actual.disk
    || host.natPortsUsedCount !== before.hostCounters.portCount + actual.portCount) return
  await tx.instanceResourceReservation.updateMany({
    where: { instanceId: actual.instanceId, state: 'released', generation: before.generation, hostEpoch: before.hostEpoch },
    data: { state: 'reserved', generation: { increment: 1 }, hostEpoch: host.reservationEpoch }
  })
}
