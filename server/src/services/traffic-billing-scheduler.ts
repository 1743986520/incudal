import { Prisma } from '@prisma/client'
import { schedule } from 'node-cron'
import { prisma } from '../db/prisma.js'
import { getIncusClient } from '../lib/incus/incus-pool.js'
import { stopInstance } from '../lib/incus/incus-instances.js'
import { sendTrafficBillingLowBalanceEmail } from '../lib/mailer.js'

const GIB = 1024 * 1024 * 1024
const HALF_GIB = GIB / 2
const SUSPEND_REASON = 'traffic_billing_insufficient_balance'

type SettlementTrigger = 'hourly' | 'gigabyte'

function nextHour(from = new Date()): Date {
  return new Date(from.getTime() + 60 * 60 * 1000)
}

type SettlementResult = {
  instanceId: number
  incusId: string
  host: {
    id: number
    url: string
    certPath: string | null
    keyPath: string | null
    serverCertificate: string | null
    serverFingerprint: string | null
    allowPrivateNetwork: boolean
  }
  suspended: boolean
}

async function sendLowBalanceWarnings(): Promise<void> {
  const instances = await prisma.instance.findMany({
    where: {
      trafficBillingMode: 'usage',
      trafficUnitPrice: { gt: 0 },
      OR: [
        { status: 'running' },
        { status: 'suspended', suspendReason: SUSPEND_REASON }
      ]
    },
    select: {
      id: true,
      name: true,
      trafficUnitPrice: true,
      trafficLowBalanceNotifiedAt: true,
      user: { select: { username: true, email: true, balance: true } }
    }
  })

  for (const instance of instances) {
    const unitPricePerGb = new Prisma.Decimal(instance.trafficUnitPrice).div(100).toNumber()
    const warningBalance = new Prisma.Decimal(unitPricePerGb).mul(5).toNumber()
    const balance = Number(instance.user.balance)

    if (balance >= warningBalance) {
      if (instance.trafficLowBalanceNotifiedAt) {
        await prisma.instance.updateMany({
          where: { id: instance.id, trafficLowBalanceNotifiedAt: { not: null } },
          data: { trafficLowBalanceNotifiedAt: null }
        })
      }
      continue
    }

    const email = instance.user.email?.trim()
    if (!email || instance.trafficLowBalanceNotifiedAt) continue

    // Atomic claim prevents duplicate mail when multiple panel replicas run the cron.
    const claimed = await prisma.instance.updateMany({
      where: { id: instance.id, trafficLowBalanceNotifiedAt: null },
      data: { trafficLowBalanceNotifiedAt: new Date() }
    })
    if (claimed.count !== 1) continue

    const result = await sendTrafficBillingLowBalanceEmail(email, {
      username: instance.user.username,
      instanceName: instance.name,
      balance,
      unitPricePerGb,
      affordableGb: unitPricePerGb > 0 ? balance / unitPricePerGb : 0
    })
    if (!result.success) {
      // Allow the next hourly run to retry transient SMTP failures.
      await prisma.instance.update({
        where: { id: instance.id },
        data: { trafficLowBalanceNotifiedAt: null }
      })
      console.error(`[TrafficBilling] Low-balance email failed for instance ${instance.id}: ${result.error}`)
    }
  }
}

async function settleInstance(instanceId: number, now: Date, trigger: SettlementTrigger): Promise<SettlementResult | null> {
  return prisma.$transaction(async tx => {
    const instance = await tx.instance.findUnique({
      where: { id: instanceId },
      include: {
        host: {
          select: {
            id: true,
            url: true,
            certPath: true,
            keyPath: true,
            serverCertificate: true,
            serverFingerprint: true,
            allowPrivateNetwork: true
          }
        }
      }
    })

    if (!instance || instance.status !== 'running' || instance.trafficBillingMode !== 'usage' ||
      new Prisma.Decimal(instance.trafficUnitPrice).lte(0) ||
      (trigger === 'hourly' && instance.nextTrafficBillingAt && instance.nextTrafficBillingAt > now)) {
      return null
    }

    const included = instance.monthlyTrafficLimit ?? 0n
    const totalOverage = instance.monthlyTrafficUsed > included ? instance.monthlyTrafficUsed - included : 0n
    const unsettledBytes = totalOverage > instance.trafficSettledBytes
      ? totalOverage - instance.trafficSettledBytes
      : 0n
    const dueAt = instance.nextTrafficBillingAt ?? now
    const followingRun = nextHour(now)
    const pendingRecord = await tx.trafficBillingRecord.findFirst({
      where: { instanceId: instance.id, status: 'pending' },
      orderBy: { createdAt: 'desc' }
    })

    const threshold = trigger === 'gigabyte' ? BigInt(GIB) : BigInt(HALF_GIB)
    if (unsettledBytes < threshold && !pendingRecord) {
      if (trigger === 'hourly') {
        await tx.instance.update({
          where: { id: instance.id },
          data: { nextTrafficBillingAt: followingRun }
        })
      }
      return { instanceId: instance.id, incusId: instance.incusId, host: instance.host, suspended: false }
    }

    if (unsettledBytes === 0n && !pendingRecord) {
      await tx.instance.update({ where: { id: instance.id }, data: { nextTrafficBillingAt: followingRun } })
      return { instanceId: instance.id, incusId: instance.incusId, host: instance.host, suspended: false }
    }

    // PackagePlan prices are stored in cents. User balances and billing records are stored in yuan.
    const rawAmount = new Prisma.Decimal(unsettledBytes.toString())
        .div(GIB)
        .mul(instance.trafficUnitPrice)
        .div(100)
    // Wallet balances have cent precision. Always round down and leave the
    // fractional value represented by unbilled bytes, so tiny unit prices are
    // accumulated rather than rounded away or rounded up against the user.
    const amountDecimal = unsettledBytes === 0n && pendingRecord
      ? new Prisma.Decimal(pendingRecord.amount)
      : rawAmount.toDecimalPlaces(2, Prisma.Decimal.ROUND_DOWN)
    const amount = amountDecimal.toNumber()
    const billingBytes = unsettledBytes === 0n && pendingRecord
      ? pendingRecord.trafficBytes
      : BigInt(amountDecimal
        .mul(100)
        .mul(GIB)
        .div(instance.trafficUnitPrice)
        .toDecimalPlaces(0, Prisma.Decimal.ROUND_DOWN)
        .toFixed(0))
    if (amount <= 0) {
      // Keep sub-cent usage pending until enough bytes accumulate to one cent.
      if (trigger === 'hourly') {
        await tx.instance.update({ where: { id: instance.id }, data: { nextTrafficBillingAt: followingRun } })
      }
      return { instanceId: instance.id, incusId: instance.incusId, host: instance.host, suspended: false }
    }

    const user = await tx.user.findUnique({ where: { id: instance.userId }, select: { balance: true } })
    if (!user) throw new Error(`Traffic billing user ${instance.userId} not found`)
    const balanceBefore = Number(user.balance)
    const periodStart = new Date(dueAt.getTime() - 60 * 60 * 1000)
    if (balanceBefore < amount) {
      if (pendingRecord) {
        // A host owner may temporarily unsuspend an unpaid instance. Refresh the
        // existing debt instead of generating duplicate pending bills.
        await tx.trafficBillingRecord.update({
          where: { id: pendingRecord.id },
          data: {
            trafficBytes: billingBytes,
            unitPrice: instance.trafficUnitPrice,
            amount,
            periodEnd: now
          }
        })
      } else {
        await tx.trafficBillingRecord.create({
          data: {
            instanceId: instance.id,
            userId: instance.userId,
            trafficBytes: billingBytes,
            unitPrice: instance.trafficUnitPrice,
            amount,
            status: 'pending',
            periodStart,
            periodEnd: now
          }
        })
      }
      await tx.instance.update({
        where: { id: instance.id },
        data: {
          status: 'suspended',
          suspendedAt: now,
          suspendedBy: null,
          suspendReason: SUSPEND_REASON,
          nextTrafficBillingAt: null,
          version: { increment: 1 }
        }
      })
      return { instanceId: instance.id, incusId: instance.incusId, host: instance.host, suspended: true }
    }

    const balanceAfter = Number((balanceBefore - amount).toFixed(2))
    await tx.user.update({ where: { id: instance.userId }, data: { balance: balanceAfter } })
    const balanceLog = await tx.balanceLog.create({
      data: {
        userId: instance.userId,
        type: 'consume',
        amount: -amount,
        balanceBefore,
        balanceAfter,
        instanceId: instance.id,
        remark: `实例 ${instance.name} 按量流量费（${billingBytes.toString()} bytes）`
      }
    })
    if (pendingRecord) {
      await tx.trafficBillingRecord.update({
        where: { id: pendingRecord.id },
        data: {
          trafficBytes: billingBytes,
          unitPrice: instance.trafficUnitPrice,
          amount,
          status: 'paid',
          periodEnd: now,
          balanceLogId: balanceLog.id
        }
      })
    } else {
      await tx.trafficBillingRecord.create({
        data: {
          instanceId: instance.id,
          userId: instance.userId,
          trafficBytes: billingBytes,
          unitPrice: instance.trafficUnitPrice,
          amount,
          status: 'paid',
          periodStart,
          periodEnd: now,
          balanceLogId: balanceLog.id
        }
      })
    }
    await tx.instance.update({
      where: { id: instance.id },
      data: {
        trafficSettledBytes: { increment: billingBytes },
        trafficSettledCost: { increment: amount },
        nextTrafficBillingAt: trigger === 'hourly'
          ? followingRun
          : (instance.nextTrafficBillingAt ?? followingRun)
      }
    })
    return { instanceId: instance.id, incusId: instance.incusId, host: instance.host, suspended: false }
  }, {
    isolationLevel: Prisma.TransactionIsolationLevel.Serializable,
    timeout: 15000
  })
}

async function runSettlementCandidates(candidateIds: number[], now: Date, trigger: SettlementTrigger): Promise<void> {
  for (const instanceId of candidateIds) {
    try {
      const result = await settleInstance(instanceId, now, trigger)
      if (!result?.suspended) continue
      try {
        const client = await getIncusClient(result.host)
        await stopInstance(client, result.incusId, true)
      } catch (error) {
        console.error(`[TrafficBilling] Instance ${result.instanceId} was suspended but Incus stop failed:`, error)
      }
    } catch (error) {
      console.error(`[TrafficBilling] Failed to settle instance ${instanceId}:`, error)
    }
  }
}

export async function runTrafficBillingThresholdJob(instanceIds?: number[]): Promise<void> {
  const candidates = await prisma.instance.findMany({
    where: {
      id: instanceIds ? { in: instanceIds } : undefined,
      trafficBillingMode: 'usage',
      status: 'running'
    },
    select: {
      id: true,
      monthlyTrafficLimit: true,
      monthlyTrafficUsed: true,
      trafficSettledBytes: true
    }
  })
  const dueIds = candidates
    .filter(instance => {
      const included = instance.monthlyTrafficLimit ?? 0n
      const overage = instance.monthlyTrafficUsed > included ? instance.monthlyTrafficUsed - included : 0n
      return overage - instance.trafficSettledBytes >= BigInt(GIB)
    })
    .map(instance => instance.id)

  await runSettlementCandidates(dueIds, new Date(), 'gigabyte')
}

export async function runTrafficBillingJob(): Promise<void> {
  const now = new Date()
  const dueInstances = await prisma.instance.findMany({
    where: {
      trafficBillingMode: 'usage',
      status: 'running',
      OR: [{ nextTrafficBillingAt: null }, { nextTrafficBillingAt: { lte: now } }]
    },
    select: { id: true }
  })

  await runSettlementCandidates(dueInstances.map(candidate => candidate.id), now, 'hourly')

  // A host can be temporarily unreachable during the first suspension attempt.
  // Retry the physical stop without creating another bill or touching the balance.
  const suspendedInstances = await prisma.instance.findMany({
    where: {
      trafficBillingMode: 'usage',
      status: 'suspended',
      suspendReason: SUSPEND_REASON
    },
    include: {
      host: {
        select: {
          id: true,
          url: true,
          certPath: true,
          keyPath: true,
          serverCertificate: true,
          serverFingerprint: true,
          allowPrivateNetwork: true
        }
      }
    }
  })
  for (const instance of suspendedInstances) {
    try {
      const client = await getIncusClient(instance.host)
      await stopInstance(client, instance.incusId, true)
    } catch (error) {
      console.error(`[TrafficBilling] Retry stop failed for instance ${instance.id}:`, error)
    }
  }

  await sendLowBalanceWarnings()
}

export function startTrafficBillingScheduler(): void {
  schedule('0 * * * *', () => runTrafficBillingJob().catch(console.error))
  console.log('[TrafficBilling] Scheduler started (1 GiB threshold + hourly 0.5 GiB fallback)')
}
