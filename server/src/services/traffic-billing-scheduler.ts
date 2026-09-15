import { Prisma } from '@prisma/client'
import { schedule } from 'node-cron'
import { prisma } from '../db/prisma.js'
import { getIncusClient } from '../lib/incus/incus-pool.js'
import { stopInstance } from '../lib/incus/incus-instances.js'
import { sendTrafficBillingLowBalanceEmail } from '../lib/mailer.js'
import { getTrafficPeriod } from './traffic-utils.js'

const GIB = 1024 * 1024 * 1024
const HALF_GIB = GIB / 2
const SUSPEND_REASON = 'traffic_billing_insufficient_balance'

type SettlementTrigger = 'hourly' | 'gigabyte'

function nextHour(from = new Date()): Date {
  return new Date(from.getTime() + 60 * 60 * 1000)
}

const LOW_BALANCE_WARNING_COOLDOWN_MS = 24 * 60 * 60 * 1000

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
    // Never make the warning threshold smaller than the wallet's one-cent
    // precision, otherwise very cheap plans could never produce a warning.
    const warningBalance = Prisma.Decimal.max(new Prisma.Decimal(unitPricePerGb).mul(5), new Prisma.Decimal(0.01)).toNumber()
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
    const warningCutoff = new Date(Date.now() - LOW_BALANCE_WARNING_COOLDOWN_MS)
    if (!email || (instance.trafficLowBalanceNotifiedAt && instance.trafficLowBalanceNotifiedAt > warningCutoff)) continue

    // Atomic claim prevents duplicate mail when multiple panel replicas run the cron.
    const claimed = await prisma.instance.updateMany({
      where: {
        id: instance.id,
        OR: [
          { trafficLowBalanceNotifiedAt: null },
          { trafficLowBalanceNotifiedAt: { lte: warningCutoff } }
        ]
      },
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
            allowPrivateNetwork: true,
            trafficResetDay: true
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
    // An existing debt is immutable and belongs to its original traffic
    // period. Pay it first; current-period usage is settled on the next pass.
    const amountDecimal = pendingRecord
      ? new Prisma.Decimal(pendingRecord.amount)
      : rawAmount.toDecimalPlaces(2, Prisma.Decimal.ROUND_DOWN)
    const amount = amountDecimal.toNumber()
    const billingBytes = pendingRecord
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
    const balanceBefore = new Prisma.Decimal(user.balance)
    const trafficPeriodStart = getTrafficPeriod(instance.host.trafficResetDay ?? 1, now).periodStart
    const previousPaidRecord = await tx.trafficBillingRecord.findFirst({
      where: { instanceId: instance.id, status: 'paid' },
      orderBy: { periodEnd: 'desc' },
      select: { periodEnd: true }
    })
    const periodStart = previousPaidRecord?.periodEnd && previousPaidRecord.periodEnd > trafficPeriodStart
      ? previousPaidRecord.periodEnd
      : trafficPeriodStart
    if (balanceBefore.lt(amountDecimal)) {
      if (pendingRecord) {
        // Keep the original debt and its period snapshot unchanged.
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
      const suspended = await tx.instance.updateMany({
        where: { id: instance.id, version: instance.version },
        data: {
          status: 'suspended',
          suspendedAt: now,
          suspendedBy: null,
          suspendReason: SUSPEND_REASON,
          nextTrafficBillingAt: null,
          version: { increment: 1 }
        }
      })
      if (suspended.count !== 1) throw new Error('TRAFFIC_BILLING_INSTANCE_CHANGED')
      return { instanceId: instance.id, incusId: instance.incusId, host: instance.host, suspended: true }
    }

    const balanceAfter = balanceBefore.sub(amountDecimal)
    await tx.user.update({ where: { id: instance.userId }, data: { balance: { decrement: amountDecimal } } })
    const balanceLog = await tx.balanceLog.create({
      data: {
        userId: instance.userId,
        type: 'consume',
        amount: amountDecimal.neg(),
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
    const currentPeriodBillingBytes = pendingRecord && pendingRecord.periodStart < trafficPeriodStart
      ? 0n
      : billingBytes
    const currentPeriodBillingAmount = pendingRecord && pendingRecord.periodStart < trafficPeriodStart
      ? new Prisma.Decimal(0)
      : amountDecimal
    const instanceUpdate = await tx.instance.updateMany({
      where: { id: instance.id, version: instance.version },
      data: {
        trafficSettledBytes: { increment: currentPeriodBillingBytes },
        trafficSettledCost: { increment: currentPeriodBillingAmount },
        nextTrafficBillingAt: trigger === 'hourly'
          ? followingRun
          : (instance.nextTrafficBillingAt ?? followingRun),
        version: { increment: 1 }
      }
    })
    if (instanceUpdate.count !== 1) throw new Error('TRAFFIC_BILLING_INSTANCE_CHANGED')
    return { instanceId: instance.id, incusId: instance.incusId, host: instance.host, suspended: false }
  }, {
    isolationLevel: Prisma.TransactionIsolationLevel.Serializable,
    timeout: 15000
  })
}

/**
 * Let an instance owner settle the debt that caused a traffic suspension.
 * The wallet debit, billing record, accounting counters and unsuspension are
 * committed atomically. The instance remains physically stopped afterwards.
 */
export async function payPendingTrafficBillAndUnsuspend(instanceId: number, userId: number): Promise<{ amount: number }> {
  return prisma.$transaction(async tx => {
    const instance = await tx.instance.findUnique({
      where: { id: instanceId },
      include: { host: { select: { trafficResetDay: true } } }
    })
    if (!instance || instance.userId !== userId) throw new Error('INSTANCE_NOT_FOUND')
    if (instance.status !== 'suspended' || instance.suspendReason !== SUSPEND_REASON) {
      throw new Error('INSTANCE_NOT_TRAFFIC_SUSPENDED')
    }

    const pending = await tx.trafficBillingRecord.findFirst({
      where: { instanceId, userId, status: 'pending' },
      orderBy: { createdAt: 'desc' }
    })
    if (!pending) throw new Error('PENDING_TRAFFIC_BILL_NOT_FOUND')

    const amount = new Prisma.Decimal(pending.amount)
    const user = await tx.user.findUnique({ where: { id: userId }, select: { balance: true } })
    if (!user) throw new Error('USER_NOT_FOUND')
    const balanceBefore = new Prisma.Decimal(user.balance)
    if (balanceBefore.lt(amount)) throw new Error('BALANCE_INSUFFICIENT')
    const balanceAfter = balanceBefore.sub(amount)

    const walletUpdate = await tx.user.updateMany({
      where: { id: userId, balance: { gte: amount } },
      data: { balance: { decrement: amount } }
    })
    if (walletUpdate.count !== 1) throw new Error('BALANCE_INSUFFICIENT')

    const balanceLog = await tx.balanceLog.create({
      data: {
        userId,
        instanceId,
        type: 'consume',
        amount: amount.neg(),
        balanceBefore,
        balanceAfter,
        remark: `实例 ${instance.name} 补缴按量流量费（${pending.trafficBytes.toString()} bytes）`
      }
    })
    await tx.trafficBillingRecord.update({
      where: { id: pending.id },
      data: { status: 'paid', balanceLogId: balanceLog.id, periodEnd: new Date() }
    })

    const periodStart = getTrafficPeriod(instance.host.trafficResetDay ?? 1).periodStart
    const belongsToCurrentPeriod = pending.periodStart >= periodStart
    const updated = await tx.instance.updateMany({
      where: {
        id: instanceId,
        userId,
        version: instance.version,
        status: 'suspended',
        suspendReason: SUSPEND_REASON
      },
      data: {
        status: 'stopped',
        suspendedAt: null,
        suspendedBy: null,
        suspendReason: null,
        nextTrafficBillingAt: nextHour(),
        trafficSettledBytes: belongsToCurrentPeriod ? { increment: pending.trafficBytes } : undefined,
        trafficSettledCost: belongsToCurrentPeriod ? { increment: amount } : undefined,
        version: { increment: 1 }
      }
    })
    if (updated.count !== 1) throw new Error('INSTANCE_STATE_CHANGED')
    return { amount: amount.toNumber() }
  }, { isolationLevel: Prisma.TransactionIsolationLevel.Serializable, timeout: 15000 })
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

  await retryTrafficBillingSuspensions()

  await sendLowBalanceWarnings()
}

/** Retry the physical stop without creating another bill or touching balance. */
export async function retryTrafficBillingSuspensions(): Promise<void> {
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

}

export function startTrafficBillingScheduler(): void {
  schedule('0 * * * *', () => runTrafficBillingJob().catch(console.error))
  schedule('*/5 * * * *', () => retryTrafficBillingSuspensions().catch(console.error))
  console.log('[TrafficBilling] Scheduler started (1 GiB threshold + hourly 0.5 GiB fallback)')
}
