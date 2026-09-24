import { Prisma } from '@prisma/client'
import { schedule } from 'node-cron'
import { prisma } from '../db/prisma.js'
import { getIncusClient } from '../lib/incus/incus-pool.js'
import { stopInstance } from '../lib/incus/incus-instances.js'
import {
  calculateHourlyBreakdown,
  calculateHourlyCost,
  ceilToQuantum,
  hourlyPricingFromPackagePlan,
  serializeHourlyDecimal,
  type HourlyResources
} from '../lib/hourly-billing.js'

const SETTLEMENT_INTERVAL_MS = 5 * 60 * 1000
const HOURLY_SUSPEND_REASON = 'hourly_billing_insufficient_balance'

type HourlyTx = Prisma.TransactionClient

type HourlyTransactionOperation<T> = (tx: HourlyTx) => Promise<T>

type SettlementResult = {
  instanceId: number
  suspended: boolean
  host: {
    id: number
    url: string
    certPath: string | null
    keyPath: string | null
    serverCertificate: string | null
    serverFingerprint: string | null
    allowPrivateNetwork: boolean
  } | null
}

type HourlyPricingSource = {
  packagePlan?: Parameters<typeof hourlyPricingFromPackagePlan>[0] | null
  pricingVersion?: HourlyPricingSourceVersion | null
}

type HourlyPricingSourceVersion = {
  cpuUnitPercent: number
  memoryUnitMb: number
  diskUnitMb: number
  minCpu: number
  minMemoryMb: number
  minDiskMb: number
  cpuPricePerUnit: Prisma.Decimal
  memoryPricePerUnit: Prisma.Decimal
  diskPricePerUnit: Prisma.Decimal
  reserveQuantum: Prisma.Decimal
}

function getAccountPricing(account: HourlyPricingSource) {
  if (account.packagePlan) return hourlyPricingFromPackagePlan(account.packagePlan)
  if (account.pricingVersion) return account.pricingVersion
  throw new Error('HOURLY_PRICING_MISSING')
}

function zero(): Prisma.Decimal {
  return new Prisma.Decimal(0)
}

function nowPlusInterval(now: Date): Date {
  return new Date(now.getTime() + SETTLEMENT_INTERVAL_MS)
}

function buildSettlementKey(accountId: number, version: number): string {
  return `hourly:${accountId}:${version}`
}

function isSerializationConflict(error: unknown): boolean {
  return error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2034'
}

async function runSerializableTransaction<T>(operation: HourlyTransactionOperation<T>): Promise<T> {
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    try {
      return await prisma.$transaction(operation, {
        isolationLevel: Prisma.TransactionIsolationLevel.Serializable,
        timeout: 15000
      })
    } catch (error) {
      if (!isSerializationConflict(error) || attempt === 3) throw error
      await new Promise(resolve => setTimeout(resolve, attempt * 50))
    }
  }

  throw new Error('Hourly billing transaction retries exhausted')
}

async function createHourlyHostingIncome(tx: HourlyTx, instanceId: number, amount: Prisma.Decimal): Promise<void> {
  if (amount.lte(0)) return
  const instance = await tx.instance.findUnique({
    where: { id: instanceId },
    select: {
      name: true,
      user: { select: { username: true, email: true, avatarStyle: true } },
      host: {
        select: {
          name: true,
          userId: true,
          user: { select: { role: true } }
        }
      },
      package: { select: { name: true } },
      packagePlan: { select: { name: true } }
    }
  })
  if (!instance || instance.host.user.role === 'admin') return

  await tx.hostingBalanceLog.create({
    data: {
      userId: instance.host.userId,
      type: 'income',
      actionType: 'hourly',
      amount,
      frozen: true,
      unfreezeAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
      relatedId: instanceId,
      remark: `按小时计费资源收入（冻结30天）`,
      snapshotBuyerName: instance.user.username,
      snapshotBuyerEmail: instance.user.email,
      snapshotBuyerAvatar: instance.user.avatarStyle,
      snapshotInstanceName: instance.name,
      snapshotHostName: instance.host.name,
      snapshotPackageName: instance.package?.name ?? null,
      snapshotPlanName: instance.packagePlan?.name ?? null
    }
  })
}

async function createBalanceLog(
  tx: HourlyTx,
  input: {
    userId: number
    instanceId: number
    type: 'hourly_reserve' | 'hourly_release' | 'hourly_consume'
    amount: Prisma.Decimal
    balanceBefore: Prisma.Decimal
    balanceAfter: Prisma.Decimal
    remark: string
  }
): Promise<number> {
  const log = await tx.balanceLog.create({ data: input })
  return log.id
}

async function reserveForHourlyCharge(
  tx: HourlyTx,
  input: {
    userId: number
    instanceId: number
    amount: Prisma.Decimal
    balance: Prisma.Decimal
    remark: string
  }
): Promise<{ reserved: Prisma.Decimal; balanceAfter: Prisma.Decimal; balanceLogId: number | null }> {
  if (input.amount.lte(0)) return { reserved: zero(), balanceAfter: input.balance, balanceLogId: null }

  const balanceAfter = input.balance.sub(input.amount)
  const updated = await tx.user.updateMany({
    where: { id: input.userId, balance: { gte: input.amount } },
    data: {
      balance: { decrement: input.amount },
      hourlyReservedBalance: { increment: input.amount }
    }
  })
  if (updated.count !== 1) return { reserved: zero(), balanceAfter: input.balance, balanceLogId: null }

  const balanceLogId = await createBalanceLog(tx, {
    userId: input.userId,
    instanceId: input.instanceId,
    type: 'hourly_reserve',
    amount: input.amount.neg(),
    balanceBefore: input.balance,
    balanceAfter,
    remark: input.remark
  })
  return { reserved: input.amount, balanceAfter, balanceLogId }
}

async function settleInTransaction(
  tx: HourlyTx,
  instanceId: number,
  now: Date,
  options: { force?: boolean } = {}
): Promise<SettlementResult> {
  const initialAccount = await tx.hourlyBillingAccount.findUnique({
    where: { instanceId },
    include: {
      packagePlan: true,
      pricingVersion: true,
      instance: {
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
      }
    }
  })

  if (!initialAccount) return { instanceId, suspended: false, host: null }

  // Prisma's regular read does not lock the account row. Lock and re-read it
  // before calculating the period so overlapping schedulers cannot settle the
  // same seconds twice.
  await tx.$queryRaw(Prisma.sql`
    SELECT id
    FROM "hourly_billing_accounts"
    WHERE id = ${initialAccount.id}
    FOR UPDATE
  `)
  const account = await tx.hourlyBillingAccount.findUnique({
    where: { id: initialAccount.id },
    include: {
      packagePlan: true,
      pricingVersion: true,
      instance: {
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
      }
    }
  })

  if (!account) return { instanceId, suspended: false, host: null }
  if (account.status !== 'active') return { instanceId, suspended: account.status === 'suspended', host: account.instance.host }
  if (!options.force && account.instance.status !== 'running') {
    await tx.hourlyBillingAccount.update({
      where: { id: account.id },
      data: { status: 'paused', nextSettlementAt: null, version: { increment: 1 } }
    })
    return { instanceId, suspended: false, host: account.instance.host }
  }

  const periodStart = account.lastSettledAt
  const activeSeconds = Math.max(0, Math.floor((now.getTime() - periodStart.getTime()) / 1000))
  // Keep sub-second remainder in the next settlement instead of rounding it
  // away by moving lastSettledAt all the way to `now`.
  const settlementCursor = new Date(periodStart.getTime() + activeSeconds * 1000)
  const resources: HourlyResources = {
    cpu: account.instance.cpu,
    memory: account.instance.memory,
    disk: account.instance.disk
  }
  const pricing = getAccountPricing(account)
  const breakdown = calculateHourlyBreakdown(resources, pricing)
  const cpuAmount = calculateHourlyCost(breakdown.cpuAmount, activeSeconds)
  const memoryAmount = calculateHourlyCost(breakdown.memoryAmount, activeSeconds)
  const diskAmount = calculateHourlyCost(breakdown.diskAmount, activeSeconds)
  const actualAmount = cpuAmount.add(memoryAmount).add(diskAmount)
  const existingPrepaid = new Prisma.Decimal(account.prepaidBalance)
  const requiredAdditional = actualAmount.gt(existingPrepaid)
    ? ceilToQuantum(actualAmount.sub(existingPrepaid), new Prisma.Decimal(pricing.reserveQuantum))
    : zero()

  const user = await tx.user.findUnique({
    where: { id: account.instance.userId },
    select: { balance: true, hourlyReservedBalance: true }
  })
  if (!user) throw new Error(`Hourly billing user ${account.instance.userId} not found`)

  const reserveResult = await reserveForHourlyCharge(tx, {
    userId: account.instance.userId,
    instanceId,
    amount: requiredAdditional,
    balance: new Prisma.Decimal(user.balance),
    remark: `按小时计费追加冻结预付款：${serializeHourlyDecimal(requiredAdditional)}`
  })
  const combinedPrepaid = existingPrepaid.add(reserveResult.reserved)
  const paidAmount = Prisma.Decimal.min(combinedPrepaid, actualAmount)
  const unpaidAmount = actualAmount.sub(paidAmount)
  const shouldRecord = activeSeconds > 0 || requiredAdditional.gt(0) || actualAmount.gt(0)
  let consumeLogId: number | null = null
  if (shouldRecord) {
    const balanceBefore = new Prisma.Decimal(reserveResult.balanceAfter)
    consumeLogId = await createBalanceLog(tx, {
      userId: account.instance.userId,
      instanceId,
      type: 'hourly_consume',
      // Only settled money is counted as consumption. Any unpaid amount is
      // recorded as outstanding and added when the user resumes the instance.
      amount: paidAmount,
      balanceBefore,
      balanceAfter: balanceBefore,
      remark: `按小时计费实际费用：${serializeHourlyDecimal(actualAmount)}（从冻结预付款结算）`
    })
  }

  if (paidAmount.gt(0)) {
    await tx.user.update({
      where: { id: account.instance.userId },
      data: { hourlyReservedBalance: { decrement: paidAmount } }
    })
  }

  if (shouldRecord) {
    await tx.hourlyBillingRecord.create({
      data: {
        settlementKey: buildSettlementKey(account.id, account.version),
        accountId: account.id,
        instanceId,
        userId: account.instance.userId,
        packagePlanId: account.packagePlanId,
        pricingVersionId: account.pricingVersionId,
        periodStart,
        periodEnd: now,
        activeSeconds,
        cpu: resources.cpu,
        memory: resources.memory,
        disk: resources.disk,
        cpuAmount,
        memoryAmount,
        diskAmount,
        actualAmount,
        reserveAmount: reserveResult.reserved,
        status: unpaidAmount.gt(0) ? 'pending' : 'paid',
        balanceLogId: consumeLogId
      }
    })
  }

  await createHourlyHostingIncome(tx, instanceId, paidAmount)

  const suspended = unpaidAmount.gt(0)
  await tx.hourlyBillingAccount.update({
    where: { id: account.id },
    data: {
      lastSettledAt: settlementCursor,
      nextSettlementAt: suspended ? null : nowPlusInterval(now),
      prepaidBalance: combinedPrepaid.sub(paidAmount),
      totalCost: { increment: actualAmount },
      totalReserved: { increment: reserveResult.reserved },
      outstandingAmount: { increment: unpaidAmount },
      status: suspended ? 'suspended' : 'active',
      version: { increment: 1 }
    }
  })

  if (suspended) {
    await tx.instance.updateMany({
      where: { id: instanceId, status: 'running' },
      data: {
        status: 'suspended',
        suspendedAt: now,
        suspendedBy: null,
        suspendReason: HOURLY_SUSPEND_REASON,
        version: { increment: 1 }
      }
    })
  }

  return { instanceId, suspended, host: account.instance.host }
}

export async function activateHourlyBilling(instanceId: number): Promise<boolean> {
  return runSerializableTransaction(async tx => {
    const account = await tx.hourlyBillingAccount.findUnique({
      where: { instanceId },
      include: { packagePlan: true, pricingVersion: true, instance: true }
    })
    if (!account) return false
    await tx.$queryRaw(Prisma.sql`
      SELECT id
      FROM "hourly_billing_accounts"
      WHERE id = ${account.id}
      FOR UPDATE
    `)
    const lockedAccount = await tx.hourlyBillingAccount.findUnique({
      where: { id: account.id },
      include: { packagePlan: true, pricingVersion: true, instance: true }
    })
    if (!lockedAccount) return false
    if (lockedAccount.status === 'active') return lockedAccount.instance.status === 'running'
    if (lockedAccount.status === 'suspended') {
      const now = new Date()
      await tx.instance.updateMany({
        where: { id: instanceId, status: { in: ['running', 'stopped'] } },
        data: {
          status: 'suspended',
          suspendedAt: now,
          suspendedBy: null,
          suspendReason: HOURLY_SUSPEND_REASON,
          version: { increment: 1 }
        }
      })
      return false
    }
    if (lockedAccount.status !== 'paused') return false

    const now = new Date()
    const prepaid = new Prisma.Decimal(lockedAccount.prepaidBalance)
    const outstanding = new Prisma.Decimal(lockedAccount.outstandingAmount)
    if (outstanding.gt(0)) {
      await tx.hourlyBillingAccount.update({
        where: { id: lockedAccount.id },
        data: { status: 'suspended', nextSettlementAt: null, version: { increment: 1 } }
      })
      await tx.instance.updateMany({
        where: { id: instanceId, status: { in: ['running', 'stopped'] } },
        data: {
          status: 'suspended',
          suspendedAt: now,
          suspendedBy: null,
          suspendReason: HOURLY_SUSPEND_REASON,
          version: { increment: 1 }
        }
      })
      return false
    }
    let addedReserve = zero()
    if (prepaid.lte(0)) {
      const user = await tx.user.findUnique({ where: { id: lockedAccount.instance.userId }, select: { balance: true } })
      if (!user) throw new Error('USER_NOT_FOUND')
      const quantum = new Prisma.Decimal(getAccountPricing(lockedAccount).reserveQuantum)
      const reserveResult = await reserveForHourlyCharge(tx, {
        userId: lockedAccount.instance.userId,
        instanceId,
        amount: quantum,
        balance: new Prisma.Decimal(user.balance),
        remark: `启动按小时计费实例，冻结预付款：${serializeHourlyDecimal(quantum)}`
      })
      if (reserveResult.reserved.lt(quantum)) {
        await tx.hourlyBillingAccount.update({
          where: { id: lockedAccount.id },
          data: { status: 'suspended', nextSettlementAt: null, version: { increment: 1 } }
        })
        await tx.instance.updateMany({
          where: { id: instanceId, status: { in: ['running', 'stopped'] } },
          data: {
            status: 'suspended',
            suspendedAt: now,
            suspendedBy: null,
            suspendReason: HOURLY_SUSPEND_REASON,
            version: { increment: 1 }
          }
        })
        return false
      }
      addedReserve = reserveResult.reserved
    }

    await tx.hourlyBillingAccount.update({
      where: { id: lockedAccount.id },
      data: {
        status: 'active',
        lastSettledAt: now,
        nextSettlementAt: nowPlusInterval(now),
        prepaidBalance: addedReserve.gt(0) ? { increment: addedReserve } : undefined,
        totalReserved: addedReserve.gt(0) ? { increment: addedReserve } : undefined,
        version: { increment: 1 }
      }
    })
    return true
  })
}

export async function resumeHourlyBilling(instanceId: number, userId: number): Promise<void> {
  await runSerializableTransaction(async tx => {
    const account = await tx.hourlyBillingAccount.findUnique({
      where: { instanceId },
      include: { packagePlan: true, pricingVersion: true, instance: true }
    })
    if (!account || account.instance.userId !== userId) throw new Error('HOURLY_ACCOUNT_NOT_FOUND')
    await tx.$queryRaw(Prisma.sql`
      SELECT id
      FROM "hourly_billing_accounts"
      WHERE id = ${account.id}
      FOR UPDATE
    `)
    const lockedAccount = await tx.hourlyBillingAccount.findUnique({
      where: { id: account.id },
      include: { packagePlan: true, pricingVersion: true, instance: true }
    })
    if (!lockedAccount || lockedAccount.instance.userId !== userId) throw new Error('HOURLY_ACCOUNT_NOT_FOUND')
    if (lockedAccount.status !== 'suspended') return

    const outstanding = new Prisma.Decimal(lockedAccount.outstandingAmount)
    const quantum = new Prisma.Decimal(getAccountPricing(lockedAccount).reserveQuantum)
    const reserveAmount = ceilToQuantum(outstanding.add(quantum), quantum)
    const user = await tx.user.findUnique({ where: { id: userId }, select: { balance: true } })
    if (!user) throw new Error('USER_NOT_FOUND')
    const balanceBefore = new Prisma.Decimal(user.balance)
    const reserveResult = await reserveForHourlyCharge(tx, {
      userId,
      instanceId,
      amount: reserveAmount,
      balance: balanceBefore,
      remark: `恢复按小时计费实例，追加冻结预付款：${serializeHourlyDecimal(reserveAmount)}`
    })
    if (reserveResult.reserved.lt(reserveAmount)) throw new Error('BALANCE_INSUFFICIENT')

    const balanceAfterReserve = reserveResult.balanceAfter
    if (outstanding.gt(0)) {
      const consumeLogId = await createBalanceLog(tx, {
        userId,
        instanceId,
        type: 'hourly_consume',
        amount: outstanding,
        balanceBefore: balanceAfterReserve,
        balanceAfter: balanceAfterReserve,
        remark: `补缴按小时计费欠费：${serializeHourlyDecimal(outstanding)}`
      })
      await createHourlyHostingIncome(tx, instanceId, outstanding)
      await tx.user.update({ where: { id: userId }, data: { hourlyReservedBalance: { decrement: outstanding } } })
      await tx.hourlyBillingRecord.updateMany({
        where: { instanceId, status: 'pending' },
        data: { status: 'paid', balanceLogId: consumeLogId }
      })
    }
    await tx.hourlyBillingAccount.update({
      where: { id: lockedAccount.id },
      data: {
        status: 'paused',
        outstandingAmount: 0,
        prepaidBalance: reserveAmount.sub(outstanding),
        totalReserved: { increment: reserveAmount },
        lastSettledAt: new Date(),
        nextSettlementAt: null,
        version: { increment: 1 }
      }
    })
  })
}

export async function settleHourlyInstance(instanceId: number, now = new Date(), options: { force?: boolean } = {}): Promise<SettlementResult> {
  return runSerializableTransaction(tx => settleInTransaction(tx, instanceId, now, options))
}

export async function pauseHourlyBilling(instanceId: number, now = new Date()): Promise<SettlementResult> {
  return runSerializableTransaction(async tx => {
    const result = await settleInTransaction(tx, instanceId, now, { force: true })
    const account = await tx.hourlyBillingAccount.findUnique({ where: { instanceId }, include: { instance: true } })
    if (!account || account.status === 'closed') return result

    const prepaid = new Prisma.Decimal(account.prepaidBalance)
    if (prepaid.gt(0)) {
      const user = await tx.user.findUnique({ where: { id: account.instance.userId }, select: { balance: true } }).catch(() => null)
      if (!user) throw new Error('Hourly billing user not found')
      const before = new Prisma.Decimal(user.balance)
      const after = before.add(prepaid)
      await tx.user.update({
        where: { id: account.instance.userId },
        data: {
          balance: { increment: prepaid },
          hourlyReservedBalance: { decrement: prepaid }
        }
      })
      await createBalanceLog(tx, {
        userId: account.instance.userId,
        instanceId,
        type: 'hourly_release',
        amount: prepaid,
        balanceBefore: before,
        balanceAfter: after,
        remark: `按小时计费实例停止，退回冻结预付款：${serializeHourlyDecimal(prepaid)}`
      })
    }
    await tx.hourlyBillingAccount.update({
      where: { id: account.id },
      data: { status: 'paused', nextSettlementAt: null, prepaidBalance: 0, totalReleased: { increment: prepaid }, version: { increment: 1 } }
    })
    return result
  })
}

export async function closeHourlyBilling(instanceId: number, now = new Date()): Promise<SettlementResult> {
  return runSerializableTransaction(async tx => {
    const result = await settleInTransaction(tx, instanceId, now, { force: true })
    const account = await tx.hourlyBillingAccount.findUnique({
      where: { instanceId },
      include: { instance: true }
    })
    if (!account || account.status === 'closed') return result
    const prepaid = new Prisma.Decimal(account.prepaidBalance)
    if (prepaid.gt(0)) {
      const user = await tx.user.findUnique({ where: { id: account.instance.userId }, select: { balance: true } })
      if (!user) throw new Error('Hourly billing user not found')
      const before = new Prisma.Decimal(user.balance)
      await tx.user.update({
        where: { id: account.instance.userId },
        data: {
          balance: { increment: prepaid },
          hourlyReservedBalance: { decrement: prepaid }
        }
      })
      await createBalanceLog(tx, {
        userId: account.instance.userId,
        instanceId,
        type: 'hourly_release',
        amount: prepaid,
        balanceBefore: before,
        balanceAfter: before.add(prepaid),
        remark: `按小时计费实例销毁，退回冻结预付款：${serializeHourlyDecimal(prepaid)}`
      })
    }
    await tx.hourlyBillingAccount.update({
      where: { id: account.id },
      data: { status: 'closed', nextSettlementAt: null, prepaidBalance: 0, totalReleased: { increment: prepaid }, version: { increment: 1 } }
    })
    return result
  })
}

export async function runHourlyBillingJob(): Promise<void> {
  const now = new Date()
  const suspendedAccounts = await prisma.hourlyBillingAccount.findMany({
    where: {
      status: 'suspended',
      instance: { status: 'suspended', suspendReason: HOURLY_SUSPEND_REASON }
    },
    select: {
      instanceId: true,
      instance: {
        select: {
          incusId: true,
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
      }
    }
  })
  for (const account of suspendedAccounts) {
    try {
      const client = await getIncusClient(account.instance.host)
      await stopInstance(client, account.instance.incusId, true)
    } catch (error) {
      console.error(`[HourlyBilling] failed to retry physical stop for instance ${account.instanceId}:`, error)
    }
  }

  const staleAccounts = await prisma.hourlyBillingAccount.findMany({
    where: { status: 'active', instance: { status: { not: 'running' } } },
    select: { instanceId: true }
  })
  for (const account of staleAccounts) {
    try {
      await pauseHourlyBilling(account.instanceId, now)
    } catch (error) {
      console.error(`[HourlyBilling] failed to close stale runtime for instance ${account.instanceId}:`, error)
    }
  }

  const accounts = await prisma.hourlyBillingAccount.findMany({
    where: {
      status: 'active',
      instance: { status: 'running' },
      OR: [{ nextSettlementAt: null }, { nextSettlementAt: { lte: now } }]
    },
    select: { instanceId: true }
  })

  for (const account of accounts) {
    try {
      const result = await settleHourlyInstance(account.instanceId, now)
      if (result.suspended && result.host) {
        try {
          const client = await getIncusClient(result.host)
          const instance = await prisma.instance.findUnique({ where: { id: account.instanceId }, select: { incusId: true } })
          if (instance) await stopInstance(client, instance.incusId, true)
        } catch (error) {
          console.error(`[HourlyBilling] failed to stop suspended instance ${account.instanceId}:`, error)
        }
      }
    } catch (error) {
      console.error(`[HourlyBilling] failed to settle instance ${account.instanceId}:`, error)
    }
  }
}

export function startHourlyBillingScheduler(): void {
  schedule('*/5 * * * *', () => runHourlyBillingJob().catch(error => console.error('[HourlyBilling] scheduler failed:', error)))
  void runHourlyBillingJob().catch(error => console.error('[HourlyBilling] initial reconciliation failed:', error))
  console.log('[HourlyBilling] Scheduler started (5 minute settlement interval)')
}

export { HOURLY_SUSPEND_REASON }
