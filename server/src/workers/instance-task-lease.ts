import type { InstanceTaskStatus, Prisma } from '@prisma/client'

export const INSTANCE_TASK_LEASE_MS = 2 * 60 * 1000
export const INSTANCE_TASK_HEARTBEAT_MS = 30 * 1000

interface RecoverableTask {
  status: 'PENDING' | 'PROCESSING'
  createdAt: Date
  startedAt: Date | null
  leaseExpiresAt: Date | null
}

interface InstanceTaskUpdateClient {
  instanceTask: {
    updateMany(args: unknown): Promise<{ count: number }>
  }
}

export const INSTANCE_TASK_ORPHANED_PROGRESS = 'orphaned'

export class InstanceTaskLeaseLostError extends Error {
  constructor() {
    super('任务执行租约已失效')
    this.name = 'InstanceTaskLeaseLostError'
  }
}

function activeExecutionWhere(taskId: number, executionToken: string, now: Date) {
  return {
    id: taskId,
    status: 'PROCESSING' as const,
    executionToken,
    leaseExpiresAt: { gt: now }
  }
}

export function canRecoverInstanceTask(
  task: RecoverableTask,
  now: Date,
  force: boolean
): boolean {
  if (task.status === 'PROCESSING') {
    // Lease expiry alone is not proof that the old worker stopped. Only an
    // administrator's explicit force recovery may release an expired orphan.
    return force && (task.leaseExpiresAt === null || task.leaseExpiresAt.getTime() <= now.getTime())
  }

  return force || now.getTime() - task.createdAt.getTime() >= 15 * 60 * 1000
}

export async function hasActiveInstanceTaskLease(
  client: { instanceTask: { count(args: unknown): Promise<number> } },
  taskId: number,
  executionToken: string,
  now = new Date()
): Promise<boolean> {
  return (await client.instanceTask.count({
    where: activeExecutionWhere(taskId, executionToken, now)
  })) === 1
}

export async function renewInstanceTaskLease(
  client: InstanceTaskUpdateClient,
  taskId: number,
  executionToken: string,
  now = new Date()
): Promise<boolean> {
  const result = await client.instanceTask.updateMany({
    where: activeExecutionWhere(taskId, executionToken, now),
    data: { leaseExpiresAt: new Date(now.getTime() + INSTANCE_TASK_LEASE_MS) }
  })
  return result.count === 1
}

export async function updateInstanceTaskExecutionData(
  client: InstanceTaskUpdateClient,
  taskId: number,
  executionToken: string,
  data: Prisma.InstanceTaskUpdateManyMutationInput,
  now = new Date()
): Promise<boolean> {
  const result = await client.instanceTask.updateMany({
    where: activeExecutionWhere(taskId, executionToken, now),
    data
  })
  return result.count === 1
}

export async function updateInstanceTaskExecutionProgress(
  client: InstanceTaskUpdateClient,
  taskId: number,
  executionToken: string,
  progress: string,
  now = new Date()
): Promise<boolean> {
  return updateInstanceTaskExecutionData(client, taskId, executionToken, { progress }, now)
}

export async function finishInstanceTaskExecution(
  client: InstanceTaskUpdateClient,
  taskId: number,
  executionToken: string,
  status: Extract<InstanceTaskStatus, 'COMPLETED' | 'FAILED'>,
  updates: Prisma.InstanceTaskUpdateManyMutationInput,
  now = new Date()
): Promise<boolean> {
  const result = await client.instanceTask.updateMany({
    where: activeExecutionWhere(taskId, executionToken, now),
    data: {
      status,
      ...updates,
      leaseExpiresAt: null,
      executionToken: null
    }
  })
  return result.count === 1
}
