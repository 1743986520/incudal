import { AsyncLocalStorage } from 'node:async_hooks'

export interface IncusExecutionGuard {
  signal: AbortSignal
  assertActive(): Promise<void>
}

const guardStorage = new AsyncLocalStorage<IncusExecutionGuard>()

export function runWithIncusExecutionGuard<T>(
  guard: IncusExecutionGuard,
  callback: () => Promise<T>
): Promise<T> {
  return guardStorage.run(guard, callback)
}

export function getIncusExecutionGuard(): IncusExecutionGuard | undefined {
  return guardStorage.getStore()
}

export function throwIfIncusExecutionAborted(): void {
  const guard = getIncusExecutionGuard()
  if (guard?.signal.aborted) {
    throw guard.signal.reason instanceof Error
      ? guard.signal.reason
      : new Error('Instance task execution lease is no longer owned')
  }
}
