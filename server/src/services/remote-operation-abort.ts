import { AsyncLocalStorage } from 'node:async_hooks'

const signals = new AsyncLocalStorage<AbortSignal>()

/** Best-effort cancellation only: a request already accepted by a remote
 * service can continue after its HTTP connection is aborted. */
export function runWithRemoteOperationAbortSignal<T>(signal: AbortSignal, operation: () => Promise<T>): Promise<T> {
  const parent = signals.getStore()
  const combined = parent ? AbortSignal.any([parent, signal]) : signal
  return signals.run(combined, async () => {
    combined.throwIfAborted()
    return operation()
  })
}

export function getRemoteOperationAbortSignal(): AbortSignal | undefined {
  return signals.getStore()
}

export function throwIfRemoteOperationAborted(): void {
  signals.getStore()?.throwIfAborted()
}
