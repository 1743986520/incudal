const LAST_CHUNK_RELOAD_KEY = 'incudal.chunk-reload-at'
const CHUNK_RELOAD_COOLDOWN_MS = 60_000

/** Reload once for a stale deploy chunk, never in an unbounded loop. */
export function reloadOnceForChunkError(): void {
  const now = Date.now()
  try {
    const previous = Number(sessionStorage.getItem(LAST_CHUNK_RELOAD_KEY) || 0)
    if (now - previous < CHUNK_RELOAD_COOLDOWN_MS) return
    sessionStorage.setItem(LAST_CHUNK_RELOAD_KEY, String(now))
  } catch {
    // If storage is unavailable, do not risk a reload loop.
    return
  }
  window.location.reload()
}
