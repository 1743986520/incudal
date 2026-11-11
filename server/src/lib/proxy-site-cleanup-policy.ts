type CurrentSite = {
  id: number
  instanceId: number
  hostId: number
  domain: string
  updatedAt: Date
  status: string
  enabled: boolean
  instance: { status: string; hostId?: number; ipv4?: string | null }
}

/** A transfer may only remove the exact, unchanged site it observed before
 * transferring ownership. New-owner edits and pending deletions win. */
export function canCleanupTransferredSite(
  current: CurrentSite | null,
  expected: { id: number; instanceId: number; hostId: number | undefined; domain: string; updatedAt: string }
): boolean {
  return !!current && current.id === expected.id && current.instanceId === expected.instanceId &&
    current.hostId === expected.hostId && current.domain === expected.domain &&
    current.updatedAt.toISOString() === expected.updatedAt &&
    current.instance.status !== 'deleted' && current.instance.status !== 'deleting'
}

/** Stale status-sync results must not recreate routes for deleted, moved or
 * subsequently reconfigured sites. */
export function canUpdateSyncedSite(
  current: CurrentSite | null,
  expected: { id: number; instanceId: number; hostId: number; domain: string; ipv4: string }
): boolean {
  return !!current && current.id === expected.id && current.instanceId === expected.instanceId &&
    current.hostId === expected.hostId && current.domain === expected.domain &&
    current.instance.hostId === expected.hostId && current.instance.ipv4 === expected.ipv4 &&
    current.instance.status !== 'deleted' && current.instance.status !== 'deleting' &&
    current.status === 'active' && current.enabled
}
