import { prisma } from '../db/prisma.js'
import { withInstanceRemoteOperationLock } from './instance-remote-operation-lock.js'

/**
 * Legacy synchronous deletion paths cannot safely remove Caddy sites. Fail
 * closed before claiming deletion. Holding the same session lock as site
 * creation until the claim commits prevents a check-then-create race.
 */
export async function claimLegacyDeletionWithoutProxySites(
  instanceId: number,
  claim: () => Promise<boolean>
): Promise<'busy' | 'sites' | 'claimed' | 'conflict'> {
  const result = await withInstanceRemoteOperationLock(instanceId, async () => {
    if (await prisma.proxySite.count({ where: { instanceId } }) > 0) return 'sites' as const
    return await claim() ? 'claimed' as const : 'conflict' as const
  })
  return result.acquired ? result.value : 'busy'
}
