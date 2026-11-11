import type { Host } from '../types/database.js'
import { throwIfRemoteOperationAborted } from './remote-operation-abort.js'

type Site = { id: number; instanceId: number; hostId: number; domain: string }
type Dependencies = {
  listSites(instanceId: number): Promise<Site[]>
  getSite(id: number): Promise<Site | null>
  deleteSite(host: Host, domain: string): Promise<void>
  withDomainLock(domain: string, operation: () => Promise<void>): Promise<{ acquired: boolean }>
}

export function taskCaddyConfiguration(host: Host): { host: string; port: number; username: string; password: string } {
  const address = host.nat_public_ip || host.ip_address
  if (!host.caddy_enabled || !address || !host.caddy_username || !host.caddy_password) {
    throw new Error('Caddy site removal cannot be confirmed')
  }
  return { host: address, port: host.caddy_port || 8444, username: host.caddy_username, password: host.caddy_password }
}

async function defaultDependencies(): Promise<Dependencies> {
  const [{ prisma }, { createCaddyClient }, { withDomainRemoteOperationLock }] = await Promise.all([
    import('../db/prisma.js'), import('../lib/caddy-client.js'), import('./instance-remote-operation-lock.js')
  ])
  return {
    listSites: instanceId => prisma.proxySite.findMany({ where: { instanceId } }),
    getSite: id => prisma.proxySite.findUnique({ where: { id } }),
    async deleteSite(host, domain) {
      await createCaddyClient(taskCaddyConfiguration(host)).deleteSite(domain)
    },
    withDomainLock: (domain, operation) => withDomainRemoteOperationLock(domain, operation)
  }
}

/** Caller must hold the instance remote-operation lock until its database
 * cleanup/switch is committed. Rows stay reserved until all remote routes
 * are removed, so another instance cannot acquire an in-flight domain. */
export async function removeTaskProxyRoutes(instanceId: number, host: Host, providedDependencies?: Dependencies): Promise<void> {
  const deps = providedDependencies ?? await defaultDependencies()
  const sites = await deps.listSites(instanceId)
  for (const site of sites) {
    const locked = await deps.withDomainLock(site.domain, async () => {
      const current = await deps.getSite(site.id)
      if (!current || current.instanceId !== instanceId || current.hostId !== host.id || current.domain !== site.domain) {
        throw new Error('Caddy site identity changed during instance task')
      }
      await deps.deleteSite(host, current.domain)
    })
    if (!locked.acquired) throw new Error('Caddy domain operation is in progress')
    throwIfRemoteOperationAborted()
  }
}
