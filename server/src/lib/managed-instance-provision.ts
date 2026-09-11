import { prisma } from '../db/prisma.js'
import { buildInstanceConfig, createInstance, getIncusClient, getInstance, getInstanceState, startInstance } from '../lib/incus/index.js'
import {
  persistResolvedInstanceNetworkAddresses,
  resolveInstanceNetworkAddresses,
  type ResolvedInstanceNetworkAddresses
} from './instance-network-sync.js'
import type { Host } from '../types/database.js'

export interface ManagedInstanceProvisionConfig {
  name: string
  image: string
  cpu: number
  memory: number
  disk: number
  cloudInitConfig?: Record<string, string>
  networkMode: 'nat' | 'nat_ipv6' | 'nat_ipv6_nat' | 'ipv6_only' | 'ipv6_nat'
  nested?: boolean
  privileged?: boolean
  portLimit?: number
  instanceType?: 'container' | 'vm'
  sshPort?: number | null
  storagePool?: string | null
  ipv4Address?: string | null
  ipv6Address?: string | null
  ipv6Gateway?: string | null
  hostInterface?: string | null
  limitsRead?: string | null
  limitsWrite?: string | null
  limitsReadIops?: number | null
  limitsWriteIops?: number | null
  limitsIngress?: string | null
  limitsEgress?: string | null
  limitsProcesses?: number | null
  limitsCpuPriority?: number | null
  bootAutostart?: boolean | null
  bootAutostartPriority?: number | null
  bootAutostartDelay?: number | null
  bootHostShutdownTimeout?: number | null
}

export async function provisionManagedInstanceAsync(
  instanceId: number,
  host: Host,
  config: ManagedInstanceProvisionConfig
): Promise<void> {
  try {
    console.log(`\n[Managed Provisioning] ===== start =====`)
    console.log(`[Managed Provisioning] instanceId=${instanceId}, name=${config.name}, host=${host.name}`)

    const client = await getIncusClient(host)
    const ipv6Config = config.ipv6Address ? { primaryIp: config.ipv6Address } : null

    const incusConfig = buildInstanceConfig({
      name: config.name,
      image: config.image,
      cpu: config.cpu,
      memory: config.memory,
      disk: config.disk,
      sshKey: '',
      password: '',
      cloudInitConfig: config.cloudInitConfig as { 'user.user-data': string } | undefined,
      networkMode: config.networkMode,
      nested: config.nested || false,
      privileged: config.privileged || false,
      instanceType: config.instanceType || 'container',
      storagePool: config.storagePool || 'default',
      ipv4Address: config.ipv4Address,
      ipv6Config,
      hostInterface: config.hostInterface || 'eth0',
      ipv6Address: config.ipv6Address,
      ipv6Gateway: config.ipv6Gateway,
      limitsRead: config.limitsRead,
      limitsWrite: config.limitsWrite,
      limitsReadIops: config.limitsReadIops,
      limitsWriteIops: config.limitsWriteIops,
      limitsIngress: config.limitsIngress,
      limitsEgress: config.limitsEgress,
      limitsProcesses: config.limitsProcesses,
      limitsCpuPriority: config.limitsCpuPriority,
      bootAutostart: config.bootAutostart,
      bootAutostartPriority: config.bootAutostartPriority,
      bootAutostartDelay: config.bootAutostartDelay,
      bootHostShutdownTimeout: config.bootHostShutdownTimeout
    })

    await createInstance(client, incusConfig)

    let ready = false
    for (let i = 0; i < 60; i++) {
      await new Promise(resolve => setTimeout(resolve, 2000))
      try {
        const stateResp = await getInstanceState(client, config.name) as { status?: string }
        if (stateResp?.status) {
          ready = true
          break
        }
      } catch {
        // keep waiting
      }
    }

    if (!ready) {
      throw new Error('Instance creation timed out')
    }

    await startInstance(client, config.name)

    for (let i = 0; i < 30; i++) {
      await new Promise(resolve => setTimeout(resolve, 2000))
      try {
        const stateResp = await getInstanceState(client, config.name) as { status?: string }
        if (stateResp?.status === 'Running') {
          break
        }
      } catch {
        // keep waiting
      }
    }

    const storedInstance = await prisma.instance.findUniqueOrThrow({
      where: { id: instanceId },
      select: {
        id: true,
        name: true,
        hostId: true,
        networkMode: true,
        ipv4: true,
        ipv6: true
      }
    })

    let resolvedNetwork: ResolvedInstanceNetworkAddresses = {
      ipv4: config.ipv4Address || storedInstance.ipv4 || null,
      ipv6: config.ipv6Address || storedInstance.ipv6 || null,
      ipv4Device: 'eth0',
      ipv6Device: 'eth1',
      configuredIpv6: config.ipv6Address || null,
      observedIpv6: null
    }

    try {
      const [incusInstance, stateResp] = await Promise.all([
        getInstance(client, config.name),
        getInstanceState(client, config.name)
      ]) as [Awaited<ReturnType<typeof getInstance>>, {
        network?: Record<string, { addresses?: Array<{ family: string; scope: string; address: string }> }>
      }]
      resolvedNetwork = resolveInstanceNetworkAddresses(
        {
          ...storedInstance,
          ipv4: config.ipv4Address || storedInstance.ipv4,
          ipv6: config.ipv6Address || storedInstance.ipv6
        },
        incusInstance,
        stateResp
      )
    } catch {
      // keep pre-allocated addresses
    }

    await persistResolvedInstanceNetworkAddresses(storedInstance, resolvedNetwork)

    await prisma.instance.update({
      where: { id: instanceId },
      data: {
        status: 'running',
        storagePoolName: config.storagePool || 'default'
      }
    })
  } catch (error) {
    console.error(`[Managed Provisioning] instance ${instanceId} failed:`, error)

    await prisma.instance.update({
      where: { id: instanceId },
      data: { status: 'error' }
    }).catch(() => {})

    throw error
  }
}
