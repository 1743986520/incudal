export const HOST_RESOURCE_INSTANCE_STATUSES = ['creating', 'running', 'stopped', 'suspended'] as const

export interface HostResourceAllocation {
  status: string
  cpu: number
  memory: number
  disk?: number
}

export function calculateAllocatedHostResources(instances: HostResourceAllocation[]): {
  cpuUsed: number
  memoryUsed: number
  diskUsed: number
} {
  const allocatedStatuses = new Set<string>(HOST_RESOURCE_INSTANCE_STATUSES)

  return instances.reduce((usage, instance) => {
    if (!allocatedStatuses.has(instance.status)) return usage
    usage.cpuUsed += instance.cpu
    usage.memoryUsed += instance.memory
    usage.diskUsed += instance.disk ?? 0
    return usage
  }, { cpuUsed: 0, memoryUsed: 0, diskUsed: 0 })
}
