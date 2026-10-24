//! Host resource accounting constants.
//! Port of lib/host-resource-usage.ts.

/// Instance statuses counted toward a host's allocated resources
/// (`HOST_RESOURCE_INSTANCE_STATUSES`).
pub const HOST_RESOURCE_INSTANCE_STATUSES: &[&str] = &[
    "creating",
    "running",
    "stopped",
    "suspended",
];

/// The same list rendered as a SQL `IN (...)` fragment (Prisma `_sum` queries
/// in db/hosts.ts aggregate over exactly these statuses).
pub const HOST_RESOURCE_INSTANCE_STATUSES_SQL: &str =
    "('creating','running','stopped','suspended')";

/// One instance's allocation as seen by calculateAllocatedHostResources.
pub struct HostResourceAllocation<'a> {
    pub status: &'a str,
    pub cpu: i64,
    pub memory: i64,
    pub disk: i64,
}

/// Mirrors calculateAllocatedHostResources: sums cpu/memory/disk over the
/// allocated statuses only.
pub fn calculate_allocated_host_resources(instances: &[HostResourceAllocation]) -> (i64, i64, i64) {
    let mut cpu_used = 0i64;
    let mut memory_used = 0i64;
    let mut disk_used = 0i64;
    for instance in instances {
        if !HOST_RESOURCE_INSTANCE_STATUSES.contains(&instance.status) {
            continue;
        }
        cpu_used += instance.cpu;
        memory_used += instance.memory;
        disk_used += instance.disk;
    }
    (cpu_used, memory_used, disk_used)
}
