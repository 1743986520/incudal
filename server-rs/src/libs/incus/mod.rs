//! Incus host client layer.
//! Rust port of the whole `server/src/lib/incus/` directory plus the
//! instance-provisioning/networking helpers it depends on
//! (`incus-config-generator*.ts`, `network-payload-builder.ts`,
//! `ip-calculator.ts`, `network-address.ts`, `instance-swap.ts`,
//! `vm-network-identifiers.ts`, `cloud-init-status.ts`,
//! `managed-instance-provision.ts`).
//!
//! This is a library layer: routes own DB/API error translation, so failures
//! surface as [`incus_client::IncusError`] (with `IncusError::Api` carrying the
//! Incus status code, method, and path) instead of `ApiError`.

// Library layer: most of the surface is consumed by route modules that will be
// ported later; keep unused items silent in the meantime.
#![allow(dead_code)]
#![allow(unused_imports)]

pub mod cloud_init_status;
pub mod host_health;
pub mod incus_backups;
pub mod incus_client;
pub mod incus_config_container;
pub mod incus_config_generator;
pub mod incus_config_vm;
pub mod incus_execution_guard;
pub mod incus_images;
pub mod incus_instances;
pub mod incus_network;
pub mod incus_pool;
pub mod incus_restore;
pub mod incus_snapshots;
pub mod incus_storage;
pub mod incus_tls;
pub mod incus_traffic;
pub mod incus_utils;
pub mod instance_swap;
pub mod ip_calculator;
pub mod managed_instance_provision;
pub mod network_address;
pub mod network_payload_builder;
pub mod vm_network_identifiers;

// ==================== barrel exports (mirrors incus/index.ts) ====================

// 主类 (main client)
pub use incus_client::{IncusClient, IncusClientOptions, IncusError, is_incus_not_found};

// 实例管理 (instances)
pub use incus_instances::{
    build_instance_config, create_instance, delete_instance, ensure_instance_deleted, exec,
    exec_with_output, freeze_instance, get_console_websocket_url, get_instance, get_instance_state,
    is_missing_vm_nvram_error, list_instances, patch_instance_resources, rebuild_instance,
    restart_instance, start_instance, start_instance_with_nvram_repair, stop_instance,
    unfreeze_instance, update_instance, update_instance_ipv6_addresses, wait_for_created_instance,
    wait_for_provisioning_instance_resolution, BusyRetryOptions, IncusExecCommand, IncusExecOutput,
    IncusInstance, IncusOperation, InstanceResourcePatch, ProvisionStatus,
    ProvisioningInstanceResolution, RebuildImageSource,
};

// 镜像管理 (images)
pub use incus_images::{
    create_image_alias, delete_image, delete_image_alias, get_image, get_image_alias,
    image_exists_by_alias, list_image_aliases, list_images, pull_image,
    pull_image_with_long_timeout, update_image_alias, IncusImage, IncusImageAlias,
    PullImageOptions,
};

// 快照管理 (snapshots)
pub use incus_snapshots::{
    create_snapshot, delete_snapshot, get_snapshot, list_snapshots, rename_snapshot,
    restore_snapshot, IncusSnapshot,
};

// 备份管理 (backups)
pub use incus_backups::{
    create_backup, delete_backup, get_backup, get_backup_export_stream, get_backup_export_url,
    restore_from_backup, CreateBackupOptions, IncusBackup,
};

// 网络管理 (networks)
pub use incus_network::{get_network, list_networks, IncusNetwork};

// 存储管理 (storage pools)
pub use incus_storage::{
    create_storage_pool, delete_storage_pool, get_storage_pool, get_storage_pool_resources,
    list_storage_pools, update_storage_pool, CreateStoragePoolOptions, IncusStoragePool,
    UpdateStoragePoolOptions,
};

// 工具函数 (utils)
pub use incus_utils::{
    allowance_to_cores, is_valid_allowance, map_instance_status, normalize_allowance,
    wait_for_operation, wait_for_operation_long,
};

// 连接池管理 (pool — the TS module globals become the Arc-shared IncusClientPool)
pub use incus_pool::{IncusClientPool, PoolHost, PoolStatusEntry};
pub use host_health::{
    clear_host_health, get_all_host_health, get_health_summary, get_host_health,
    get_unhealthy_hosts, is_host_healthy, record_host_error, record_host_success, HealthSummary,
    HostHealth,
};

// 流量管理 (traffic)
pub use incus_traffic::{
    apply_throttle, get_traffic_counters, get_traffic_counters_from_state, is_throttled,
    restore_bandwidth, NetworkCounters, THROTTLE_BANDWIDTH,
};

// 恢复管理 (restore — only the non-conflicting exports, like the TS index)
pub use incus_restore::{
    generate_temp_instance_name, instance_exists, rename_instance, restore_from_stream,
};

// TLS/连接入口 (tls)
pub use incus_tls::{
    assert_allowed_host_url, assert_certificate_matches_fingerprint,
    assert_server_managed_certificate_paths, build_incus_tls_connect_options,
    capture_incus_server_certificate, certificate_fingerprint, is_public_host_address,
    normalize_certificate_pem, panel_certificate_paths, resolve_incus_target,
    trust_ca_path_from_environment, ResolvedIncusTarget, TlsConnectOptions,
};

// 执行守卫 (execution guard)
pub use incus_execution_guard::{
    get_incus_execution_guard, run_with_incus_execution_guard, throw_if_incus_execution_aborted,
    IncusExecutionGuard,
};

// 配置生成器 (config generators)
pub use incus_config_container::{
    detect_os_info, generate_container_config, generate_random_password, IncusConfigMetaData,
    IncusConfigParams, IncusConfigPayload, IncusConfigResult, OsFamily, StaticNetworkConfig,
};
pub use incus_config_generator::{generate_incus_config, SSH_PORT};

// 网络构建与 IP 计算 (payload builder / calculators)
pub use ip_calculator::{
    calculate_ipv6, generate_random_ipv4, generate_random_ipv6, generate_random_subnet,
    get_ipv6_offset, is_ipv4_in_range, is_ipv6_in_subnet, is_strict_valid_ipv6,
    is_valid_ipv6_subnet, Ipv4Config,
};
pub use network_address::{
    extract_host_address_from_url, format_host_for_listen, format_host_for_url,
    get_address_family, get_dns_record_type, is_ip_literal, is_ipv6_address,
    normalize_ipv4_address, normalize_network_host, select_bindable_ipv4_listen_address,
    AddressFamily, DnsRecordType,
};
pub use network_payload_builder::{
    build_network_devices, generate_cloud_init_network_config,
    generate_cloud_init_network_config_legacy, has_ipv6_support, remove_instance_ipv6,
    sync_instance_network, Ipv6Config, NetworkMode,
};
pub use instance_swap::{
    format_incus_swap_limit, resolve_effective_swap_size, resolve_incus_swap_value,
    should_sync_instance_swap_size_with_plan,
};
pub use vm_network_identifiers::{generate_vm_nic_macs, VmNicMacs};

// 云初始化与开通过程 (cloud-init / provisioning)
pub use cloud_init_status::{
    detect_cloud_init_status, get_cached_cloud_init_status, persist_cloud_init_status,
    reset_instance_cloud_init_state, CloudInitStatusResponse,
};
pub use managed_instance_provision::{
    claim_creating_instance_for_cleanup, cleanup_and_settle_failed_provision,
    mark_creating_instance_provisioned, provision_managed_instance_async,
    resolve_instance_network_addresses, FailedProvisionCleanupResult,
    FailedProvisionResourceRollback, ManagedInstanceProvisionConfig,
    ResolvedInstanceNetworkAddresses,
};
