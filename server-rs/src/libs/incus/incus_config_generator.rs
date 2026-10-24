//! Incus config generator entry point.
//! Port of lib/incus-config-generator.ts: routes to the container or VM
//! generator based on the instance type.

use crate::libs::incus::incus_config_container::{
    generate_container_config, generate_random_password, IncusConfigMetaData, IncusConfigParams,
    IncusConfigResult,
};
use crate::libs::incus::incus_config_vm::generate_vm_config;

/// SSH port is fixed at 22.
pub const SSH_PORT: i64 = 22;

/// Mirrors `generateIncusConfig`: route by instance type.
pub fn generate_incus_config(params: &IncusConfigParams) -> Result<IncusConfigResult, String> {
    // VM route.
    if params.instance_type.as_deref() == Some("virtual-machine") {
        let vm_result = generate_vm_config(params);
        return Ok(IncusConfigResult {
            config_payload: vm_result.config_payload,
            meta_data: Some(IncusConfigMetaData {
                ssh_port: SSH_PORT,
                root_password: params.root_password.clone(),
                os_family: "linux".to_string(),
                image_alias: params.image_alias.clone(),
                instance_type: "virtual-machine".to_string(),
                ip_address: params
                    .network
                    .as_ref()
                    .and_then(|n| n.ip_address.clone())
                    .unwrap_or_else(|| "dhcp".to_string()),
            }),
        });
    }

    // Container route.
    generate_container_config(params)
}

/// Mirrors the re-exported `generateRandomPassword` (default length 16).
pub fn generate_random_password_default() -> String {
    generate_random_password(16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::libs::incus::incus_config_container::StaticNetworkConfig;

    #[test]
    fn routes_by_instance_type() {
        let params = IncusConfigParams {
            instance_name: "srv-1".to_string(),
            image_alias: "debian/12/cloud".to_string(),
            root_password: "secret-123".to_string(),
            instance_type: Some("virtual-machine".to_string()),
            network: Some(StaticNetworkConfig {
                ip_address: Some("10.10.2.5/22".to_string()),
                gateway: Some("10.10.0.1".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let result = generate_incus_config(&params).expect("vm config");
        let meta = result.meta_data.as_ref().expect("vm metadata");
        assert_eq!(meta.instance_type, "virtual-machine");
        assert_eq!(meta.os_family, "linux");
        assert_eq!(meta.ssh_port, 22);
        assert_eq!(meta.ip_address, "10.10.2.5/22");
        assert!(result.config_payload.user_data.starts_with("#cloud-config"));
        assert!(result.config_payload.network_config.contains("macaddress:"));
    }

    #[test]
    fn container_route_reports_container_metadata() {
        let params = IncusConfigParams {
            instance_name: "ct-1".to_string(),
            image_alias: "ubuntu/22.04/cloud".to_string(),
            root_password: "secret-123".to_string(),
            ..Default::default()
        };
        let result = generate_incus_config(&params).expect("container config");
        let meta = result.meta_data.as_ref().expect("container metadata");
        assert_eq!(meta.instance_type, "container");
        assert_eq!(meta.os_family, "ubuntu");
        assert_eq!(meta.ip_address, "dhcp");
    }

    #[test]
    fn missing_params_fail_like_ts() {
        let params = IncusConfigParams {
            instance_name: "ct-2".to_string(),
            image_alias: String::new(),
            root_password: String::new(),
            ..Default::default()
        };
        let err = generate_incus_config(&params).expect_err("must fail");
        assert_eq!(err, "Missing params");
    }
}
