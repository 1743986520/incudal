//! Deterministic VM NIC MAC addresses.
//! Port of lib/vm-network-identifiers.ts.

use sha2::{Digest, Sha256};

/// Mirrors `VmNicMacs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmNicMacs {
    pub eth0: String,
    pub eth1: String,
}

fn format_mac(bytes: [u8; 6]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn generate_vm_nic_mac(seed: &str, nic_label: &str) -> String {
    let hash = Sha256::digest(format!("incudal-vm-nic:{seed}:{nic_label}").as_bytes());
    format_mac([0x02, hash[0], hash[1], hash[2], hash[3], hash[4]])
}

/// Mirrors `generateVmNicMacs`: locally administered (02:...) MACs derived
/// from a sha256 of the seed, so VM guest interfaces can be recognized
/// regardless of distro-specific interface naming.
pub fn generate_vm_nic_macs(seed: &str) -> VmNicMacs {
    VmNicMacs {
        eth0: generate_vm_nic_mac(seed, "eth0"),
        eth1: generate_vm_nic_mac(seed, "eth1"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macs_are_stable_locally_administered_and_label_separated() {
        let macs = generate_vm_nic_macs("vm-1");
        assert!(macs.eth0.starts_with("02:"));
        assert!(macs.eth1.starts_with("02:"));
        assert_ne!(macs.eth0, macs.eth1);
        assert_eq!(macs, generate_vm_nic_macs("vm-1"));
        assert_eq!(macs.eth0.len(), 17);
        let second = generate_vm_nic_macs("vm-2");
        assert_ne!(macs.eth0, second.eth0);
    }
}
