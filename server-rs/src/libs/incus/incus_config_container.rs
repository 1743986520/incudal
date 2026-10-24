//! LXC container cloud-init config generator.
//! Port of lib/incus-config-container.ts. All generated shell/YAML strings are
//! byte-for-byte identical to the TS templates.

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

// ==================== types ====================

/// Mirrors `OsFamily`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OsFamily {
    #[serde(rename = "debian")]
    Debian,
    #[serde(rename = "ubuntu")]
    Ubuntu,
    #[serde(rename = "rhel")]
    Rhel,
    #[serde(rename = "rhel8")]
    Rhel8,
    #[serde(rename = "suse")]
    Suse,
    #[serde(rename = "alpine")]
    Alpine,
    #[serde(rename = "arch")]
    Arch,
    #[serde(rename = "linux")]
    Linux,
    #[serde(rename = "other")]
    Other,
}

impl OsFamily {
    pub fn as_str(&self) -> &'static str {
        match self {
            OsFamily::Debian => "debian",
            OsFamily::Ubuntu => "ubuntu",
            OsFamily::Rhel => "rhel",
            OsFamily::Rhel8 => "rhel8",
            OsFamily::Suse => "suse",
            OsFamily::Alpine => "alpine",
            OsFamily::Arch => "arch",
            OsFamily::Linux => "linux",
            OsFamily::Other => "other",
        }
    }
}

/// Mirrors `PackageManager`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageManager {
    Apt,
    Dnf,
    Yum,
    Zypper,
    Apk,
    Pacman,
}

/// Mirrors `InitSystem`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitSystem {
    Systemd,
    Openrc,
}

/// Mirrors `OsInfo`.
#[derive(Debug, Clone)]
pub struct OsInfo {
    pub family: OsFamily,
    pub package_manager: PackageManager,
    pub init_system: InitSystem,
    pub ssh_service_name: &'static str,
    pub default_shell: &'static str,
    pub default_users: Vec<&'static str>,
    pub supports_include: bool,
}

/// Static network config with dual-stack support (mirrors `StaticNetworkConfig`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StaticNetworkConfig {
    /// IPv4 CIDR, e.g. 10.10.1.100/24.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    /// IPv4 gateway, e.g. 10.10.1.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    /// IPv4 DNS, default ["8.8.8.8", "1.1.1.1"] in v1 configs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<Vec<String>>,
    /// IPv6 CIDR, e.g. 2001:db8::100/64.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6_address: Option<String>,
    /// IPv6 gateway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6_gateway: Option<String>,
    /// IPv6 DNS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6_dns: Option<Vec<String>>,
}

/// Mirrors `IncusConfigParams` (shared container/VM entry parameters).
#[derive(Debug, Clone, Default)]
pub struct IncusConfigParams {
    pub instance_name: String,
    pub image_alias: String,
    pub root_password: String,
    pub ssh_key: Option<String>,
    /// 'container' | 'virtual-machine'
    pub instance_type: Option<String>,
    pub network_mode: Option<String>,
    /// Panel-computed static IP config; DHCP when absent.
    pub network: Option<StaticNetworkConfig>,
    /// User-provided init commands (multi-line, split on newline).
    pub extra_shell_commands: Option<String>,
    /// VM-only: deterministic MAC seed.
    pub instance_id_seed: Option<String>,
}

/// Mirrors `IncusConfigMetaData`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncusConfigMetaData {
    pub ssh_port: i64,
    pub root_password: String,
    pub os_family: String,
    pub image_alias: String,
    pub instance_type: String,
    pub ip_address: String,
}

/// Mirrors `IncusConfigResult`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncusConfigResult {
    pub config_payload: IncusConfigPayload,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta_data: Option<IncusConfigMetaData>,
}

/// The cloud-init payload keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncusConfigPayload {
    #[serde(rename = "user.user-data")]
    pub user_data: String,
    #[serde(rename = "user.network-config")]
    pub network_config: String,
}

// ==================== constants ====================

pub const SSH_PORT: i64 = 22;
const NETWORK_RETRY_COUNT: u32 = 20;
const NETWORK_RETRY_DELAY: u32 = 3;
/// DNS points at the bridge dnsmasq gateway so pure-IPv6 hosts can proxy
/// upstream resolution through DNS64.
const DEFAULT_DNS: [&str; 1] = ["10.10.0.1"];
const INTERFACE_NAME: &str = "eth0";

// ==================== utilities ====================

/// Mirrors `generateRandomPassword` (alphanumeric + shell-safe symbols).
pub fn generate_random_password(length: usize) -> String {
    const CHARS: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let mut password = String::with_capacity(length);
    for _ in 0..length {
        let index = rng.gen_range(0..CHARS.len());
        password.push(CHARS[index] as char);
    }
    password
}

fn escape_for_shell_single_quote(value: &str) -> String {
    value.replace('\'', "'\"'\"'")
}

fn escape_for_shell_double_quote(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('$', "\\$")
        .replace('`', "\\`")
        .replace('"', "\\\"")
}

static SSH_KEY_PATTERN: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(
        r"^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|ssh-dss)\s+[A-Za-z0-9+/=]+",
    )
    .expect("static regex")
});

fn is_valid_ssh_key(key: &str) -> bool {
    SSH_KEY_PATTERN.is_match(key.trim())
}

// ==================== OS detection ====================

fn is_rhel8_series(alias: &str) -> bool {
    static RE: Lazy<regex::Regex> =
        Lazy::new(|| regex::Regex::new(r"(?i)alma.*8|rocky.*8|oracle.*8|centos.*8").expect("regex"));
    RE.is_match(alias)
}

fn is_old_debian(alias: &str) -> bool {
    static RE: Lazy<regex::Regex> =
        Lazy::new(|| regex::Regex::new(r"(?i)debian.*(10|buster|11|bullseye)").expect("regex"));
    RE.is_match(alias)
}

fn contains_any(alias: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| alias.contains(needle))
}

/// Mirrors `detectOsInfo`.
pub fn detect_os_info(image_alias: &str) -> OsInfo {
    let alias = image_alias.to_lowercase();

    if alias.contains("ubuntu") {
        return OsInfo {
            family: OsFamily::Ubuntu,
            package_manager: PackageManager::Apt,
            init_system: InitSystem::Systemd,
            ssh_service_name: "ssh",
            default_shell: "/bin/bash",
            default_users: vec!["root", "ubuntu"],
            supports_include: true,
        };
    }

    if alias.contains("arch") {
        return OsInfo {
            family: OsFamily::Arch,
            package_manager: PackageManager::Pacman,
            init_system: InitSystem::Systemd,
            ssh_service_name: "sshd",
            default_shell: "/bin/bash",
            default_users: vec!["root", "arch"],
            supports_include: true,
        };
    }

    if alias.contains("kali") {
        return OsInfo {
            family: OsFamily::Debian,
            package_manager: PackageManager::Apt,
            init_system: InitSystem::Systemd,
            ssh_service_name: "ssh",
            default_shell: "/bin/bash",
            default_users: vec!["root", "kali"],
            supports_include: true,
        };
    }

    if alias.contains("debian") {
        let is_old = is_old_debian(&alias);
        return OsInfo {
            family: OsFamily::Debian,
            package_manager: PackageManager::Apt,
            init_system: InitSystem::Systemd,
            ssh_service_name: "ssh",
            default_shell: "/bin/bash",
            default_users: vec!["root", "debian"],
            supports_include: !is_old,
        };
    }

    if alias.contains("alpine") {
        return OsInfo {
            family: OsFamily::Alpine,
            package_manager: PackageManager::Apk,
            init_system: InitSystem::Openrc,
            ssh_service_name: "sshd",
            default_shell: "/bin/ash",
            default_users: vec!["root"],
            supports_include: true,
        };
    }

    if contains_any(&alias, &["opensuse", "suse", "tumbleweed", "leap"]) {
        return OsInfo {
            family: OsFamily::Suse,
            package_manager: PackageManager::Zypper,
            init_system: InitSystem::Systemd,
            ssh_service_name: "sshd",
            default_shell: "/bin/bash",
            default_users: vec!["root"],
            supports_include: true,
        };
    }

    if alias.contains("fedora") {
        return OsInfo {
            family: OsFamily::Rhel,
            package_manager: PackageManager::Dnf,
            init_system: InitSystem::Systemd,
            ssh_service_name: "sshd",
            default_shell: "/bin/bash",
            default_users: vec!["root", "fedora"],
            supports_include: true,
        };
    }

    if contains_any(&alias, &["alma", "rocky", "oracle", "centos", "rhel"]) {
        let is_version8 = is_rhel8_series(&alias);
        // TS: defaultUser = 'root' unless a distro-specific user was detected;
        // the list is always ['root', defaultUser] (duplicates included).
        let default_user = if alias.contains("alma") {
            "almalinux"
        } else if alias.contains("rocky") {
            "rocky"
        } else if alias.contains("oracle") {
            "oracle"
        } else if alias.contains("centos") {
            "centos"
        } else {
            "root"
        };
        return OsInfo {
            family: if is_version8 { OsFamily::Rhel8 } else { OsFamily::Rhel },
            package_manager: if is_version8 { PackageManager::Yum } else { PackageManager::Dnf },
            init_system: InitSystem::Systemd,
            ssh_service_name: "sshd",
            default_shell: "/bin/bash",
            default_users: vec!["root", default_user],
            supports_include: true,
        };
    }

    OsInfo {
        family: OsFamily::Other,
        package_manager: PackageManager::Apt,
        init_system: InitSystem::Systemd,
        ssh_service_name: "sshd",
        default_shell: "/bin/bash",
        default_users: vec!["root"],
        supports_include: true,
    }
}

// ==================== package list ====================

fn get_packages_for_os(os_info: &OsInfo) -> Vec<&'static str> {
    let common_utils = ["curl", "wget", "sudo", "ca-certificates"];
    match os_info.package_manager {
        PackageManager::Apt => {
            let mut list = common_utils.to_vec();
            list.extend(["openssh-server", "sed", "grep", "iproute2"]);
            list
        }
        PackageManager::Dnf | PackageManager::Yum => {
            let mut list = common_utils.to_vec();
            list.extend(["openssh-server", "openssh-clients", "sed", "grep", "iproute"]);
            list
        }
        PackageManager::Zypper => {
            let mut list = common_utils.to_vec();
            list.extend(["openssh", "sed", "grep", "iproute2"]);
            list
        }
        PackageManager::Pacman | PackageManager::Apk => Vec::new(),
    }
}

// ==================== setup commands ====================

fn wrap_with_network_retry(cmd: &str) -> String {
    format!(
        r#"
  j=0
  while [ $j -lt {retry_count} ]; do
    # 动态获取 IPv4 或 IPv6 默认网关作为 DNS，若依然全空，则给予双栈的知名公测兜底 DNS，护航纯 IPv6 及异常段启动
    GW4=$(ip -4 route show default 2>/dev/null | awk '/default/ {{print $3}}' | head -n 1)
    GW6=$(ip -6 route show default 2>/dev/null | awk '/default/ {{print $3}}' | head -n 1)
    if [ -n "$GW4" ]; then echo "nameserver $GW4" > /etc/resolv.conf; elif [ -n "$GW6" ]; then echo "nameserver $GW6" > /etc/resolv.conf; else echo -e "nameserver 8.8.8.8\nnameserver 2001:4860:4860::8888" > /etc/resolv.conf; fi

    if {cmd}; then
      break
    fi

    echo "Command failed (attempt $j), retrying in {retry_delay}s..."
    j=$((j+1))
    sleep {retry_delay}
  done
  "#,
        retry_count = NETWORK_RETRY_COUNT,
        retry_delay = NETWORK_RETRY_DELAY,
        cmd = cmd
    )
}

fn get_setup_commands(os_info: &OsInfo) -> Vec<String> {
    let mut cmds: Vec<String> = Vec::new();

    // Alpine
    if os_info.family == OsFamily::Alpine {
        cmds.push(r#"sed -i "s/https:/http:/g" /etc/apk/repositories || true"#.to_string());
        let essential_pkgs = "openssh openssh-server-pam bash shadow sed grep dhcpcd util-linux ca-certificates iproute2";
        let install_cmd = format!("apk update && apk add --no-cache --allow-untrusted {essential_pkgs}");
        cmds.push(wrap_with_network_retry(&install_cmd));
        cmds.push(r#"sed -i "s/http:/https:/g" /etc/apk/repositories || true"#.to_string());
        cmds.push("touch /etc/shadow && chmod 640 /etc/shadow || true".to_string());
    }
    // Arch Linux
    else if os_info.family == OsFamily::Arch {
        cmds.push(wrap_with_network_retry("pacman -Sy --noconfirm openssh sed grep iproute2"));
        cmds.push("ssh-keygen -A || true".to_string());
    }
    // Everything else
    else {
        match os_info.package_manager {
            PackageManager::Apt => {
                cmds.push(wrap_with_network_retry("DEBIAN_FRONTEND=noninteractive apt-get update"));
                cmds.push(
                    "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server sed grep iproute2 || true"
                        .to_string(),
                );
            }
            PackageManager::Dnf => {
                cmds.push(wrap_with_network_retry(
                    "dnf install -y openssh-server openssh-clients sed grep iproute",
                ));
            }
            PackageManager::Yum => {
                cmds.push(wrap_with_network_retry(
                    "yum install -y openssh-server openssh-clients sed grep iproute",
                ));
            }
            PackageManager::Zypper => {
                cmds.push(wrap_with_network_retry("zypper --non-interactive refresh"));
                cmds.push("zypper --non-interactive install -y openssh sed grep iproute2 || true".to_string());
            }
            PackageManager::Pacman | PackageManager::Apk => {}
        }
    }

    // Common configuration.
    cmds.push("mkdir -p /etc/ssh/sshd_config.d".to_string());
    cmds.push(
        r#"sed -i -E "s/^[#[:space:]]*Subsystem[[:space:]]+sftp.*/Subsystem sftp internal-sftp/" /etc/ssh/sshd_config 2>/dev/null || true"#
            .to_string(),
    );
    cmds.push(
        r#"grep -q "^Subsystem sftp " /etc/ssh/sshd_config || printf "\n%s\n" "Subsystem sftp internal-sftp" >> /etc/ssh/sshd_config"#
            .to_string(),
    );

    if os_info.supports_include {
        cmds.push(
            r#"grep -q "^Include /etc/ssh/sshd_config.d" /etc/ssh/sshd_config || sed -i "1i Include /etc/ssh/sshd_config.d/*.conf" /etc/ssh/sshd_config || true"#
                .to_string(),
        );
    }

    cmds.push(
        "command -v ssh-keygen >/dev/null && { test -f /etc/ssh/ssh_host_rsa_key || ssh-keygen -A 2>/dev/null; } || true"
            .to_string(),
    );

    // Service management.
    if os_info.init_system == InitSystem::Systemd {
        cmds.push(format!("systemctl unmask {} || true", os_info.ssh_service_name));
        cmds.push(format!("systemctl enable {} || true", os_info.ssh_service_name));
    } else {
        cmds.push(format!(
            "[ -f /etc/init.d/{0} ] && rc-update add {0} default 2>/dev/null || true",
            os_info.ssh_service_name
        ));
        cmds.push("[ -f /etc/init.d/dhcpcd ] && rc-update add dhcpcd default 2>/dev/null || true".to_string());
    }

    cmds
}

// ==================== script generation ====================

fn generate_setup_script(
    ssh_key: Option<&str>,
    root_password: &str,
    users: &[&str],
    os_info: &OsInfo,
) -> String {
    let escaped_key = escape_for_shell_double_quote(ssh_key.unwrap_or(""));
    let escaped_password = escape_for_shell_single_quote(root_password);
    let users_list_for_loop = users.join(" ");
    let ssh_service_name = os_info.ssh_service_name;

    let restart_ssh_cmd = if os_info.init_system == InitSystem::Openrc {
        format!(
            "rc-service {0} restart 2>/dev/null || /etc/init.d/{0} restart || /etc/init.d/{0} start || true",
            ssh_service_name
        )
    } else {
        format!(
            "systemctl restart {0} 2>/dev/null || service {0} restart || true",
            ssh_service_name
        )
    };

    format!(
        r#"#!/bin/sh
set -e

SSH_KEY="{escaped_key}"
ROOT_PASSWORD='{escaped_password}'
USERS="{users_list_for_loop}"

if echo "root:$ROOT_PASSWORD" | chpasswd >/dev/null 2>&1; then
  :
else
  echo -e "$ROOT_PASSWORD\n$ROOT_PASSWORD" | passwd root >/dev/null 2>&1 || true
fi

passwd -u root >/dev/null 2>&1 || usermod -U root >/dev/null 2>&1 || true

mkdir -p /root/.ssh
chmod 700 /root/.ssh
if [ -n "$SSH_KEY" ]; then
  echo "$SSH_KEY" > /root/.ssh/authorized_keys
  chmod 600 /root/.ssh/authorized_keys
  chown root:root /root/.ssh /root/.ssh/authorized_keys
else
  chown root:root /root/.ssh
fi

for u in $USERS; do
  if [ "$u" = "root" ]; then continue; fi
  if id "$u" >/dev/null 2>&1; then
    HOMEDIR="/home/$u"
    if [ ! -d "$HOMEDIR" ]; then continue; fi
    mkdir -p "$HOMEDIR/.ssh"
    if [ -n "$SSH_KEY" ]; then
      echo "$SSH_KEY" > "$HOMEDIR/.ssh/authorized_keys"
      chmod 600 "$HOMEDIR/.ssh/authorized_keys"
    fi
    chown -R "$u" "$HOMEDIR/.ssh" 2>/dev/null || true
    chmod 700 "$HOMEDIR/.ssh"
    echo "$u:$ROOT_PASSWORD" | chpasswd >/dev/null 2>&1 || true
  fi
done

SED_BIN="sed"
SSH_CONFIG="/etc/ssh/sshd_config"

$SED_BIN -i 's/^PermitRootLogin/#PermitRootLogin/g' $SSH_CONFIG 2>/dev/null || true
$SED_BIN -i 's/^PasswordAuthentication/#PasswordAuthentication/g' $SSH_CONFIG 2>/dev/null || true
$SED_BIN -i 's/^PubkeyAuthentication/#PubkeyAuthentication/g' $SSH_CONFIG 2>/dev/null || true

if ! grep -q "^Include /etc/ssh/sshd_config.d" $SSH_CONFIG; then
    $SED_BIN -i "1i Include /etc/ssh/sshd_config.d/*.conf" $SSH_CONFIG 2>/dev/null || true
fi

echo "PermitRootLogin yes" >> $SSH_CONFIG
echo "PasswordAuthentication yes" >> $SSH_CONFIG
echo "PubkeyAuthentication yes" >> $SSH_CONFIG

{restart_ssh_cmd}

exit 0
"#
    )
}

// ==================== bootcmd ====================

fn get_bootcmd(os_info: &OsInfo) -> Vec<String> {
    let mut cmds: Vec<String> = Vec::new();

    if os_info.family == OsFamily::Alpine {
        // Dynamic gateway DNS with public fallbacks for pure-IPv6 hosts.
        cmds.push(
            "GW4=$(ip -4 route show default 2>/dev/null | awk '/default/ {print $3}' | head -n 1); GW6=$(ip -6 route show default 2>/dev/null | awk '/default/ {print $3}' | head -n 1); if [ -n \"$GW4\" ]; then echo \"nameserver $GW4\" > /etc/resolv.conf; elif [ -n \"$GW6\" ]; then echo \"nameserver $GW6\" > /etc/resolv.conf; else echo -e \"nameserver 8.8.8.8\\nnameserver 2001:4860:4860::8888\" > /etc/resolv.conf; fi"
                .to_string(),
        );
        cmds.push("rc-update add networking boot || true".to_string());
        cmds.push("rc-service networking start 2>/dev/null || true".to_string());
    } else {
        match os_info.package_manager {
            PackageManager::Apt => cmds.push(
                "cloud-init-per once apt_update_early apt-get update || true".to_string(),
            ),
            PackageManager::Dnf => {
                cmds.push("cloud-init-per once dnf_makecache dnf makecache || true".to_string())
            }
            PackageManager::Yum => {
                cmds.push("cloud-init-per once yum_makecache yum makecache || true".to_string())
            }
            PackageManager::Zypper => cmds.push(
                "cloud-init-per once zypper_refresh zypper --non-interactive refresh || true"
                    .to_string(),
            ),
            PackageManager::Pacman | PackageManager::Apk => {}
        }
    }

    cmds
}

// ==================== network config ====================

fn get_network_config(
    net: Option<&StaticNetworkConfig>,
    should_block_shared_ipv6_on_eth0: bool,
) -> String {
    let Some(net) = net else {
        if should_block_shared_ipv6_on_eth0 {
            return format!(
                "version: 1\nconfig:\n  - type: physical\n    name: {INTERFACE_NAME}\n    subnets:\n      - type: dhcp\n"
            );
        }
        return format!(
            "version: 1\nconfig:\n  - type: physical\n    name: {INTERFACE_NAME}\n    subnets:\n      - type: dhcp\n      - type: dhcp6\n"
        );
    };

    let mut subnets: Vec<String> = Vec::new();
    let dns_v4: Vec<String> = net
        .dns
        .clone()
        .unwrap_or_else(|| DEFAULT_DNS.iter().map(|d| d.to_string()).collect());
    if let (Some(ip), Some(gateway)) = (&net.ip_address, &net.gateway) {
        let dns_lines = dns_v4
            .iter()
            .map(|d| format!("          - {d}"))
            .collect::<Vec<_>>()
            .join("\n");
        subnets.push(format!(
            "      - type: static\n        address: {ip}\n        gateway: {gateway}\n        dns_nameservers:\n{dns_lines}"
        ));
    }

    let mut config = format!(
        "version: 1\nconfig:\n  - type: physical\n    name: {INTERFACE_NAME}\n    subnets:\n{}\n",
        subnets.join("\n")
    );

    // eth1: IPv6 routed (dual-NIC architecture; gateway fe80::1 is the Incus
    // routed-mode standard link-local gateway).
    if let Some(ipv6_address) = &net.ipv6_address {
        let ipv6_addr = if ipv6_address.contains('/') {
            ipv6_address.clone()
        } else {
            format!("{ipv6_address}/128")
        };
        let dns_v6: Vec<String> = net
            .ipv6_dns
            .clone()
            .unwrap_or_else(|| {
                vec![
                    "2606:4700:4700::1111".to_string(),
                    "2001:4860:4860::8888".to_string(),
                ]
            });
        let dns_lines = dns_v6
            .iter()
            .map(|d| format!("          - {d}"))
            .collect::<Vec<_>>()
            .join("\n");
        config.push_str(&format!(
            "  - type: physical\n    name: eth1\n    subnets:\n      - type: static\n        address: {ipv6_addr}\n        gateway: fe80::1\n        dns_nameservers:\n{dns_lines}\n"
        ));
    }

    config
}

// ==================== main ====================

/// Mirrors `generateContainerConfig`.
pub fn generate_container_config(params: &IncusConfigParams) -> Result<IncusConfigResult, String> {
    let IncusConfigParams {
        image_alias,
        root_password,
        ssh_key,
        network,
        extra_shell_commands,
        network_mode,
        ..
    } = params;

    if image_alias.is_empty() || root_password.is_empty() {
        return Err("Missing params".to_string());
    }
    if let Some(key) = ssh_key {
        if !key.is_empty() && !is_valid_ssh_key(key) {
            return Err("Invalid SSH Key".to_string());
        }
    }

    let os_info = detect_os_info(image_alias);
    let is_alpine = os_info.family == OsFamily::Alpine;
    let ssh_port = SSH_PORT;
    let common_users: Vec<&str> = os_info.default_users.clone();

    // 1. Users YAML.
    let users_yaml = common_users
        .iter()
        .map(|u| {
            let mut lines = vec![
                format!("  - name: {u}"),
                "    lock_passwd: false".to_string(),
                "    create_home: true".to_string(),
                format!("    shell: {}", os_info.default_shell),
                "    sudo: ALL=(ALL) NOPASSWD:ALL".to_string(),
            ];
            if let Some(key) = ssh_key.as_deref().map(str::trim).filter(|k| !k.is_empty()) {
                lines.push("    ssh_authorized_keys:".to_string());
                lines.push(format!("      - {key}"));
            }
            lines.join("\n")
        })
        .collect::<Vec<_>>()
        .join("\n");

    // 2. SSH config.
    let sshd_drop_in_path = "/etc/ssh/sshd_config.d/50-incus.conf";
    let sshd_drop_in_content = [
        format!("Port {ssh_port}"),
        "PermitRootLogin yes".to_string(),
        "PasswordAuthentication yes".to_string(),
        "PubkeyAuthentication yes".to_string(),
    ]
    .join("\n");

    // 3. Scripts.
    let setup_script = generate_setup_script(ssh_key.as_deref(), root_password, &common_users, &os_info);
    let setup_cmds = get_setup_commands(&os_info);

    // 4. Runcmd.
    let user_custom_cmds: Vec<String> = extra_shell_commands
        .as_deref()
        .map(|cmds| {
            cmds.split('\n')
                .map(|cmd| cmd.trim().to_string())
                .filter(|cmd| !cmd.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let should_block_shared_ipv6_on_eth0 = match network_mode.as_deref() {
        Some(mode) => mode != "nat_ipv6_nat" && mode != "ipv6_nat",
        None => network
            .as_ref()
            .map(|n| n.ipv6_address.is_some())
            .unwrap_or(false),
    };

    let routed_ipv6_guard_cmds: Vec<&str> = if should_block_shared_ipv6_on_eth0 {
        vec![
            "mkdir -p /etc/sysctl.d || true",
            "printf \"%s\\n%s\\n%s\\n\" \"net.ipv6.conf.eth0.disable_ipv6 = 1\" \"net.ipv6.conf.eth0.accept_ra = 0\" \"net.ipv6.conf.eth0.autoconf = 0\" > /etc/sysctl.d/99-incudal-routed-ipv6.conf",
            "sysctl -p /etc/sysctl.d/99-incudal-routed-ipv6.conf >/dev/null 2>&1 || true",
            "ip -6 addr flush dev eth0 scope global >/dev/null 2>&1 || true",
            "ip -6 route del default dev eth0 >/dev/null 2>&1 || true",
            "ip -6 route replace default via fe80::1 dev eth1 metric 100 >/dev/null 2>&1 || true",
        ]
    } else {
        Vec::new()
    };

    let mut runcmd: Vec<String> = vec!["mkdir -p /etc/ssh/sshd_config.d || true".to_string()];
    runcmd.extend(setup_cmds);
    runcmd.push("/usr/local/bin/incus-setup.sh || true".to_string());
    runcmd.extend(routed_ipv6_guard_cmds.iter().map(|c| c.to_string()));
    runcmd.extend(user_custom_cmds);

    // 5. Write files.
    let packages = get_packages_for_os(&os_info);
    let packages_yaml = packages
        .iter()
        .map(|p| format!("  - {p}"))
        .collect::<Vec<_>>()
        .join("\n");

    let mut write_files_lines: Vec<String> = vec![
        format!("  - path: {sshd_drop_in_path}"),
        "    owner: root:root".to_string(),
        "    permissions: '0644'".to_string(),
        "    content: |".to_string(),
    ];
    write_files_lines.extend(
        sshd_drop_in_content
            .split('\n')
            .map(|l| format!("      {l}")),
    );
    write_files_lines.push("  - path: /usr/local/bin/incus-setup.sh".to_string());
    write_files_lines.push("    owner: root:root".to_string());
    write_files_lines.push("    permissions: '0755'".to_string());
    write_files_lines.push("    content: |".to_string());
    write_files_lines.extend(setup_script.split('\n').map(|l| format!("      {l}")));
    let write_files_yaml = write_files_lines.join("\n");

    let runcmd_yaml = runcmd
        .iter()
        .map(|cmd| {
            format!(
                "  - {}",
                serde_json::to_string(cmd).unwrap_or_else(|_| "\"\"".to_string())
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let bootcmd_list = get_bootcmd(&os_info);
    let bootcmd_section = if !bootcmd_list.is_empty() {
        format!(
            "bootcmd:\n{}\n",
            bootcmd_list
                .iter()
                .map(|cmd| format!("  - {cmd}"))
                .collect::<Vec<_>>()
                .join("\n")
        )
    } else {
        String::new()
    };
    let yaml_safe_password = root_password
        .replace('\'', "''")
        .replace('\\', "\\\\");
    let ssh_pwauth = if is_alpine { "false" } else { "true" };
    let packages_section = if !packages.is_empty() {
        format!("packages:\n{packages_yaml}\n\n")
    } else {
        String::new()
    };
    let chpasswd_section = if is_alpine {
        String::new()
    } else {
        format!(
            "chpasswd:\n  expire: false\n  list: |\n    root:{yaml_safe_password}\n\n"
        )
    };

    // 6. Network config.
    let network_config_yaml = get_network_config(network.as_ref(), should_block_shared_ipv6_on_eth0);

    // 7. Output.
    let cloud_config_yaml = format!(
        "#cloud-config\npackage_update: {}\npackage_upgrade: false\ntimezone: Asia/Shanghai\n\nssh_pwauth: {}\ndisable_root: false\n\n{}{}users:\n{}\n\nwrite_files:\n{}\n\n{}runcmd:\n{}\n",
        if is_alpine { "false" } else { "true" },
        ssh_pwauth,
        packages_section,
        chpasswd_section,
        users_yaml,
        write_files_yaml,
        bootcmd_section,
        runcmd_yaml
    );

    Ok(IncusConfigResult {
        config_payload: IncusConfigPayload {
            user_data: cloud_config_yaml,
            network_config: network_config_yaml,
        },
        meta_data: Some(IncusConfigMetaData {
            ssh_port,
            root_password: root_password.clone(),
            os_family: os_info.family.as_str().to_string(),
            image_alias: image_alias.clone(),
            instance_type: "container".to_string(),
            ip_address: network
                .as_ref()
                .and_then(|n| n.ip_address.clone())
                .unwrap_or_else(|| "dhcp".to_string()),
        }),
    })
}

/// Helper mirroring the metaData default used by the VM route of the generator.
pub fn default_vm_meta_data(params: &IncusConfigParams) -> IncusConfigMetaData {
    IncusConfigMetaData {
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
    }
}

/// Value-shape convenience for routes: `{ configPayload, metaData }`.
pub fn result_to_value(result: &IncusConfigResult) -> Value {
    json!({
        "configPayload": {
            "user.user-data": result.config_payload.user_data,
            "user.network-config": result.config_payload.network_config,
        },
        "metaData": result.meta_data.as_ref().map(|meta| json!({
            "sshPort": meta.ssh_port,
            "rootPassword": meta.root_password,
            "osFamily": meta.os_family,
            "imageAlias": meta.image_alias,
            "instanceType": meta.instance_type,
            "ipAddress": meta.ip_address,
        })),
    })
}
