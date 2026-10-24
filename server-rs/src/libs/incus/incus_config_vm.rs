//! VM cloud-init config generator.
//! Port of lib/incus-config-vm.ts. All generated shell/YAML strings are
//! byte-for-byte identical to the TS templates.

use once_cell::sync::Lazy;
use regex::Regex;

use crate::libs::incus::incus_config_container::{IncusConfigParams, IncusConfigPayload, IncusConfigResult, StaticNetworkConfig};
use crate::libs::incus::vm_network_identifiers::{generate_vm_nic_macs, VmNicMacs};

// ==================== types ====================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VmOsFamily {
    Ubuntu,
    Debian,
    Rhel,
    Rhel8,
    Alpine,
    Linux,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VmPackageManager {
    Apt,
    Dnf,
    Yum,
    Apk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VmInitSystem {
    Systemd,
    Openrc,
}

struct VmOsInfo {
    family: VmOsFamily,
    package_manager: VmPackageManager,
    init_system: VmInitSystem,
    ssh_service_name: &'static str,
    default_shell: &'static str,
    default_users: Vec<&'static str>,
}

// DNS points at the bridge dnsmasq gateway (same as LXC) so pure-IPv6 hosts
// can forward through DNS64.
const DEFAULT_DNS_V4: [&str; 1] = ["10.10.0.1"];
const DEFAULT_DNS_V6: [&str; 2] = ["2606:4700:4700::1111", "2001:4860:4860::8888"];
const DEFAULT_IPV6_GATEWAY: &str = "fe80::1";
const SSHD_PRIMARY_DROPIN_PATH: &str = "/etc/ssh/sshd_config.d/99-incudal-force.conf";
const SSHD_LEGACY_DROPIN_PATH: &str = "/etc/ssh/sshd_config.d/00-incudal-auth.conf";

// ==================== utilities ====================

fn indent_string(value: &str, count: usize) -> String {
    let indent = " ".repeat(count);
    value
        .split('\n')
        .map(|line| {
            if line.is_empty() {
                line.to_string()
            } else {
                format!("{indent}{line}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
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

fn escape_for_yaml_single_quote(value: &str) -> String {
    value.replace('\'', "''")
}

static RHEL8_SERIES: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)alma.*8|rocky.*8|oracle.*8|centos.*8|rhel.*8").expect("regex"));

fn is_rhel8_series(alias: &str) -> bool {
    RHEL8_SERIES.is_match(alias)
}

fn unique_users(users: Vec<&'static str>) -> Vec<&'static str> {
    let mut seen: Vec<&'static str> = Vec::new();
    for user in users {
        if !user.is_empty() && !seen.contains(&user) {
            seen.push(user);
        }
    }
    seen
}

fn contains_any(alias: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| alias.contains(needle))
}

fn detect_vm_os_info(image_alias: &str) -> VmOsInfo {
    let alias = image_alias.to_lowercase();

    if alias.contains("ubuntu") {
        return VmOsInfo {
            family: VmOsFamily::Ubuntu,
            package_manager: VmPackageManager::Apt,
            init_system: VmInitSystem::Systemd,
            ssh_service_name: "ssh",
            default_shell: "/bin/bash",
            default_users: vec!["root", "ubuntu"],
        };
    }

    if alias.contains("debian") || alias.contains("kali") {
        return VmOsInfo {
            family: VmOsFamily::Debian,
            package_manager: VmPackageManager::Apt,
            init_system: VmInitSystem::Systemd,
            ssh_service_name: "ssh",
            default_shell: "/bin/bash",
            default_users: vec!["root", "debian"],
        };
    }

    if alias.contains("alpine") {
        return VmOsInfo {
            family: VmOsFamily::Alpine,
            package_manager: VmPackageManager::Apk,
            init_system: VmInitSystem::Openrc,
            ssh_service_name: "sshd",
            default_shell: "/bin/ash",
            default_users: vec!["root"],
        };
    }

    if contains_any(
        &alias,
        &["alma", "rocky", "oracle", "centos", "rhel", "fedora"],
    ) {
        let detected_user: &'static str = if alias.contains("alma") {
            "almalinux"
        } else if alias.contains("rocky") {
            "rocky"
        } else if alias.contains("oracle") {
            "opc"
        } else if alias.contains("centos") {
            "centos"
        } else if alias.contains("fedora") {
            "fedora"
        } else {
            "cloud-user"
        };

        return VmOsInfo {
            family: if is_rhel8_series(&alias) {
                VmOsFamily::Rhel8
            } else {
                VmOsFamily::Rhel
            },
            package_manager: if is_rhel8_series(&alias) {
                VmPackageManager::Yum
            } else {
                VmPackageManager::Dnf
            },
            init_system: VmInitSystem::Systemd,
            ssh_service_name: "sshd",
            default_shell: "/bin/bash",
            default_users: unique_users(vec!["root", "cloud-user", detected_user]),
        };
    }

    VmOsInfo {
        family: VmOsFamily::Linux,
        package_manager: VmPackageManager::Apt,
        init_system: VmInitSystem::Systemd,
        ssh_service_name: "sshd",
        default_shell: "/bin/bash",
        default_users: vec!["root"],
    }
}

fn normalize_ipv6_address(address: &str) -> String {
    let trimmed = address.trim();
    if trimmed.contains('/') {
        trimmed.to_string()
    } else {
        format!("{trimmed}/128")
    }
}

fn get_package_install_command(os_info: &VmOsInfo) -> &'static str {
    match os_info.package_manager {
        VmPackageManager::Apt => {
            "retry_cmd \"DEBIAN_FRONTEND=noninteractive apt-get update\" && retry_cmd \"DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends qemu-guest-agent openssh-server curl ca-certificates\""
        }
        VmPackageManager::Dnf => {
            "retry_cmd \"dnf install -y qemu-guest-agent openssh-server curl ca-certificates\""
        }
        VmPackageManager::Yum => {
            "retry_cmd \"yum install -y qemu-guest-agent openssh-server curl ca-certificates\""
        }
        VmPackageManager::Apk => {
            "retry_cmd \"apk update\" && retry_cmd \"apk add --no-cache qemu-guest-agent openssh-server openssh-keygen curl ca-certificates shadow\" || retry_cmd \"apk add --no-cache qemu-guest-agent openssh curl ca-certificates shadow\""
        }
    }
}

fn get_cloud_init_packages(os_info: &VmOsInfo) -> Vec<&'static str> {
    match os_info.package_manager {
        VmPackageManager::Apt | VmPackageManager::Dnf | VmPackageManager::Yum => {
            vec!["qemu-guest-agent", "openssh-server", "curl", "ca-certificates"]
        }
        VmPackageManager::Apk => Vec::new(),
    }
}

fn get_sshd_drop_in_content(os_info: &VmOsInfo) -> String {
    let mut lines = vec![
        "PermitRootLogin yes".to_string(),
        "PasswordAuthentication yes".to_string(),
        "PubkeyAuthentication yes".to_string(),
        "ChallengeResponseAuthentication no".to_string(),
    ];
    if os_info.family != VmOsFamily::Alpine {
        lines.push("UsePAM yes".to_string());
    }
    lines.join("\n")
}

fn get_network_match_yaml(mac_address: &str) -> String {
    format!("      macaddress: \"{}\"", mac_address.to_lowercase())
}

// ==================== setup script ====================

fn generate_setup_script(params: &IncusConfigParams, os_info: &VmOsInfo) -> String {
    let escaped_key = escape_for_shell_double_quote(params.ssh_key.as_deref().unwrap_or(""));
    let escaped_password = escape_for_shell_single_quote(&params.root_password);
    let users_list = os_info.default_users.join(" ");
    let ssh_service_name = os_info.ssh_service_name;
    let package_install_command = get_package_install_command(os_info);
    let sshd_primary_drop_in_path = SSHD_PRIMARY_DROPIN_PATH;
    let sshd_legacy_drop_in_path = SSHD_LEGACY_DROPIN_PATH;

    let extra_commands = params
        .extra_shell_commands
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(": # No extra commands");
    let sshd_drop_in_content = get_sshd_drop_in_content(os_info);
    let has_routed_ipv6 = params
        .network
        .as_ref()
        .map(|n| n.ipv6_address.is_some())
        .unwrap_or(false);
    let escaped_primary_ipv6 = params
        .network
        .as_ref()
        .and_then(|n| n.ipv6_address.as_deref())
        .map(|addr| escape_for_shell_double_quote(addr.trim().split('/').next().unwrap_or("")))
        .unwrap_or_default();

    let serial_console_commands = if os_info.init_system == VmInitSystem::Openrc {
        r#"if [ -f /etc/inittab ] && ! grep -q '^ttyS0::respawn:/sbin/getty -L ttyS0 115200 vt100$' /etc/inittab 2>/dev/null; then
  echo 'ttyS0::respawn:/sbin/getty -L ttyS0 115200 vt100' >> /etc/inittab
fi
kill -HUP 1 2>/dev/null || true"#
    } else {
        "systemctl enable serial-getty@ttyS0.service || true
systemctl restart serial-getty@ttyS0.service || true"
    };

    let service_enable_commands = if os_info.init_system == VmInitSystem::Openrc {
        Box::leak(
            format!(
                "[ -f /etc/init.d/{0} ] && rc-update add {0} default 2>/dev/null || true\n[ -f /etc/init.d/{0} ] && rc-service {0} restart 2>/dev/null || /etc/init.d/{0} restart 2>/dev/null || /etc/init.d/{0} start 2>/dev/null || true\n[ -f /etc/init.d/qemu-guest-agent ] && rc-update add qemu-guest-agent default 2>/dev/null || true\n[ -f /etc/init.d/qemu-guest-agent ] && rc-service qemu-guest-agent restart 2>/dev/null || /etc/init.d/qemu-guest-agent restart 2>/dev/null || /etc/init.d/qemu-guest-agent start 2>/dev/null || true",
                ssh_service_name
            )
            .into_boxed_str(),
        )
    } else {
        Box::leak(
            format!(
                "systemctl daemon-reload || true\nsystemctl unmask {0} || true\nsystemctl enable {0} 2>/dev/null || true\nsystemctl restart {0} 2>/dev/null || true\nsystemctl enable qemu-guest-agent 2>/dev/null || true\nsystemctl restart qemu-guest-agent 2>/dev/null || true",
                ssh_service_name
            )
            .into_boxed_str(),
        )
    };

    let family_str = match os_info.family {
        VmOsFamily::Ubuntu => "ubuntu",
        VmOsFamily::Debian => "debian",
        VmOsFamily::Rhel => "rhel",
        VmOsFamily::Rhel8 => "rhel8",
        VmOsFamily::Alpine => "alpine",
        VmOsFamily::Linux => "linux",
    };

    let ipv6_guard_section = if has_routed_ipv6 {
        format!(
            r#"echo "Installing persistent IPv6 default-route guard..."
cat > /usr/local/bin/incudal-ipv6-route-guard.sh <<'EOF'
#!/bin/sh
set -e

TARGET_IPV6="{escaped_primary_ipv6}"
if [ -z "$TARGET_IPV6" ]; then
  exit 0
fi

IPV6_IFACE="$(ip -6 -o addr show scope global 2>/dev/null | awk -v target="$TARGET_IPV6" '$4 ~ ("^" target "/") {{print $2; exit}}')"
if [ -z "$IPV6_IFACE" ]; then
  exit 0
fi

if ! ip -6 route show default 2>/dev/null | grep -q "dev \${{IPV6_IFACE}}"; then
  ip -6 route replace default via fe80::1 dev "\${{IPV6_IFACE}}" metric 100 onlink >/dev/null 2>&1 || true
fi
EOF
chmod +x /usr/local/bin/incudal-ipv6-route-guard.sh
/usr/local/bin/incudal-ipv6-route-guard.sh || true

if command -v systemctl >/dev/null 2>&1; then
  cat > /etc/systemd/system/incudal-ipv6-route-guard.service <<'EOF'
[Unit]
Description=Incudal IPv6 routed default-route guard
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/incudal-ipv6-route-guard.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload || true
  systemctl enable incudal-ipv6-route-guard.service || true
  systemctl start incudal-ipv6-route-guard.service || true
elif [ -d /etc/local.d ]; then
  cat > /etc/local.d/incudal-ipv6-route-guard.start <<'EOF'
#!/bin/sh
/usr/local/bin/incudal-ipv6-route-guard.sh || true
EOF
  chmod +x /etc/local.d/incudal-ipv6-route-guard.start
  rc-update add local default 2>/dev/null || true
  /etc/local.d/incudal-ipv6-route-guard.start || true
fi
"#
        )
    } else {
        String::new()
    };

    format!(
        r#"#!/bin/sh
LOG_FILE="/var/log/incudal-vm-setup.log"
exec >>"$LOG_FILE" 2>&1
# 不启用 shell trace，避免 ROOT_PASSWORD/SSH_KEY 写入 guest 日志

SSH_KEY="{escaped_key}"
ROOT_PASSWORD='{escaped_password}'
DEFAULT_USERS="{users_list}"
SSH_SERVICE="{ssh_service_name}"

retry_cmd() {{
  command="$1"
  attempt=0
  while [ "$attempt" -lt 20 ]; do
    if sh -c "$command"; then
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 3
  done
  return 1
}}

ensure_dns_fallback() {{
  if [ ! -s /etc/resolv.conf ] || ! grep -q '^nameserver ' /etc/resolv.conf 2>/dev/null; then
    {{
      # DNS 指向网桥 dnsmasq，兼容纯 IPv6 宿主机
      printf '%s\n' 'nameserver 10.10.0.1'
    }} > /etc/resolv.conf
  fi
}}

wait_for_network() {{
  attempt=0
  while [ "$attempt" -lt 30 ]; do
    if ip route show default >/dev/null 2>&1; then
      return 0
    fi
    if ping -c 1 -W 1 1.1.1.1 >/dev/null 2>&1; then
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 2
  done
  return 1
}}

user_home_dir() {{
  user="$1"
  if [ "$user" = "root" ]; then
    echo "/root"
    return 0
  fi
  awk -F: -v target="$user" '$1 == target {{ print $6; exit }}' /etc/passwd 2>/dev/null
}}

set_password() {{
  user="$1"
  id "$user" >/dev/null 2>&1 || return 0
  echo "$user:$ROOT_PASSWORD" | chpasswd >/dev/null 2>&1 || true
  passwd -u "$user" >/dev/null 2>&1 || usermod -U "$user" >/dev/null 2>&1 || true
}}

set_authorized_key() {{
  [ -n "$SSH_KEY" ] || return 0
  user="$1"
  id "$user" >/dev/null 2>&1 || return 0

  home_dir="$(user_home_dir "$user")"
  [ -n "$home_dir" ] || return 0

  mkdir -p "$home_dir/.ssh"
  chmod 700 "$home_dir/.ssh"
  printf '%s\n' "$SSH_KEY" > "$home_dir/.ssh/authorized_keys"
  chmod 600 "$home_dir/.ssh/authorized_keys"

  if [ "$user" = "root" ]; then
    chown root:root "$home_dir/.ssh" "$home_dir/.ssh/authorized_keys" 2>/dev/null || true
  else
    chown -R "$user":"$user" "$home_dir/.ssh" 2>/dev/null || true
  fi
}}

ensure_include_directive() {{
  config_path="/etc/ssh/sshd_config"
  [ -f "$config_path" ] || return 0

  grep -q '^Include /etc/ssh/sshd_config.d/\*\.conf$' "$config_path" && return 0

  tmp_path="$config_path.incudal.tmp"
  {{
    printf '%s\n' 'Include /etc/ssh/sshd_config.d/*.conf'
    cat "$config_path"
  }} > "$tmp_path" && mv "$tmp_path" "$config_path"
}}

write_sshd_dropin() {{
  mkdir -p /etc/ssh/sshd_config.d
  ensure_include_directive
  # 暴力清理各大云系统的防修改枷锁文件
  rm -f "{sshd_legacy_drop_in_path}" 2>/dev/null || true
  rm -f /etc/ssh/sshd_config.d/50-cloud-init.conf 2>/dev/null || true
  rm -f /etc/ssh/sshd_config.d/60-cloudimg-settings.conf 2>/dev/null || true
  # 以 99 结尾占据排序优势
  cat > "{sshd_primary_drop_in_path}" <<'EOF'
{sshd_drop_in_content}
EOF
}}

update_sshd_main_config() {{
  config_path="/etc/ssh/sshd_config"
  [ -f "$config_path" ] || return 0

  # 极其暴力的 SED：不管前面有没有注释，只要包含这两个关键句语意，统统连根铲除或覆盖
  sed -i -E 's/^[#[:space:]]*PermitRootLogin.*/PermitRootLogin yes/' "$config_path" 2>/dev/null || true
  sed -i -E 's/^[#[:space:]]*PasswordAuthentication.*/PasswordAuthentication yes/' "$config_path" 2>/dev/null || true
  sed -i -E 's/^[#[:space:]]*PubkeyAuthentication.*/PubkeyAuthentication yes/' "$config_path" 2>/dev/null || true
  sed -i -E 's/^[#[:space:]]*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' "$config_path" 2>/dev/null || true

  # 有些极端的镜像会直接把 PasswordAuthentication no 写好几遍，甚至藏在别的 drop-in 里。
  # 我们强行剔除其他零散文件里的阻碍
  if ls /etc/ssh/sshd_config.d/*.conf 1> /dev/null 2>&1; then
      for f in /etc/ssh/sshd_config.d/*.conf; do
          if [ "$f" != "{sshd_primary_drop_in_path}" ]; then
              sed -i -E 's/^[#[:space:]]*(PasswordAuthentication|PermitRootLogin)[[:space:]]+no/# &/' "$f" 2>/dev/null || true
          fi
      done
  fi

  grep -q '^PermitRootLogin ' "$config_path" || printf '\n%s\n' 'PermitRootLogin yes' >> "$config_path"
  grep -q '^PasswordAuthentication ' "$config_path" || printf '%s\n' 'PasswordAuthentication yes' >> "$config_path"
  grep -q '^PubkeyAuthentication ' "$config_path" || printf '%s\n' 'PubkeyAuthentication yes' >> "$config_path"
  grep -q '^ChallengeResponseAuthentication ' "$config_path" || printf '%s\n' 'ChallengeResponseAuthentication no' >> "$config_path"

  # 无论如何暴力统一注入内置 internal-sftp 子系统来抵抗外部缺失包
  sed -i -E 's/^[#[:space:]]*Subsystem[[:space:]]+sftp.*/Subsystem sftp internal-sftp/' "$config_path" 2>/dev/null || true
  grep -q '^Subsystem sftp ' "$config_path" || printf '\n%s\n' 'Subsystem sftp internal-sftp' >> "$config_path"

  if [ "{family_str}" != "alpine" ]; then
    sed -i -E 's/^[#[:space:]]*UsePAM.*/UsePAM yes/' "$config_path" 2>/dev/null || true
    grep -q '^UsePAM ' "$config_path" || printf '%s\n' 'UsePAM yes' >> "$config_path"
  fi
}}

disable_firewall() {{
  if command -v ufw >/dev/null 2>&1; then
    ufw disable || true
  fi

  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now firewalld 2>/dev/null || true
  fi
}}

echo "Installing base packages..."
ensure_dns_fallback
wait_for_network || true
{package_install_command} || true

command -v update-ca-certificates >/dev/null 2>&1 && update-ca-certificates || true
command -v ssh-keygen >/dev/null 2>&1 && ssh-keygen -A || true

echo "Configuring SSH access..."
disable_firewall
write_sshd_dropin
update_sshd_main_config

for user in $DEFAULT_USERS; do
  set_password "$user"
  set_authorized_key "$user"
done

if command -v restorecon >/dev/null 2>&1; then
  restorecon -RF /root/.ssh /etc/ssh /home 2>/dev/null || true
fi

echo "Enabling serial console..."
{serial_console_commands}

echo "Enabling guest services..."
{service_enable_commands}

echo "Installing persistent IPv4-only guard for primary NIC..."
cat > /usr/local/bin/incudal-ipv4-only.sh <<'EOF'
#!/bin/sh
set -e

PRIMARY_IFACE="$(ip -4 route show default 2>/dev/null | awk '/default/ {{print $5; exit}}')"
if [ -z "$PRIMARY_IFACE" ]; then
  PRIMARY_IFACE="$(ip route show default 2>/dev/null | awk '/default/ {{for(i=1;i<=NF;i++) if($i=="dev") {{print $(i+1); exit}}}}')"
fi
if [ -z "$PRIMARY_IFACE" ]; then
  PRIMARY_IFACE="eth0"
fi

mkdir -p /etc/sysctl.d
cat > /etc/sysctl.d/99-incudal-ipv4-only.conf <<CONF
net.ipv6.conf.\${{PRIMARY_IFACE}}.disable_ipv6 = 1
net.ipv6.conf.\${{PRIMARY_IFACE}}.accept_ra = 0
net.ipv6.conf.\${{PRIMARY_IFACE}}.autoconf = 0
CONF

sysctl -p /etc/sysctl.d/99-incudal-ipv4-only.conf >/dev/null 2>&1 || true
ip -6 addr flush dev "\${{PRIMARY_IFACE}}" scope global >/dev/null 2>&1 || true
ip -6 route del default dev "\${{PRIMARY_IFACE}}" >/dev/null 2>&1 || true
EOF
chmod +x /usr/local/bin/incudal-ipv4-only.sh
/usr/local/bin/incudal-ipv4-only.sh || true

if command -v systemctl >/dev/null 2>&1; then
  cat > /etc/systemd/system/incudal-ipv4-only.service <<'EOF'
[Unit]
Description=Incudal primary NIC IPv4-only guard
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/incudal-ipv4-only.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload || true
  systemctl enable incudal-ipv4-only.service || true
  systemctl start incudal-ipv4-only.service || true
elif [ -d /etc/local.d ]; then
  cat > /etc/local.d/incudal-ipv4-only.start <<'EOF'
#!/bin/sh
/usr/local/bin/incudal-ipv4-only.sh || true
EOF
  chmod +x /etc/local.d/incudal-ipv4-only.start
  rc-update add local default 2>/dev/null || true
  /etc/local.d/incudal-ipv4-only.start || true
fi

{ipv6_guard_section}

echo "Running user custom commands..."
{extra_commands}
"#
    )
}

// ==================== cloud-init: user-data ====================

fn generate_user_data(params: &IncusConfigParams, os_info: &VmOsInfo) -> String {
    let setup_script_content = generate_setup_script(params, os_info);
    let yaml_safe_password = escape_for_yaml_single_quote(&params.root_password);
    let packages = get_cloud_init_packages(os_info);
    let packages_section = if !packages.is_empty() {
        format!(
            "packages:\n{}\n\n",
            packages
                .iter()
                .map(|pkg| format!("  - {pkg}"))
                .collect::<Vec<_>>()
                .join("\n")
        )
    } else {
        String::new()
    };
    let ssh_key_section = params
        .ssh_key
        .as_deref()
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .map(|key| format!("    ssh_authorized_keys:\n      - {key}\n"))
        .unwrap_or_default();

    format!(
        "#cloud-config\npackage_update: {}\npackage_upgrade: false\nhostname: {}\nmanage_etc_hosts: true\n\n{}users:\n  - default\n  - name: root\n    lock_passwd: false\n    shell: {}\n{}chpasswd:\n  expire: false\n  list:\n    - 'root:{}'\n\nssh_pwauth: true\ndisable_root: false\n\nwrite_files:\n  - path: /root/incudal-vm-setup.sh\n    permissions: '0755'\n    owner: root:root\n    content: |\n{}runcmd:\n  - [ \"/bin/sh\", \"-c\", \"/root/incudal-vm-setup.sh\" ]\n",
        if !packages.is_empty() { "true" } else { "false" },
        params.instance_name,
        packages_section,
        os_info.default_shell,
        ssh_key_section,
        yaml_safe_password,
        indent_string(&setup_script_content, 6)
    )
}

// ==================== cloud-init: network-config ====================

fn generate_dhcp_network_config(nic_macs: &VmNicMacs) -> String {
    format!(
        "version: 2\nethernets:\n  incus_eth0:\n    match:\n{}\n    dhcp4: true\n    dhcp6: false\n    accept-ra: false\n    link-local: [ ipv4 ]\n",
        get_network_match_yaml(&nic_macs.eth0)
    )
}

fn generate_network_config(
    net: Option<&StaticNetworkConfig>,
    nic_macs: &VmNicMacs,
) -> String {
    let Some(net) = net else {
        return generate_dhcp_network_config(nic_macs);
    };

    let dns_v4: Vec<String> = if net.dns.as_ref().map(|d| !d.is_empty()).unwrap_or(false) {
        net.dns.clone().expect("checked")
    } else {
        DEFAULT_DNS_V4.iter().map(|d| d.to_string()).collect()
    };
    let dns_v6: Vec<String> = if net
        .ipv6_dns
        .as_ref()
        .map(|d| !d.is_empty())
        .unwrap_or(false)
    {
        net.ipv6_dns.clone().expect("checked")
    } else {
        DEFAULT_DNS_V6.iter().map(|d| d.to_string()).collect()
    };

    let ipv4_section = match (&net.ip_address, &net.gateway) {
        (Some(ip), Some(gateway)) => format!(
            "  incus_eth0:\n    match:\n{}\n    dhcp4: false\n    dhcp6: false\n    accept-ra: false\n    link-local: [ ipv4 ]\n    addresses:\n      - {ip}\n    gateway4: {gateway}\n    nameservers:\n      addresses:\n{}",
            get_network_match_yaml(&nic_macs.eth0),
            dns_v4
                .iter()
                .map(|dns| format!("        - {dns}"))
                .collect::<Vec<_>>()
                .join("\n")
        ),
        _ => String::new(),
    };

    let Some(ipv6_address) = &net.ipv6_address else {
        if ipv4_section.is_empty() {
            return generate_dhcp_network_config(nic_macs);
        }
        return format!("version: 2\nethernets:\n{ipv4_section}\n");
    };

    let ipv6_section = format!(
        "  incus_eth1:\n    match:\n{}\n    dhcp4: false\n    dhcp6: false\n    accept-ra: false\n    addresses:\n      - {}\n    routes:\n      - to: ::/0\n        via: {}\n        on-link: true\n    nameservers:\n      addresses:\n{}",
        get_network_match_yaml(&nic_macs.eth1),
        normalize_ipv6_address(ipv6_address),
        DEFAULT_IPV6_GATEWAY,
        dns_v6
            .iter()
            .map(|dns| format!("        - {dns}"))
            .collect::<Vec<_>>()
            .join("\n")
    );

    format!("version: 2\nethernets:\n{ipv4_section}\n{ipv6_section}\n")
}

// ==================== main entry ====================

/// Mirrors `generateVmConfig`.
pub fn generate_vm_config(params: &IncusConfigParams) -> IncusConfigResult {
    let os_info = detect_vm_os_info(&params.image_alias);
    let nic_macs = generate_vm_nic_macs(
        params
            .instance_id_seed
            .as_deref()
            .unwrap_or(&params.instance_name),
    );

    IncusConfigResult {
        config_payload: IncusConfigPayload {
            user_data: generate_user_data(params, &os_info),
            network_config: generate_network_config(params.network.as_ref(), &nic_macs),
        },
        meta_data: None,
    }
}
