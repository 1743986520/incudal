#!/usr/bin/env bash
# ============================================================================
# Incudal 节点安装管理脚本
# 将 Ubuntu / Debian 服务器配置为 Incudal 面板管理的 Incus LXC 容器节点
#
# 用法:
#   交互式: sudo bash Incudal.sh
#   命令行: sudo bash Incudal.sh --mode nat --token <TOKEN>
#   卸载:   sudo bash Incudal.sh --uninstall
#
# 项目地址: https://incudal.com
# ============================================================================
set -euo pipefail

# ========面板动态注入区========
# 面板在下载时自动注入以下变量，无需手动修改
INJECT_PANEL_URL=""
INJECT_TOKEN=""
INJECT_MODE=""
INJECT_IPV6_SUBNET=""
INJECT_IPV6_IFACE=""
INJECT_AGENT_ID=""
INJECT_AGENT_SECRET=""
INJECT_AGENT_INSTALL_TOKEN=""
INJECT_AGENT_BINARY_URL=""
INJECT_AGENT_BINARY_SHA256=""
INJECT_AGENT_ENABLED="true"
INJECT_PPS_LIMIT=""
# ==============================

# ========================== 全局常量 ==========================
PANEL_URL="${INJECT_PANEL_URL:-}"
PANEL_URL="${PANEL_URL%/}"
readonly PANEL_URL
readonly SCRIPT_VERSION="2.1.1"
BRIDGE_SUBNET="10.10.0.1/22"
readonly BRIDGE_NAME="incusbr0"
readonly PRESEED_FILE="/tmp/.incus-preseed-$$.yaml"
readonly AGENT_ID="${INJECT_AGENT_ID:-}"
readonly AGENT_SECRET="${INJECT_AGENT_SECRET:-}"
readonly AGENT_INSTALL_TOKEN="${INJECT_AGENT_INSTALL_TOKEN:-}"
readonly AGENT_BINARY_URL="${INJECT_AGENT_BINARY_URL:-}"
readonly AGENT_BINARY_SHA256="${INJECT_AGENT_BINARY_SHA256:-}"
readonly AGENT_ENABLED="${INJECT_AGENT_ENABLED:-true}"
readonly AGENT_SERVICE_NAME="incudal-agent"
readonly AGENT_CONFIG_FILE="${INCUDAL_AGENT_CONFIG_FILE:-/etc/incudal-agent/config.yaml}"
readonly AGENT_BIN_PATH="${INCUDAL_AGENT_BIN:-/usr/local/bin/incudal-agent}"

if [[ -n "$PANEL_URL" && ! "$PANEL_URL" =~ ^https://[^[:space:]]+$ ]]; then
    echo "[✗] PANEL_URL must use https" >&2
    exit 1
fi

# ========================== 颜色定义 ==========================
readonly RED='\033[1;31m'
readonly GREEN='\033[1;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[1;34m'
readonly CYAN='\033[1;36m'
readonly BOLD='\033[1m'
readonly DIM='\033[2m'
readonly NC='\033[0m'

# ========================== 运行时变量 ==========================
MODE=""
TOKEN=""
OS_ID=""
OS_VERSION=""
OS_CODENAME=""
ARCH=""
DEFAULT_IFACE=""
IS_PURE_IPV6="false"
AGENT_INSTALL_STATUS="未安装"
AGENT_HEARTBEAT_INTERVAL_SECONDS="30"
PPS_PROTECTION_ENABLED="true"
PPS_LIMIT="${INJECT_PPS_LIMIT:-20000}"
PPS_OPTION_EXPLICIT="false"
INCUS_PRESEED_ACTIVE="false"
# Storage is deliberately opt-in. The storage module prompts in TTY mode and
# defaults non-interactive installs to a dependency-free DIR pool.
STORAGE_DRIVER="${INJECT_STORAGE_DRIVER:-}"
STORAGE_POOL_NAME="${INJECT_STORAGE_POOL_NAME:-}"
STORAGE_SOURCE="${INJECT_STORAGE_SOURCE:-}"
STORAGE_SIZE="${INJECT_STORAGE_SIZE:-}"
# nftables 的 limit 是 token bucket；这里保留原有突发余量，仅用于实例级
# 网络层保护。单目标安全事件不会再把普通 TCP 下载流量当成异常发包。
readonly PPS_BURST_PACKETS="5000"
readonly PPS_MIN_LIMIT="20000"
readonly PPS_SINGLE_TARGET_LIMIT="20000"
readonly PPS_SINGLE_TARGET_BURST="2500"
readonly PPS_BLOCK_SECONDS="3600"
readonly PPS_OBSERVE_SECONDS="120"

# ========================== 工具函数 ==========================
log()   { echo -e "${GREEN}[✓]${NC} $1"; }
info()  { echo -e "${BLUE}[i]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }

# Incus dnsmasq cannot bind when the selected bridge gateway is already used
# by another interface/network. Pick the first RFC1918 /22 that does not
# overlap any existing IPv4 address or route on the host.
select_bridge_subnet() {
    local candidates=(
        "10.10.0.1/22" "10.20.0.1/22" "10.30.0.1/22" "10.40.0.1/22"
        "10.64.0.1/22" "10.80.0.1/22" "10.96.0.1/22" "10.112.0.1/22"
    )
    local candidate
    local existing_networks

    existing_networks="$({ ip -o -4 addr show 2>/dev/null | awk '{print $4}'; ip -4 route show table all 2>/dev/null | awk '$1 ~ /^[0-9]+\./ {print $1}'; } | sort -u)"

    for candidate in "${candidates[@]}"; do
        if command -v python3 &>/dev/null; then
            if CANDIDATE="$candidate" EXISTING_NETWORKS="$existing_networks" python3 - <<'PY'
import ipaddress
import os

candidate = ipaddress.ip_interface(os.environ["CANDIDATE"]).network
for value in os.environ.get("EXISTING_NETWORKS", "").splitlines():
    try:
        if candidate.overlaps(ipaddress.ip_network(value, strict=False)):
            raise SystemExit(1)
    except ValueError:
        pass
PY
            then
                if [[ "$candidate" != "$BRIDGE_SUBNET" ]]; then
                    warn "默认网桥子网 ${BRIDGE_SUBNET} 与现有网络冲突，已自动改用 ${candidate}"
                fi
                BRIDGE_SUBNET="$candidate"
                return 0
            fi
        else
            local gateway="${candidate%/*}"
            if ! ip -o -4 addr show 2>/dev/null | grep -qw "$gateway"; then
                BRIDGE_SUBNET="$candidate"
                return 0
            fi
        fi
    done

    error "未找到可用的 Incus 私有网桥子网，请检查现有路由配置"
    return 1
}

# The distro dnsmasq package may automatically start a standalone daemon that
# listens on 0.0.0.0:53. Incus launches its own per-network dnsmasq process and
# cannot bind the bridge gateway while that system service owns the wildcard
# socket. Keep the binary installed, but disable only the standalone service.
prepare_incus_dnsmasq() {
    local was_active="false"

    if command -v systemctl &>/dev/null; then
        if systemctl is-active --quiet dnsmasq.service 2>/dev/null; then
            was_active="true"
        fi
        systemctl disable --now dnsmasq.service >/dev/null 2>&1 || true
    elif command -v rc-service &>/dev/null; then
        if rc-service dnsmasq status >/dev/null 2>&1; then
            was_active="true"
        fi
        rc-service dnsmasq stop >/dev/null 2>&1 || true
        rc-update del dnsmasq default >/dev/null 2>&1 || true
    fi

    if [[ "$was_active" == "true" ]]; then
        info "已停止系统 dnsmasq 服务，端口 53 将由 Incus 网桥独立管理"
    fi
}
error() { echo -e "${RED}[✗]${NC} $1"; }
step()  { echo -e "\n${CYAN}[▶]${NC} ${BOLD}$1${NC}"; }

# 分隔线
divider() {
    echo -e "${DIM}────────────────────────────────────────────────────${NC}"
}

pause_return() {
    if [[ -t 0 ]]; then
        echo ""
        echo -ne "  ${DIM}按回车返回菜单...${NC}"
        read -r _
    fi
}

mask_value() {
    local value="${1:-}"
    local length=${#value}
    if [[ -z "$value" ]]; then
        echo "-"
    elif (( length <= 12 )); then
        echo "${value:0:4}****"
    else
        echo "${value:0:8}...${value: -4}"
    fi
}

is_https_url() {
    local value="${1:-}"
    [[ "$value" =~ ^https://[^[:space:]]+$ ]]
}

read_agent_config_value() {
    local key="$1"
    if [[ ! -f "$AGENT_CONFIG_FILE" ]]; then
        return 0
    fi

    local line=""
    line=$(grep -E "^[[:space:]]*${key}[[:space:]]*:" "$AGENT_CONFIG_FILE" 2>/dev/null | head -n1 || true)
    if [[ -z "$line" ]]; then
        return 0
    fi

    local value="${line#*:}"
    value=$(printf '%s' "$value" | sed -E "s/[[:space:]]+#.*$//; s/^[[:space:]]+//; s/[[:space:]]+$//; s/^\"(.*)\"$/\1/; s/^'(.*)'$/\1/")
    printf '%s\n' "$value"
}

get_agent_panel_url() {
    local config_panel_url=""
    config_panel_url=$(read_agent_config_value "panel_url" || true)
    if [[ -n "$config_panel_url" ]]; then
        echo "${config_panel_url%/}"
        return 0
    fi
    if [[ -n "$PANEL_URL" ]]; then
        echo "${PANEL_URL%/}"
        return 0
    fi
    return 0
}

extract_agent_install_token() {
    local input="$1"
    printf '%s\n' "$input" | grep -Eo 'ait_[A-Za-z0-9_-]{32,}' | head -n1 || true
}

extract_agent_panel_url() {
    local input="$1"
    printf '%s\n' "$input" \
        | sed -nE "s#.*(https?://[^[:space:]'\\\"]+)/api/agent/install\\.sh.*#\\1#p" \
        | head -n1 || true
}

normalize_agent_interval() {
    local value="${1:-30}"
    if [[ "$value" =~ ^[0-9]+$ ]] && (( value >= 5 && value <= 3600 )); then
        echo "$value"
    else
        echo "30"
    fi
}

prompt_agent_heartbeat_interval() {
    local default_interval=""
    default_interval=$(normalize_agent_interval "${1:-30}")

    if [[ ! -t 0 ]]; then
        AGENT_HEARTBEAT_INTERVAL_SECONDS="$default_interval"
        return 0
    fi

    echo -ne "  ${BOLD}Agent 上报间隔秒数 [默认 ${default_interval}，范围 5-3600]: ${NC}"
    local agent_interval=""
    read -r agent_interval

    if [[ -z "$agent_interval" ]]; then
        AGENT_HEARTBEAT_INTERVAL_SECONDS="$default_interval"
    elif [[ "$agent_interval" =~ ^[0-9]+$ ]] && (( agent_interval >= 5 && agent_interval <= 3600 )); then
        AGENT_HEARTBEAT_INTERVAL_SECONDS="$agent_interval"
    else
        warn "Agent 上报间隔无效，已使用默认 ${default_interval} 秒"
        AGENT_HEARTBEAT_INTERVAL_SECONDS="$default_interval"
    fi
}

show_agent_summary_line() {
    local label="${DIM}未安装${NC}"
    if command -v systemctl &>/dev/null && systemctl is-active --quiet "$AGENT_SERVICE_NAME" 2>/dev/null; then
        label="${GREEN}运行中${NC}"
    elif command -v rc-service &>/dev/null && rc-service "$AGENT_SERVICE_NAME" status >/dev/null 2>&1; then
        label="${GREEN}运行中${NC}"
    elif [[ -f "$AGENT_CONFIG_FILE" || -x "$AGENT_BIN_PATH" ]]; then
        label="${YELLOW}已安装（未运行）${NC}"
    fi
    echo -e "  Agent    :  ${label}"
}

# 清理临时文件
cleanup() {
    rm -f "$PRESEED_FILE" 2>/dev/null || true
}

# Keep failures from disappearing back into the SSH prompt.  The preseed file
# is intentionally printed on an unexpected exit so a remote installer can
# be diagnosed without needing an interactive shell on the target host.
installer_exit() {
    local exit_code=$?
    trap - EXIT
    if (( exit_code != 0 )); then
        error "安装脚本异常退出（退出码 ${exit_code}，命令: ${BASH_COMMAND:-unknown}）"
        if [[ "${INCUS_PRESEED_ACTIVE:-false}" == "true" && -f "$PRESEED_FILE" ]]; then
            error "检测到未完成的 Incus preseed，配置如下："
            sed 's/^/  | /' "$PRESEED_FILE" >&2 || true
        fi
    fi
    cleanup
    exit "$exit_code"
}
trap installer_exit EXIT

# ========================== 显示横幅 ==========================
show_banner() {
    clear 2>/dev/null || true
    echo ""
    echo -e "${CYAN}  ╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}  ║                                                  ║${NC}"
    echo -e "${CYAN}  ║            ${BOLD}Incudal 节点安装管理脚本${NC}${CYAN}              ║${NC}"
    echo -e "${CYAN}  ║            ${DIM}LXC Container Host Setup${NC}${CYAN}              ║${NC}"
    echo -e "${CYAN}  ║                                                  ║${NC}"
    echo -e "${CYAN}  ╚══════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${DIM}版本: ${SCRIPT_VERSION}  |  面板: ${PANEL_URL}${NC}"
    echo ""
}

# ========================== 系统检测 ==========================
detect_system() {
    # 检测 /etc/os-release 是否存在
    if [[ ! -f /etc/os-release ]]; then
        error "无法检测操作系统（/etc/os-release 不存在）"
        exit 1
    fi

    source /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_VERSION="${VERSION_ID:-unknown}"
    OS_CODENAME="${VERSION_CODENAME:-unknown}"

    if [[ -n "${INCUDAL_PLATFORM_OS:-}" && "$OS_ID" != "$INCUDAL_PLATFORM_OS" ]]; then
        error "平台脚本与实际系统不匹配: 期望 ${INCUDAL_PLATFORM_OS}，实际 ${OS_ID}"
        exit 1
    fi

    ARCH=$(dpkg --print-architecture 2>/dev/null || uname -m)
    [[ "$ARCH" == "x86_64" ]] && ARCH="amd64"
    [[ "$ARCH" == "aarch64" ]] && ARCH="arm64"

    # Ubuntu/Debian use Zabbly packages; Rocky 10 uses the Incus COPR repository.
    if [[ "$OS_ID" != "ubuntu" && "$OS_ID" != "debian" && "$OS_ID" != "rocky" && "$OS_ID" != "alpine" ]]; then
        error "不支持的操作系统: ${OS_ID}"
        error "本脚本支持 Ubuntu、Debian、Rocky Linux 9/10 和 Alpine Linux 3.20+"
        exit 1
    fi

    # 版本兼容性检查
    case "$OS_ID" in
        ubuntu)
            # 建议 Ubuntu 22.04+
            local ubuntu_major="${OS_VERSION%%.*}"
            if [[ "$ubuntu_major" -lt 22 ]] 2>/dev/null; then
                warn "Ubuntu 版本较低 (${OS_VERSION})，建议使用 22.04 或 24.04"
                echo -ne "  是否继续？[y/N]: "
                read -r confirm
                [[ "$confirm" =~ ^[yY]$ ]] || exit 0
            fi
            ;;
        debian)
            # 最低 Debian 11 (Bullseye)
            local deb_major="${OS_VERSION%%.*}"
            if [[ "$deb_major" -lt 11 ]] 2>/dev/null; then
                error "Debian 版本过低 (${OS_VERSION})，最低要求 Debian 11 (Bullseye)"
                exit 1
            fi
            ;;
        rocky)
            local rocky_major="${OS_VERSION%%.*}"
            if [[ "$rocky_major" -ne 9 && "$rocky_major" -ne 10 ]] 2>/dev/null; then
                error "Rocky Linux 版本不受支持 (${OS_VERSION})，目前支持 Rocky Linux 9 和 10"
                exit 1
            fi
            ;;
        alpine)
            local alpine_major="${OS_VERSION%%.*}"
            local alpine_minor="${OS_VERSION#*.}"; alpine_minor="${alpine_minor%%.*}"
            if (( alpine_major < 3 || (alpine_major == 3 && alpine_minor < 20) )); then
                error "Alpine Linux 版本过低 (${OS_VERSION})，最低要求 3.20"
                exit 1
            fi
            ;;
    esac

    # 检测默认网络接口
    DEFAULT_IFACE=$(ip route get 8.8.8.8 2>/dev/null | awk -F'dev ' '{print $2}' | awk '{print $1}' | head -n1 || true)
    if [[ -z "$DEFAULT_IFACE" ]]; then
        warn "无法通过默认路由检测网络接口"
        # 回退：获取第一个非 lo 的 UP 接口
        DEFAULT_IFACE=$(ip -o link show up 2>/dev/null | awk -F': ' '{print $2}' | grep -v lo | head -n1 || true)
        if [[ -z "$DEFAULT_IFACE" ]]; then
            error "未找到可用的网络接口"
            exit 1
        fi
        info "使用备选接口: ${DEFAULT_IFACE}"
    fi

    # 纯 IPv6 环境检测 (双通道并发)
    if ! curl -4 -s --connect-timeout 2 1.1.1.1 >/dev/null 2>&1; then
        if curl -6 -s --connect-timeout 2 "https://[2606:4700:4700::1111]" >/dev/null 2>&1; then
            IS_PURE_IPV6="true"
            info "检测到当前服务器为【纯 IPv6 (Pure IPv6)】"
        fi
    fi
}

# ========================== 显示系统信息 ==========================
show_system_info() {
    divider
    echo -e "  ${BOLD}系统信息${NC}"
    divider

    # 操作系统名称格式化
    local os_label=""
    case "$OS_ID" in
        ubuntu) os_label="Ubuntu" ;;
        debian) os_label="Debian" ;;
        *)      os_label="$OS_ID" ;;
    esac

    echo -e "  操作系统  :  ${GREEN}${os_label} ${OS_VERSION}${NC} (${OS_CODENAME})"
    echo -e "  系统架构  :  ${GREEN}${ARCH}${NC}"
    echo -e "  默认接口  :  ${GREEN}${DEFAULT_IFACE}${NC}"
    echo -e "  主 机 名  :  ${GREEN}$(hostname)${NC}"

    if [[ "$IS_PURE_IPV6" == "true" ]]; then
        echo -e "  网络环境  :  ${YELLOW}纯 IPv6 (Pure IPv6) - 将启用 WARP 出站接力${NC}"
    else
        echo -e "  网络环境  :  ${GREEN}原生 IPv4 可达${NC}"
    fi

    # 检查 Incus 安装状态
    if command -v incus &>/dev/null; then
        local incus_ver
        incus_ver=$(incus version 2>/dev/null | awk '/Client version/ {print $3}' || echo "未知")
        [[ -z "$incus_ver" ]] && incus_ver="未知"

        # 判断服务端是否能连通
        if ! incus version 2>/dev/null | grep -q -E "Server version: [0-9]"; then
            echo -e "  Incus     :  ${YELLOW}客户端残留（服务未在运行）${NC} (${incus_ver})"
        else
            echo -e "  Incus     :  ${GREEN}已安装并运行${NC} (${incus_ver})"
        fi

        # 检查网桥
        if incus network show "$BRIDGE_NAME" &>/dev/null; then
            echo -e "  网桥状态  :  ${YELLOW}${BRIDGE_NAME} 已存在${NC}"
        else
            echo -e "  网桥状态  :  ${DIM}未初始化${NC}"
        fi

        # 检查面板证书
        if incus config trust list --format csv 2>/dev/null | grep -q "panel"; then
            echo -e "  面板证书  :  ${YELLOW}已导入${NC}"
        else
            echo -e "  面板证书  :  ${DIM}未导入${NC}"
        fi
    else
        echo -e "  Incus     :  ${DIM}未安装${NC}"
    fi

    # 检查 RFW 防火墙状态
    if [[ -f /root/rfw/rfw ]]; then
        if systemctl is-active --quiet rfw 2>/dev/null; then
            local rfw_rules="未知"
            if [[ -f /etc/systemd/system/rfw.service ]]; then
                local exec_start
                exec_start=$(grep "^ExecStart=" /etc/systemd/system/rfw.service 2>/dev/null || true)
                if [[ "$exec_start" =~ "--block-all" ]] && [[ ! "$exec_start" =~ "--block-all-from" ]]; then
                    rfw_rules="全部阻止"
                else
                    rfw_rules=$(echo "$exec_start" | grep -o -- "--block-[a-z0-9-]*" | sed 's/--block-//g' | tr '\n' '/' | sed 's/\/$//')
                    [[ -z "$rfw_rules" ]] && rfw_rules="无协议过滤"
                fi

                local geo="无GeoIP"
                if [[ "$exec_start" =~ --countries\ ([A-Za-z,]*) ]]; then
                    geo="黑名单:${BASH_REMATCH[1]}"
                elif [[ "$exec_start" =~ --allow-only-countries\ ([A-Za-z,]*) ]]; then
                    geo="白名单:${BASH_REMATCH[1]}"
                elif [[ "$exec_start" =~ --block-all-from\ ([A-Za-z,]*) ]]; then
                    geo="黑名单:${BASH_REMATCH[1]}"
                fi
                rfw_rules="${rfw_rules} | ${geo}"
            fi
            echo -e "  RFW 防火墙:  ${GREEN}运行中${NC} (${rfw_rules})"
        else
            echo -e "  RFW 防火墙:  ${YELLOW}已安装（未运行）${NC}"
        fi
    else
        echo -e "  RFW 防火墙:  ${DIM}未安装${NC}"
    fi

    show_agent_summary_line

    divider
    echo ""
}

# ========================== 交互式菜单 ==========================
show_menu() {
    echo -e "  ${BOLD}请选择操作：${NC}"
    echo ""
    echo -e "    ${CYAN}1)${NC}  安装节点  ${DIM}─  仅 IPv4${NC}"
    echo -e "    ${CYAN}2)${NC}  安装节点  ${DIM}─  IPv4 + IPv6（自动检测配置）${NC}"
    echo -e "    ${CYAN}3)${NC}  安装 RFW  ${DIM}─  入站流量屏蔽防火墙${NC}"
    echo -e "    ${CYAN}4)${NC}  查看系统信息"
    echo -e "    ${CYAN}7)${NC}  网络模式说明（必看说明）"
    echo -e "    ${CYAN}8)${NC}  Agent 管理  ${DIM}─  安装 / 更新宿主机 Agent${NC}"
    echo -e "    ${CYAN}9)${NC}  PPS 防护管理  ${DIM}─  为每台实例限制异常发包${NC}"
    echo ""
    echo -e "    ${RED}5)${NC}  卸载 RFW  ${DIM}─  移除 RFW 防火墙${NC}"
    echo -e "    ${RED}6)${NC}  卸载节点  ${DIM}─  彻底清理还原系统${NC}"
    echo -e "    ${CYAN}0)${NC}  退出"
    echo ""
    echo -ne "  ${BOLD}请输入选项 [0-9]: ${NC}"
}

# ========================== 网络模式说明 ==========================
show_network_mode_help() {
    echo ""
    divider
    echo -e "  ${BOLD}面板支持的网络模式说明${NC}"
    divider
    echo ""
    echo -e "  ${BOLD}节点安装模式（本脚本选择）：${NC}"
    echo ""
    echo -e "  ${CYAN}模式 1：仅 IPv4${NC}"
    echo -e "  节点只启用 IPv4 NAT 网桥，容器通过端口映射访问。"
    echo -e "  适合没有 IPv6 网段或不需要 IPv6 的场景。"
    echo ""
    echo -e "  ${CYAN}模式 2：IPv4 + IPv6${NC}"
    echo -e "  节点同时启用 IPv4 NAT 和 IPv6 路由转发。"
    echo -e "  安装后可在面板创建以下任意 IPv6 网络模式的实例。"
    echo ""
    echo -e "  ${BOLD}面板实例网络模式（在面板创建实例/套餐时选择）：${NC}"
    echo ""
    echo -e "  ${GREEN}IPv4 NAT${NC}"
    echo -e "  宿主机仅有 IPv4，通过端口映射给容器提供对外服务。"
    echo -e "  ${DIM}节点要求：模式 1 或 模式 2 均可${NC}"
    echo ""
    echo -e "  ${GREEN}IPv4 NAT + IPv6${NC}"
    echo -e "  宿主机拥有 IPv4 + 独立公网 IPv6 地址（双栈）。"
    echo -e "  IPv4 通过端口映射，IPv6 根据网段选择独立分配给容器。"
    echo -e "  ${DIM}节点要求：模式 2 + 配置 IPv6 子网${NC}"
    echo ""
    echo -e "  ${GREEN}IPv4 NAT + IPv6 NAT${NC}"
    echo -e "  宿主机拥有 IPv4 + IPv6（均为 NAT 共享宿主机出口）。"
    echo -e "  适用于宿主机只有单个 IPv6 地址或者不分配 IPv6 网段，全局共享宿主机的 IPv6。"
    echo -e "  ${DIM}节点要求：模式 2，无需 IPv6 子网${NC}"
    echo ""
    echo -e "  ${GREEN}IPv6 Only${NC}"
    echo -e "  宿主机仅有独立公网 IPv6（无 IPv4）。"
    echo -e "  ${DIM}节点要求：模式 2 + 配置 IPv6 子网${NC}"
    echo ""
    echo -e "  ${GREEN}IPv6 NAT${NC}"
    echo -e "  宿主机仅有单个 IPv6（共享宿主机 IPv6 出口，无 IPv4）。"
    echo -e "  ${DIM}节点要求：模式 2，无需 IPv6 子网${NC}"
    echo ""
    echo -e "  ${YELLOW}提示：${NC}本脚本选择模式 2 后，会自动检测宿主机 IPv6，"
    echo -e "  并帮助计算适合面板使用的 IPv6 子网。安装完成后在面板"
    echo -e "  「节点管理」中填入子网信息即可。"
    echo ""
    divider
    echo ""
}

# ========================== 读取 Token ==========================
read_token() {
    echo ""
    divider
    echo -e "  ${BOLD}请输入面板 Token${NC}"
    echo -e "  ${DIM}Token 可在面板「节点管理 → 添加节点」中获取${NC}"
    divider
    echo ""

    while true; do
        echo -ne "  ${CYAN}Token: ${NC}"
        read -r TOKEN

        # 非空检查
        if [[ -z "$TOKEN" ]]; then
            warn "Token 不能为空，请重新输入"
            continue
        fi

        # 去除首尾空格
        TOKEN=$(echo "$TOKEN" | xargs)

        # Token 格式校验（宽松匹配：允许较长的数字/字母/短横线组合）
        if [[ ! "$TOKEN" =~ ^[a-zA-Z0-9_-]{16,}$ ]]; then
            warn "Token 格式不符合预期（可能不完整或包含非法字符）"
            echo -e "  ${DIM}说明: Token 通常是一串较长的包含数字和字母的字符串${NC}"
            echo -ne "  是否仍要使用此 Token？[y/N]: "
            read -r confirm
            [[ "$confirm" =~ ^[yY]$ ]] || continue
        fi

        break
    done
}

# ========================== Agent 上报间隔 ==========================
configure_agent_heartbeat_interval() {
    if [[ "$AGENT_ENABLED" != "true" || ( -z "$AGENT_INSTALL_TOKEN" && ( -z "$AGENT_ID" || -z "$AGENT_SECRET" ) ) ]]; then
        AGENT_HEARTBEAT_INTERVAL_SECONDS="30"
        return 0
    fi

    if [[ ! -t 0 ]]; then
        AGENT_HEARTBEAT_INTERVAL_SECONDS="30"
        return 0
    fi

    echo -e "\n${CYAN}==> (可选) Agent 上报间隔${NC}"
    echo -e "  ${DIM}默认 30 秒；面板宿主机状态卡片会自动跟随此间隔刷新${NC}"
    echo -ne "  ${BOLD}Agent 上报间隔秒数 [默认 30，范围 5-3600]: ${NC}"
    local agent_interval=""
    read -r agent_interval

    if [[ -z "$agent_interval" ]]; then
        AGENT_HEARTBEAT_INTERVAL_SECONDS="30"
    elif [[ "$agent_interval" =~ ^[0-9]+$ ]] && (( agent_interval >= 5 && agent_interval <= 3600 )); then
        AGENT_HEARTBEAT_INTERVAL_SECONDS="$agent_interval"
    else
        warn "Agent 上报间隔无效，已使用默认 30 秒"
        AGENT_HEARTBEAT_INTERVAL_SECONDS="30"
    fi
}

# ========================== 安装确认 ==========================
confirm_install() {
    local mode_label=""
    case "$MODE" in
        nat)      mode_label="仅 IPv4" ;;
        nat_ipv6) mode_label="IPv4 + IPv6" ;;
    esac

    local os_label=""
    case "$OS_ID" in
        ubuntu) os_label="Ubuntu ${OS_VERSION}" ;;
        debian) os_label="Debian ${OS_VERSION}" ;;
        rocky)  os_label="Rocky Linux ${OS_VERSION}" ;;
        alpine) os_label="Alpine Linux ${OS_VERSION}" ;;
        *)      os_label="${OS_ID} ${OS_VERSION}" ;;
    esac

    # Token 脱敏显示（仅显示首8位和末4位）
    local token_masked="${TOKEN:0:8}····${TOKEN: -4}"

    echo ""
    divider
    echo -e "  ${BOLD}安装确认${NC}"
    divider
    echo -e "  操作系统  :  ${GREEN}${os_label}${NC} (${OS_CODENAME})"
    echo -e "  网络模式  :  ${GREEN}${mode_label}${NC}"
    echo -e "  网桥子网  :  ${GREEN}${BRIDGE_SUBNET}${NC}"
    if [[ -n "${IPV6_SUBNET:-}" ]]; then
        echo -e "  IPv6 子网 :  ${GREEN}${IPV6_SUBNET}${NC} (${IPV6_IFACE:-auto})"
    fi
    echo -e "  通信端口  :  ${GREEN}[::]:${LISTEN_PORT}${NC}"
    if [[ "${STORAGE_DRIVER:-none}" == "none" ]]; then
        echo -e "  存储池    :  ${YELLOW}跳过，安装后手动创建${NC}"
    else
        echo -e "  存储池    :  ${GREEN}${STORAGE_POOL_NAME} (${STORAGE_DRIVER})${NC}"
        [[ -n "${STORAGE_SOURCE:-}" ]] && echo -e "  存储源    :  ${GREEN}${STORAGE_SOURCE}${NC}"
        [[ -z "${STORAGE_SOURCE:-}" ]] && echo -e "  Loop 大小 :  ${GREEN}${STORAGE_SIZE}${NC}"
    fi
    if [[ "$PPS_PROTECTION_ENABLED" == "true" ]]; then
        echo -e "  PPS 防护  :  ${GREEN}每实例 ${PPS_LIMIT} 包/秒${NC}（突发 ${PPS_BURST_PACKETS} 包）"
        echo -e "  单 IP 检测:  ${GREEN}${PPS_SINGLE_TARGET_LIMIT} 包/秒；TCP SYN 封锁 ${PPS_BLOCK_SECONDS} 秒，UDP 仅观察${NC}"
    else
        echo -e "  PPS 防护  :  ${YELLOW}关闭${NC}"
    fi
    echo -e "  Token     :  ${GREEN}${token_masked}${NC}"
    if [[ "$AGENT_ENABLED" == "true" && ( -n "$AGENT_INSTALL_TOKEN" || ( -n "$AGENT_ID" && -n "$AGENT_SECRET" ) ) ]]; then
        echo -e "  Agent     :  ${GREEN}${AGENT_HEARTBEAT_INTERVAL_SECONDS} 秒上报${NC}"
    fi

    if [[ "$IS_PURE_IPV6" == "true" ]]; then
        if [[ "${SKIP_WARP:-false}" == "true" ]]; then
            echo -e "  IPv4 出站 :  ${YELLOW}已跳过 WARP (保持纯净原生 IPv6)${NC}"
        else
            echo -e "  IPv4 出站 :  ${GREEN}Cloudflare WARP 虚拟网络接驳${NC}"
        fi
    fi

    divider
    echo ""
    echo -ne "  ${YELLOW}确认开始安装？${NC}[y/N]: "
    read -r confirm
    if [[ ! "$confirm" =~ ^[yY]$ ]]; then
        info "已取消安装"
        exit 0
    fi
}
