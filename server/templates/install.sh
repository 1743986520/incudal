#!/usr/bin/env bash
set -euo pipefail

# This file is intentionally small. It validates the host, then downloads the
# OS-specific payload from the panel instead of shipping every distro branch.
INJECT_PANEL_URL=""
INJECT_TOKEN=""
readonly PANEL_URL="${INJECT_PANEL_URL%/}"

fail() { printf '[✗] %s\n' "$*" >&2; exit 1; }
info() { printf '[i] %s\n' "$*"; }

usage() {
  cat <<'EOF'
Incudal 节点安装引导脚本

用法:
  sudo bash incudal.sh                         交互式安装
  sudo bash incudal.sh --mode nat --token ...  非交互式安装
  sudo bash incudal.sh --storage-driver dir --token ...
  sudo bash incudal.sh --uninstall             卸载节点

引导脚本会先检测系统，再只下载对应发行版的安装脚本。
EOF
}

[[ -n "$PANEL_URL" ]] || fail "安装脚本未配置面板地址，请从面板重新下载"
[[ "$PANEL_URL" =~ ^https://[^[:space:]]+$ ]] || fail "面板地址必须使用 HTTPS"

if [[ "$EUID" -ne 0 ]]; then
  command -v sudo >/dev/null 2>&1 || fail "请以 root 权限运行此脚本"
  exec sudo -E bash "$0" "$@"
fi

command -v bash >/dev/null 2>&1 || fail "系统缺少 bash"
command -v curl >/dev/null 2>&1 || fail "系统缺少 curl，请先安装 curl"
[[ -r /etc/os-release ]] || fail "无法读取 /etc/os-release"
source /etc/os-release
OS_ID="${ID:-}"
OS_VERSION="${VERSION_ID:-}"

case "$OS_ID" in
  ubuntu) (( ${OS_VERSION%%.*} >= 22 )) 2>/dev/null || fail "Ubuntu ${OS_VERSION} 不受支持，最低要求 Ubuntu 22.04" ;;
  debian) (( ${OS_VERSION%%.*} >= 11 )) 2>/dev/null || fail "Debian ${OS_VERSION} 不受支持，最低要求 Debian 11" ;;
  rocky) [[ "${OS_VERSION%%.*}" == 9 || "${OS_VERSION%%.*}" == 10 ]] || fail "Rocky Linux ${OS_VERSION} 不受支持，目前支持 9/10" ;;
  alpine)
    alpine_major="${OS_VERSION%%.*}"
    alpine_minor="${OS_VERSION#*.}"
    alpine_minor="${alpine_minor%%.*}"
    (( alpine_major > 3 || (alpine_major == 3 && alpine_minor >= 20) )) 2>/dev/null || fail "Alpine Linux ${OS_VERSION} 不受支持，最低要求 Alpine 3.20"
    ;;
  *) fail "不支持的操作系统: ${OS_ID:-unknown}。支持 Ubuntu、Debian、Rocky Linux 9/10、Alpine 3.20+" ;;
esac

case "$(uname -m)" in
  x86_64|amd64|aarch64|arm64) ;;
  *) fail "不支持的系统架构: $(uname -m)" ;;
esac

install_token="$INJECT_TOKEN"
args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --token)
      [[ $# -ge 2 ]] || fail "--token 缺少参数"
      install_token="$2"
      shift 2
      ;;
    --help|-h) usage; exit 0 ;;
    *) args+=("$1"); shift ;;
  esac
done

# Uninstall/agent actions can use the generic payload. A normal node install
# uses the one-time token route so the panel can inject Agent credentials.
if [[ -z "$install_token" && ( "${args[0]:-}" == "--uninstall" || "${args[0]:-}" == "--agent" || "${args[0]:-}" == "--agent-menu" ) ]]; then
  payload_url="${PANEL_URL}/api/hosts/install.sh?stage=platform&os=${OS_ID}"
else
  if [[ -z "$install_token" ]]; then
    [[ -t 0 ]] || fail "非交互执行必须提供 --token"
    printf '请输入面板安装 Token: '
    read -r install_token
    [[ -n "$install_token" ]] || fail "Token 不能为空"
  fi
  payload_url="${PANEL_URL}/api/hosts/install.sh/${install_token}?stage=platform&os=${OS_ID}"
fi

payload_file="$(mktemp '/tmp/incudal-platform.XXXXXX.sh')"
cleanup() { rm -f "$payload_file"; }
trap cleanup EXIT

info "已检测到 ${PRETTY_NAME:-$OS_ID $OS_VERSION}"
info "正在下载 ${OS_ID} 专用安装脚本..."
curl -fL --retry 3 --connect-timeout 10 --max-time 300 \
  -H 'Cache-Control: no-cache' "$payload_url" -o "$payload_file" \
  || fail "平台安装脚本下载失败，请检查面板地址、Token 和网络连接"

head -n 1 "$payload_file" | grep -Eq '^#!.*bash' || fail "服务器返回的安装脚本格式无效"
chmod 700 "$payload_file"
exec bash "$payload_file" "${args[@]}"
