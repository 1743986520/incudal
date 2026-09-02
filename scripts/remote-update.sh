#!/usr/bin/env bash
# ============================================================================
# Incudal 远程更新入口
#
# 用法：
#   curl -fsSL https://raw.githubusercontent.com/1743986520/incudal/deeb7d65b1d2a1df461373d48090d77b2b2e4741/scripts/remote-update.sh \
#     | sudo bash
#   curl -fsSL https://raw.githubusercontent.com/1743986520/incudal/deeb7d65b1d2a1df461373d48090d77b2b2e4741/scripts/remote-update.sh \
#     | sudo bash -s -- --source https://github.com/owner/repo
#
# --source 接受 GitHub 仓库地址或 owner/repo。未指定时使用默认仓库。
# 脚本会自动识别 Docker Compose 或 systemd 产物包部署。
# ============================================================================
set -euo pipefail

readonly DEFAULT_GITHUB_REPO="1743986520/incudal"
readonly DEFAULT_SOURCE_URL="https://github.com/${DEFAULT_GITHUB_REPO}"
readonly DEFAULT_UPDATE_REF="deeb7d65b1d2a1df461373d48090d77b2b2e4741"
INSTALL_DIR="${INCUDAL_INSTALL_DIR:-/opt/incudal}"

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
BOLD='\033[1m'
NC='\033[0m'

log()   { echo -e "${GREEN}[✓]${NC} $1" >&2; }
info()  { echo -e "${CYAN}[i]${NC} $1" >&2; }
warn()  { echo -e "${YELLOW}[!]${NC} $1" >&2; }
error() { echo -e "${RED}[✗]${NC} $1" >&2; }

normalize_github_repository() {
    local input="${1:-}"
    input="${input%/}"
    input="${input%.git}"

    if [[ "$input" =~ ^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)$ ]]; then
        printf '%s/%s' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
        return 0
    fi

    if [[ "$input" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
        printf '%s' "$input"
        return 0
    fi

    return 1
}

usage() {
    cat >&2 <<'EOF'
Incudal 远程更新工具

用法:
  remote-update.sh [选项]

选项:
  --source <地址>    GitHub 仓库地址或 owner/repo，默认使用 1743986520/incudal
  --ref <commit>     使用 40 位 immutable Git commit；默认使用内置 commit
  --mode <模式>      auto、docker 或 release，默认 auto
  --install-dir <目录>  安装目录，默认 /opt/incudal
  --help             显示帮助

示例:
  sudo bash remote-update.sh
  sudo bash remote-update.sh --source https://github.com/owner/repo
EOF
}

SOURCE_INPUT="${INCUDAL_UPDATE_SOURCE:-${INCUDAL_GITHUB_REPO:-$DEFAULT_SOURCE_URL}}"
MODE="${INCUDAL_UPDATE_MODE:-auto}"
UPDATE_REF="${INCUDAL_UPDATE_REF:-$DEFAULT_UPDATE_REF}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --source|--url|--repo)
            [[ $# -ge 2 ]] || { error "$1 缺少地址参数"; exit 2; }
            SOURCE_INPUT="$2"
            shift 2
            ;;
        --mode)
            [[ $# -ge 2 ]] || { error "--mode 缺少参数"; exit 2; }
            MODE="$2"
            shift 2
            ;;
        --ref)
            [[ $# -ge 2 ]] || { error "--ref 缺少参数"; exit 2; }
            UPDATE_REF="$2"
            shift 2
            ;;
        --install-dir)
            [[ $# -ge 2 ]] || { error "--install-dir 缺少参数"; exit 2; }
            INSTALL_DIR="$2"
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            error "未知参数: $1"
            usage
            exit 2
            ;;
    esac
done

if [[ ! "$MODE" =~ ^(auto|docker|release)$ ]]; then
    error "更新模式必须是 auto、docker 或 release"
    exit 2
fi

if [[ ! "$UPDATE_REF" =~ ^[0-9a-fA-F]{40}$ ]]; then
    error "--ref 必须是 40 位 immutable Git commit"
    exit 2
fi

if ! GITHUB_REPO="$(normalize_github_repository "$SOURCE_INPUT")"; then
    error "仅支持 HTTPS GitHub 仓库地址或 owner/repo: ${SOURCE_INPUT}"
    exit 2
fi

if [[ "$MODE" == "auto" ]]; then
    if [[ -f "${INSTALL_DIR}/docker-compose.yml" || -f "${INSTALL_DIR}/compose.yaml" || -f "${INSTALL_DIR}/compose.yml" ]]; then
        MODE="docker"
    elif [[ -f "/etc/systemd/system/incudal.service" ]]; then
        MODE="release"
    else
        error "无法识别部署类型；请使用 --mode docker 或 --mode release"
        exit 1
    fi
fi

if [[ "$MODE" == "docker" ]]; then
    SCRIPT_PATH="scripts/install-docker.sh"
else
    SCRIPT_PATH="scripts/install-panel.sh"
fi

TMP_SCRIPT="$(mktemp "${TMPDIR:-/tmp}/incudal-update.XXXXXX.sh")"
cleanup() {
    rm -f "$TMP_SCRIPT"
}
trap cleanup EXIT

SCRIPT_URL="https://raw.githubusercontent.com/${GITHUB_REPO}/${UPDATE_REF}/${SCRIPT_PATH}"
info "更新来源: https://github.com/${GITHUB_REPO}"
info "部署模式: ${MODE}"
info "下载更新脚本: ${SCRIPT_URL}"

if ! curl --fail --silent --show-error --location --connect-timeout 15 --max-time 120 \
    "$SCRIPT_URL" -o "$TMP_SCRIPT"; then
    error "无法下载远程更新脚本"
    exit 1
fi

chmod 700 "$TMP_SCRIPT"
log "开始执行远程升级"
INCUDAL_GITHUB_REPO="$GITHUB_REPO" INCUDAL_INSTALL_DIR="$INSTALL_DIR" INCUDAL_UPDATE_REF="$UPDATE_REF" \
    bash "$TMP_SCRIPT" --upgrade
log "远程升级完成"
