#!/usr/bin/env bash
# ============================================================================
# Incudal 面板一键部署脚本（产物包模式）
#
# 功能：
#   - 安装 Node.js 22、PostgreSQL 16、Redis 7
#   - 从 GitHub Releases 下载预构建产物包
#   - 自动配置数据库、环境变量、systemd 服务
#   - 支持 Nginx+Certbot / Cloudflare Tunnel / 纯端口 三种外部访问方案
#   - 支持升级已有安装
#
# 用法：
#   安装：  sudo bash install-panel.sh
#   升级：  sudo bash install-panel.sh --upgrade
#   卸载：  sudo bash install-panel.sh --uninstall
#
# 项目地址: https://github.com/1743986520/incudal
# ============================================================================
set -euo pipefail

# ========================== 全局常量 ==========================
readonly SCRIPT_VERSION="3.0.0"
readonly DEFAULT_GITHUB_REPO="1743986520/incudal"
readonly DEFAULT_UPDATE_REF="deeb7d65b1d2a1df461373d48090d77b2b2e4741"
readonly GITHUB_REPO="${INCUDAL_GITHUB_REPO:-${INCUDAL_UPDATE_SOURCE:-$DEFAULT_GITHUB_REPO}}"
readonly INSTALL_DIR="${INCUDAL_INSTALL_DIR:-/opt/incudal}"
readonly SERVICE_NAME="incudal"
readonly SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
readonly ENV_FILE="${INSTALL_DIR}/.env"
readonly RUN_USER="incudal"
readonly DEFAULT_PORT=3000
readonly NODE_MAJOR=22
readonly PG_VERSION=16
UPGRADE_BACKUP_DIR=""

# ========================== 颜色定义 ==========================
readonly RED='\033[1;31m'
readonly GREEN='\033[1;32m'
readonly YELLOW='\033[1;33m'
readonly CYAN='\033[1;36m'
readonly BOLD='\033[1m'
readonly DIM='\033[2m'
readonly NC='\033[0m'

# ========================== 工具函数 ==========================
# 所有日志输出到 stderr，避免在 $() 子 shell 中被捕获
log()   { echo -e "${GREEN}[✓]${NC} $1" >&2; }
info()  { echo -e "${CYAN}[i]${NC} $1" >&2; }
warn()  { echo -e "${YELLOW}[!]${NC} $1" >&2; }
error() { echo -e "${RED}[✗]${NC} $1" >&2; }
step()  { echo -e "\n${CYAN}[▶]${NC} ${BOLD}$1${NC}" >&2; }

divider() {
    echo -e "${DIM}────────────────────────────────────────────────────${NC}" >&2
}

# 生成随机密码
gen_password() {
    openssl rand -hex 64 | cut -c "1-${1:-24}"
}

gen_secret() {
    printf 'A1!%s' "$(openssl rand -hex 64)" | cut -c "1-${1:-48}"
}

resolve_admin_password() {
    local password="${1:-}"
    local confirmation=""

    if [[ -z "$password" && -t 0 ]]; then
        printf '请输入管理员初始密码（至少 12 位）: ' >&2
        IFS= read -r -s password || return 1
        printf '\n请再次输入管理员初始密码: ' >&2
        IFS= read -r -s confirmation || return 1
        printf '\n' >&2
        if [[ "$password" != "$confirmation" ]]; then
            error "两次输入的管理员密码不一致"
            return 1
        fi
    fi

    if [[ -z "$password" ]]; then
        password=$(gen_password 24)
        warn "未提供 ADMIN_PASSWORD，已生成随机管理员初始密码；安装完成时会显示一次"
    fi

    if [[ ${#password} -lt 12 ]]; then
        error "管理员密码至少需要 12 位"
        return 1
    fi

    # .env 使用未加引号的 KEY=VALUE 格式，拒绝会改变配置语义的字符。
    if [[ ! "$password" =~ ^[A-Za-z0-9._~!@%+,-]+$ ]]; then
        error "管理员密码只能包含字母、数字及 . _ ~ ! @ % + , -"
        return 1
    fi

    printf '%s' "$password"
}

get_env_value() {
    local key="$1"
    if [[ ! -f "$ENV_FILE" ]]; then
        return 0
    fi
    grep -E "^${key}=" "$ENV_FILE" 2>/dev/null | tail -n 1 | cut -d'=' -f2- || true
}

set_env_if_missing() {
    local key="$1"
    local value="$2"
    local label="$3"
    local current
    current="$(get_env_value "$key")"

    if [[ -n "$current" ]]; then
        return 0
    fi

    if grep -qE "^${key}=" "$ENV_FILE" 2>/dev/null; then
        local tmp_file
        tmp_file="$(mktemp)"
        awk -v key="$key" -v value="$value" '
            BEGIN { replaced = 0 }
            $0 ~ "^" key "=" && replaced == 0 {
                print key "=" value
                replaced = 1
                next
            }
            { print }
        ' "$ENV_FILE" > "$tmp_file"
        cat "$tmp_file" > "$ENV_FILE"
        rm -f "$tmp_file"
    else
        printf '\n%s=%s\n' "$key" "$value" >> "$ENV_FILE"
    fi

    log "已自动补充 ${label}: ${key}"
}

ensure_env_keys() {
    if [[ ! -f "$ENV_FILE" ]]; then
        return 0
    fi

    set_env_if_missing "JWT_SECRET" "$(gen_secret 48)" "JWT 密钥"
    set_env_if_missing "COOKIE_SECRET" "$(gen_secret 48)" "Cookie 密钥"
    set_env_if_missing "ENCRYPTION_KEY" "$(openssl rand -base64 32)" "敏感数据加密密钥"
    local current_admin_password
    current_admin_password="$(get_env_value ADMIN_PASSWORD)"
    if [[ "$current_admin_password" == "admin123" ]]; then
        warn "检测到不安全的默认管理员密码，正在替换为随机密码"
        current_admin_password=""
    fi
    if [[ -z "$current_admin_password" ]]; then
        local provided_admin_password="${ADMIN_PASSWORD:-}"
        [[ "$provided_admin_password" == "admin123" ]] && provided_admin_password=""
        current_admin_password=$(resolve_admin_password "$provided_admin_password") || return 1
        if grep -qE '^ADMIN_PASSWORD=' "$ENV_FILE" 2>/dev/null; then
            local tmp_env
            tmp_env="$(mktemp)"
            awk -v password="$current_admin_password" '
                BEGIN { replaced = 0 }
                /^ADMIN_PASSWORD=/ && replaced == 0 {
                    print "ADMIN_PASSWORD=" password
                    replaced = 1
                    next
                }
                { print }
            ' "$ENV_FILE" > "$tmp_env"
            cat "$tmp_env" > "$ENV_FILE"
            rm -f "$tmp_env"
        else
            printf '\nADMIN_PASSWORD=%s\n' "$current_admin_password" >> "$ENV_FILE"
        fi
    fi

    chmod 600 "$ENV_FILE"
    chown "${RUN_USER}:${RUN_USER}" "$ENV_FILE" 2>/dev/null || true
}

install_web_update_helper() {
    local helper_path="/usr/local/sbin/incudal-web-update"
    local sudoers_path="/etc/sudoers.d/incudal-web-update"
    local bundled_script="${INSTALL_DIR}/scripts/remote-update.sh"
    local trusted_script="/usr/local/libexec/incudal-remote-update.sh"

    # 更新器必须来自当前发行包，而不是由面板服务账号以 root 下载可变的 main 分支。
    # 旧安装若尚未包含发行包内脚本，保留一个安全的失败闭包，避免回退到任意远程脚本。
    if [[ ! -f "$bundled_script" ]]; then
        cat > "$helper_path" << 'EOF'
#!/usr/bin/env bash
set -euo pipefail
echo "发行包缺少固定版本更新器，请先执行一次受校验的手动升级" >&2
exit 1
EOF
        chmod 0755 "$helper_path"
        chown root:root "$helper_path"
        rm -f "$sudoers_path"
        rm -f "$trusted_script"
        warn "当前发行包没有内置更新器，站点更新暂不可用"
        return 0
    fi

    # 安装目录会归 incudal 用户用于读取运行时文件；root helper 不能直接执行其中的脚本。
    install -d -o root -g root -m 0755 "$(dirname "$trusted_script")"
    install -o root -g root -m 0755 "$bundled_script" "$trusted_script"

    cat > "$helper_path" << EOF
#!/usr/bin/env bash
set -euo pipefail

readonly BUNDLED_SCRIPT="${trusted_script}"
readonly INSTALL_DIR="${INSTALL_DIR}"
readonly ALLOWED_SOURCE="https://github.com/${DEFAULT_GITHUB_REPO}"

args=("\$@")
for ((index = 0; index < \${#args[@]}; index += 1)); do
    case "\${args[index]}" in
        --install-dir|--install-dir=*)
            echo "--install-dir 由系统安装目录固定，不允许从站点覆盖" >&2
            exit 2
            ;;
        --source|--url|--repo)
            ((index + 1 < \${#args[@]})) || { echo "--source 缺少参数" >&2; exit 2; }
            source="\${args[index + 1]}"
            if [[ "\$source" != "\$ALLOWED_SOURCE" && "\$source" != "${DEFAULT_GITHUB_REPO}" ]]; then
                echo "站点更新只允许使用内置官方仓库: \$ALLOWED_SOURCE" >&2
                exit 2
            fi
            ((index += 1))
            ;;
        --mode)
            ((index + 1 < \${#args[@]})) || { echo "--mode 缺少参数" >&2; exit 2; }
            case "\${args[index + 1]}" in
                auto|docker|release) ;;
                *) echo "更新模式无效" >&2; exit 2 ;;
            esac
            ((index += 1))
            ;;
        *)
            echo "不支持的更新参数: \${args[index]}" >&2
            exit 2
            ;;
    esac
done

exec /usr/bin/bash "\$BUNDLED_SCRIPT" "\${args[@]}" --install-dir "\$INSTALL_DIR"
EOF
    chmod 0755 "$helper_path"
    chown root:root "$helper_path"

    if command -v visudo >/dev/null 2>&1; then
        cat > "$sudoers_path" << EOF
${RUN_USER} ALL=(root) NOPASSWD: ${helper_path}
EOF
        chmod 0440 "$sudoers_path"
        if ! visudo -cf "$sudoers_path" >/dev/null 2>&1; then
            rm -f "$sudoers_path"
            warn "站点更新 sudo 权限配置校验失败，页面将显示手动更新命令"
        fi
    fi

    log "站点更新执行器已配置: ${helper_path}"
}

configure_web_update_service() {
    local dropin_dir="/etc/systemd/system/${SERVICE_NAME}.service.d"
    local dropin_path="${dropin_dir}/web-update.conf"

    mkdir -p "$dropin_dir"
    cat > "$dropin_path" << EOF
[Service]
# 允许 incudal 通过固定、受 sudoers 限制的更新执行器触发 root 更新。
NoNewPrivileges=false
ReadWritePaths=${INSTALL_DIR}/server/certs /var/lib/incudal/web-updates
EOF
    systemctl daemon-reload
}

# ========================== 系统检查 ==========================
check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        error "请以 root 权限运行此部署脚本！"
        error "用法: sudo bash $0"
        exit 1
    fi
}

check_os() {
    if [[ ! -f /etc/os-release ]]; then
        error "无法检测操作系统（/etc/os-release 不存在）"
        exit 1
    fi

    source /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_VERSION="${VERSION_ID:-unknown}"
    OS_CODENAME="${VERSION_CODENAME:-unknown}"
    ARCH=$(dpkg --print-architecture 2>/dev/null || uname -m)

    # 仅支持 Ubuntu 和 Debian
    if [[ "$OS_ID" != "ubuntu" && "$OS_ID" != "debian" ]]; then
        error "不支持的操作系统: ${OS_ID}"
        error "本脚本仅支持 Ubuntu 和 Debian 系统"
        exit 1
    fi

    # 版本检查
    case "$OS_ID" in
        ubuntu)
            local major="${OS_VERSION%%.*}"
            if [[ "$major" -lt 22 ]] 2>/dev/null; then
                error "Ubuntu 版本过低 (${OS_VERSION})，最低要求 Ubuntu 22.04"
                exit 1
            fi
            ;;
        debian)
            local major="${OS_VERSION%%.*}"
            if [[ "$major" -lt 12 ]] 2>/dev/null; then
                error "Debian 版本过低 (${OS_VERSION})，最低要求 Debian 12 (Bookworm)"
                exit 1
            fi
            ;;
    esac

    # 架构检查
    case "$ARCH" in
        amd64|x86_64) ARCH="amd64" ;;
        arm64|aarch64) ARCH="arm64" ;;
        *)
            error "不支持的系统架构: ${ARCH}"
            error "仅支持 amd64 (x86_64) 和 arm64 (aarch64)"
            exit 1
            ;;
    esac

    log "系统检测通过: ${OS_ID} ${OS_VERSION} (${ARCH})"
}

# ========================== 显示横幅 ==========================
show_banner() {
    clear 2>/dev/null || true
    echo ""
    echo -e "${CYAN}  ╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}  ║                                                  ║${NC}"
    echo -e "${CYAN}  ║          ${BOLD}Incudal 面板一键部署脚本${NC}${CYAN}                ║${NC}"
    echo -e "${CYAN}  ║          ${DIM}Pre-built Package Deploy${NC}${CYAN}                ║${NC}"
    echo -e "${CYAN}  ║                                                  ║${NC}"
    echo -e "${CYAN}  ╚══════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${DIM}版本: ${SCRIPT_VERSION}  |  仓库: ${GITHUB_REPO}${NC}"
    echo ""
}

# ========================== 检查已有安装 ==========================
check_existing() {
    if [[ -d "$INSTALL_DIR" && -f "${INSTALL_DIR}/server/dist/app.js" ]]; then
        return 0  # 已安装
    fi
    return 1  # 未安装
}

# ========================== 安装 Node.js ==========================
install_nodejs() {
    step "安装 Node.js ${NODE_MAJOR}..."

    if command -v node &>/dev/null; then
        local current_ver
        current_ver=$(node -v 2>/dev/null | sed 's/v//' | cut -d. -f1)
        if [[ "$current_ver" -ge "$NODE_MAJOR" ]] 2>/dev/null; then
            log "Node.js $(node -v) 已安装，跳过"
            return 0
        fi
        warn "当前 Node.js 版本较低 ($(node -v))，将升级到 v${NODE_MAJOR}"
    fi

    # 通过 NodeSource 安装
    info "添加 NodeSource APT 源..."
    curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | bash - >/dev/null 2>&1
    apt-get install -y -qq nodejs >/dev/null 2>&1

    log "Node.js $(node -v) 安装完成"
}

# ========================== 安装 PostgreSQL ==========================
install_postgresql() {
    step "安装 PostgreSQL ${PG_VERSION}..."

    if command -v psql &>/dev/null; then
        local pg_ver
        pg_ver=$(psql --version 2>/dev/null | awk '{print $3}' | cut -d. -f1)
        if [[ "$pg_ver" -ge "$PG_VERSION" ]] 2>/dev/null; then
            log "PostgreSQL ${pg_ver} 已安装，跳过"
            return 0
        fi
    fi

    # 添加 PostgreSQL 官方 APT 源
    info "添加 PostgreSQL 官方 APT 源..."
    apt-get install -y -qq gnupg lsb-release >/dev/null 2>&1

    curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
        | gpg --yes --dearmor -o /etc/apt/keyrings/postgresql.gpg

    echo "deb [signed-by=/etc/apt/keyrings/postgresql.gpg] https://apt.postgresql.org/pub/repos/apt ${OS_CODENAME}-pgdg main" \
        > /etc/apt/sources.list.d/pgdg.list

    apt-get update -qq >/dev/null 2>&1
    apt-get install -y -qq "postgresql-${PG_VERSION}" >/dev/null 2>&1

    # 确保服务启动
    systemctl enable postgresql >/dev/null 2>&1
    systemctl start postgresql

    log "PostgreSQL ${PG_VERSION} 安装完成"
}

# ========================== 安装 Redis ==========================
install_redis() {
    step "安装 Redis..."

    if command -v redis-server &>/dev/null; then
        log "Redis $(redis-server --version | awk '{print $3}' | sed 's/v=//') 已安装，跳过"
        return 0
    fi

    apt-get install -y -qq redis-server >/dev/null 2>&1

    # 确保服务启动
    systemctl enable redis-server >/dev/null 2>&1
    systemctl start redis-server

    log "Redis 安装完成"
}

# ========================== 手动包目录 ==========================
readonly MANUAL_PKG_DIR="/tmp/incudal"

# ========================== 获取最新版本号（快速尝试） ==========================
get_latest_version() {
    local api_url="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"
    local response=""
    local version=""

    # 5 秒超时速查，不阻塞
    response=$(curl -sL --connect-timeout 5 --max-time 8 "$api_url" 2>/dev/null) || true

    if [[ -n "$response" ]]; then
        version=$(echo "$response" | grep '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/' || true)
    fi

    if [[ ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
        version=""
    fi
    echo "$version"
}

sha256_file() {
    local path="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$path" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$path" | awk '{print $1}'
    else
        error "系统缺少 sha256sum 或 shasum，无法校验发行包"
        return 1
    fi
}

verify_release_package() {
    local tar_file="$1"
    local checksum_file="${2:-${tar_file}.sha256}"
    local expected actual

    if [[ ! -f "$tar_file" || ! -f "$checksum_file" ]]; then
        error "发行包或 SHA256 校验文件缺失: ${tar_file}"
        return 1
    fi

    expected="$(awk 'NF { print $1; exit }' "$checksum_file")"
    if [[ ! "$expected" =~ ^[0-9a-fA-F]{64}$ ]]; then
        error "SHA256 校验文件格式无效: ${checksum_file}"
        return 1
    fi

    actual="$(sha256_file "$tar_file")"
    if [[ "${actual,,}" != "${expected,,}" ]]; then
        error "发行包 SHA256 校验失败: expected=${expected} actual=${actual}"
        return 1
    fi
}

# ========================== 自动下载产物包 ==========================
download_release() {
    local version="$1"
    local filename="incudal-${version}-linux-${ARCH}.tar.gz"
    local download_url="https://github.com/${GITHUB_REPO}/releases/download/${version}/${filename}"
    local tmp_file
    local checksum_file
    tmp_file="$(mktemp "/tmp/incudal-${version}-${ARCH}.XXXXXX.tar.gz")"
    checksum_file="${tmp_file}.sha256"

    info "下载地址: ${download_url}"

    if curl -fSL --progress-bar --connect-timeout 15 --max-time 600 \
        "$download_url" -o "$tmp_file" 2>/dev/null \
        && curl -fSL --silent --show-error --connect-timeout 15 --max-time 60 \
        "${download_url}.sha256" -o "$checksum_file" 2>/dev/null \
        && verify_release_package "$tmp_file" "$checksum_file"; then
        local file_size
        file_size=$(du -h "$tmp_file" | cut -f1 || true)
        log "下载完成 (${file_size})"
        echo "$tmp_file"
        return 0
    fi

    rm -f "$tmp_file" "$checksum_file" 2>/dev/null || true
    return 1
}

# ========================== 扫描手动放置的产物包 ==========================
scan_manual_package() {
    local found=""

    if [[ ! -d "$MANUAL_PKG_DIR" ]]; then
        return 1
    fi

    # 优先匹配当前架构的包
    found=$(find "$MANUAL_PKG_DIR" -maxdepth 1 -name "incudal-*-linux-${ARCH}.tar.gz" -type f 2>/dev/null | head -n1 || true)

    # 退而匹配任意 incudal tar.gz
    if [[ -z "$found" ]]; then
        found=$(find "$MANUAL_PKG_DIR" -maxdepth 1 -name "incudal-*.tar.gz" -type f 2>/dev/null | head -n1 || true)
    fi

    if [[ -n "$found" ]]; then
        echo "$found"
        return 0
    fi

    return 1
}

# ========================== 等待用户放置产物包 ==========================
wait_for_manual_package() {
    echo "" >&2
    divider
    echo -e "  ${YELLOW}${BOLD}⚠ 自动获取产物包失败${NC}" >&2
    echo -e "  ${DIM}（仓库可能是私有的，或网络无法连接 GitHub）${NC}" >&2
    divider
    echo "" >&2
    echo -e "  ${BOLD}请手动下载产物包并放到以下目录：${NC}" >&2
    echo "" >&2
    echo -e "  ${CYAN}${BOLD}${MANUAL_PKG_DIR}/${NC}" >&2
    echo "" >&2
    echo -e "  ${BOLD}下载地址：${NC}" >&2
    echo -e "  ${CYAN}https://github.com/${GITHUB_REPO}/releases${NC}" >&2
    echo "" >&2
    echo -e "  ${BOLD}所需文件名格式：${NC}" >&2
    echo -e "  ${GREEN}incudal-vX.Y.Z-linux-${ARCH}.tar.gz${NC}" >&2
    echo -e "  ${GREEN}并提供同名 .sha256 校验文件${NC}" >&2
    echo "" >&2
    echo -e "  ${DIM}提示: 可使用 scp、wget、rz 等方式将文件传到服务器${NC}" >&2
    echo -e "  ${DIM}例如: scp incudal-v1.0.0-linux-${ARCH}.tar.gz root@服务器IP:${MANUAL_PKG_DIR}/${NC}" >&2
    divider
    echo "" >&2

    # 创建目录
    mkdir -p "$MANUAL_PKG_DIR"

    # 轮询等待文件出现
    local wait_count=0
    local max_wait=600  # 最多等 10 分钟（含上传时间）
    local spin_chars='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local MIN_SIZE_KB=10240  # 产物包至少 10MB

    while true; do
        # 尝试扫描
        local pkg_file=""
        pkg_file=$(scan_manual_package) || true

        if [[ -n "$pkg_file" ]]; then
            # 检测到文件，等待上传完成（文件大小稳定）
            echo "" >&2
            info "检测到文件: $(basename "$pkg_file")"
            info "等待上传完成..."

            local stable_count=0
            local last_size=0

            while true; do
                local current_size
                current_size=$(stat -c%s "$pkg_file" 2>/dev/null || echo "0")
                local current_size_human
                current_size_human=$(du -h "$pkg_file" 2>/dev/null | cut -f1 || echo "?")

                if [[ "$current_size" -eq "$last_size" && "$current_size" -gt 0 ]]; then
                    stable_count=$((stable_count + 1))
                else
                    stable_count=0
                    last_size="$current_size"
                fi

                # 连续 3 次（9 秒）大小不变，认为上传完成
                if [[ $stable_count -ge 3 ]]; then
                    # 检查最小文件大小
                    local size_kb=$((current_size / 1024))
                    if [[ $size_kb -lt $MIN_SIZE_KB ]]; then
                        warn "文件过小 (${current_size_human})，产物包通常 >100MB，可能不完整"
                        warn "如确认无误，请将文件删除后重新放置"
                        # 继续等待
                        stable_count=0
                        last_size=0
                        sleep 3
                        continue
                    fi

                    if ! verify_release_package "$pkg_file"; then
                        warn "拒绝未通过 SHA256 校验的手动产物包，请检查同名 .sha256 文件"
                        stable_count=0
                        last_size=0
                        sleep 3
                        continue
                    fi

                    log "上传完成！文件大小: ${current_size_human}"
                    echo "$pkg_file"
                    return 0
                fi

                printf "\r  ${CYAN}⏳${NC} 上传中... 当前大小: ${current_size_human}  " >&2
                sleep 3
                wait_count=$((wait_count + 3))

                if [[ $wait_count -ge $max_wait ]]; then
                    echo "" >&2
                    error "等待超时 (${max_wait}s)，请重新运行脚本"
                    return 1
                fi
            done
        fi

        # 显示等待动画（输出到 stderr）
        local spin_idx=$((wait_count % ${#spin_chars}))
        local spin_char="${spin_chars:$spin_idx:1}"
        printf "\r  ${CYAN}${spin_char}${NC} 等待产物包... (已等待 %ds，输入 Ctrl+C 取消)  " "$wait_count" >&2

        sleep 2
        wait_count=$((wait_count + 2))

        if [[ $wait_count -ge $max_wait ]]; then
            echo "" >&2
            error "等待超时 (${max_wait}s)，请重新运行脚本"
            return 1
        fi
    done
}

# ========================== 统一入口：获取产物包 ==========================
obtain_release() {
    step "获取 Incudal 产物包..."

    # ---- 阶段 0：检查是否已有手动放置的包 ----
    local existing_pkg=""
    existing_pkg=$(scan_manual_package) || true
    if [[ -n "$existing_pkg" ]]; then
        log "检测到手动放置的产物包: $(basename "$existing_pkg")"
        verify_release_package "$existing_pkg" || return 1
        echo "$existing_pkg"
        return 0
    fi

    # ---- 阶段 1：尝试 API 自动获取版本号 ----
    info "正在查询最新版本（5 秒超时）..."
    local version=""
    version=$(get_latest_version)

    if [[ -n "$version" ]]; then
        info "最新版本: ${version}"

        # ---- 阶段 2：尝试自动下载 ----
        local tar_file=""
        tar_file=$(download_release "$version") || true

        if [[ -n "$tar_file" && -f "$tar_file" ]]; then
            echo "$tar_file"
            return 0
        fi

        warn "自动下载失败（文件可能不存在或网络受限）"
    else
        warn "自动获取版本号失败（仓库可能是私有的）"
    fi

    # ---- 阶段 3：引导用户手动放置包 ----
    local manual_file=""
    manual_file=$(wait_for_manual_package) || return 1
    echo "$manual_file"
    return 0
}

# ========================== 解压安装 ==========================
install_release() {
    local tar_file="$1"
    local is_upgrade="${2:-false}"

    step "安装产物包..."

    if ! verify_release_package "$tar_file"; then
        error "拒绝安装未通过 SHA256 校验的发行包"
        return 1
    fi

    # 创建安装目录
    mkdir -p "$INSTALL_DIR"

    if [[ "$is_upgrade" == "true" ]]; then
        # 升级模式：先在旁路目录完整解压，成功后再切换目录。
        # 这样解压失败不会破坏当前版本，迁移/启动失败时还可以恢复旧版本。
        local stamp="$(date +%Y%m%d%H%M%S)-$$"
        local new_dir="${INSTALL_DIR}.new.${stamp}"
        UPGRADE_BACKUP_DIR="${INSTALL_DIR}.bak.${stamp}"

        if [[ -e "$new_dir" || -e "$UPGRADE_BACKUP_DIR" ]]; then
            error "升级临时目录已存在，请清理后重试"
            return 1
        fi

        mkdir -p "$new_dir"
        if ! tar -xzf "$tar_file" -C "$new_dir" --strip-components=0; then
            rm -rf "$new_dir"
            UPGRADE_BACKUP_DIR=""
            error "产物包解压失败，当前版本未改变"
            return 1
        fi

        # 仅迁移运行时配置和客户端证书，避免新包被旧代码覆盖。
        if [[ -f "${INSTALL_DIR}/.env" ]]; then
            cp "${INSTALL_DIR}/.env" "${new_dir}/.env"
        fi
        if [[ -d "${INSTALL_DIR}/server/certs" ]]; then
            mkdir -p "${new_dir}/server/certs"
            cp -a "${INSTALL_DIR}/server/certs/." "${new_dir}/server/certs/"
        fi

        mv "$INSTALL_DIR" "$UPGRADE_BACKUP_DIR"
        if ! mv "$new_dir" "$INSTALL_DIR"; then
            mv "$UPGRADE_BACKUP_DIR" "$INSTALL_DIR"
            UPGRADE_BACKUP_DIR=""
            error "切换新版本失败，当前版本已恢复"
            return 1
        fi
        info "旧版本已备份到: ${UPGRADE_BACKUP_DIR}"
    else
        # 全新安装
        tar -xzf "$tar_file" -C "$INSTALL_DIR" --strip-components=0
    fi

    # 清理下载的临时文件
    rm -f "$tar_file" "${tar_file}.sha256"

    # 创建证书目录
    mkdir -p "${INSTALL_DIR}/server/certs"

    log "产物包安装完成"
}

# ========================== 创建系统用户 ==========================
create_user() {
    step "配置系统用户..."

    if id "$RUN_USER" &>/dev/null; then
        log "用户 ${RUN_USER} 已存在，跳过"
    else
        useradd --system --home-dir "${INSTALL_DIR}" --shell /usr/sbin/nologin "$RUN_USER"
        log "系统用户 ${RUN_USER} 创建完成"
    fi

    # 创建 npm 缓存目录（运行时依赖需要可写的 home 目录）
    mkdir -p "${INSTALL_DIR}/.npm"
    mkdir -p "${INSTALL_DIR}/.cache"

    # 设置目录权限
    chown -R "${RUN_USER}:${RUN_USER}" "$INSTALL_DIR"
    chmod 750 "$INSTALL_DIR"
    chmod 600 "${ENV_FILE}" 2>/dev/null || true
}

# ========================== 生成面板客户端证书 ==========================
generate_panel_cert() {
    local cert_dir="${INSTALL_DIR}/server/certs"
    local cert_file="${cert_dir}/client.crt"
    local key_file="${cert_dir}/client.key"

    step "配置面板客户端证书..."

    # 幂等性：证书已存在则跳过
    if [[ -f "$cert_file" && -f "$key_file" ]]; then
        chmod 644 "$cert_file"
        chmod 600 "$key_file"
        chown "${RUN_USER}:${RUN_USER}" "$cert_file" "$key_file"
        log "面板客户端证书已存在，跳过生成"
        return 0
    fi

    mkdir -p "$cert_dir"

    # 生成自签名客户端证书（用于面板与 Incus API 的 mTLS 通信）
    info "生成面板客户端证书（RSA 4096 位，有效期 10 年）..."
    openssl req -x509 -newkey rsa:4096 \
        -keyout "$key_file" \
        -out "$cert_file" \
        -days 3650 -nodes \
        -subj "/CN=incudal-panel/O=Incudal" \
        2>/dev/null

    # 设置权限：只有 incudal 用户可读
    chmod 600 "$cert_file" "$key_file"
    chown "${RUN_USER}:${RUN_USER}" "$cert_file" "$key_file"

    log "面板客户端证书生成完成"
    info "证书路径: ${cert_file}"
    info "密钥路径: ${key_file}"
}

# ========================== 配置数据库 ==========================
setup_database() {
    local db_password="$1"

    step "配置 PostgreSQL 数据库..."

    # 检查数据库和用户是否已存在
    local db_exists
    db_exists=$(sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='incudal'" 2>/dev/null || echo "")

    if [[ "$db_exists" == "1" ]]; then
        info "数据库 'incudal' 已存在，跳过创建"
        # 更新密码
        sudo -u postgres psql -c "ALTER USER incudal WITH PASSWORD '${db_password}';" >/dev/null 2>&1 || true
    else
        # 创建用户和数据库
        sudo -u postgres psql -c "CREATE USER incudal WITH PASSWORD '${db_password}';" >/dev/null 2>&1 || true
        sudo -u postgres psql -c "CREATE DATABASE incudal OWNER incudal;" >/dev/null 2>&1
        sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE incudal TO incudal;" >/dev/null 2>&1
        log "数据库 'incudal' 创建完成"
    fi
}

# ========================== 生成环境变量 ==========================
generate_env() {
    local db_password="$1"
    local redis_password="$2"
    local admin_password="${3:-${ADMIN_PASSWORD:-}}"

    step "生成环境配置..."

    if [[ -f "$ENV_FILE" ]]; then
        info ".env 文件已存在，检查并补齐缺失的密钥配置"
        ensure_env_keys
        return 0
    fi

    local jwt_secret
    jwt_secret=$(gen_secret 48)
    local cookie_secret
    cookie_secret=$(gen_secret 48)
    local encryption_key
    encryption_key=$(openssl rand -base64 32)
    admin_password=$(resolve_admin_password "$admin_password") || return 1

    cat > "$ENV_FILE" << EOF
# ============================================================================
# Incudal 环境配置
# 由安装脚本自动生成于 $(date '+%Y-%m-%d %H:%M:%S')
# ============================================================================

# ============ 运行环境 ============
NODE_ENV=production
HOST=127.0.0.1
PORT=${DEFAULT_PORT}

# ============ 数据库配置 ============
DATABASE_URL=postgresql://incudal:${db_password}@127.0.0.1:5432/incudal

# ============ Redis 配置 ============
REDIS_URL=redis://:${redis_password}@127.0.0.1:6379

# ============ 安全配置（请勿泄露！）============
JWT_SECRET=${jwt_secret}
COOKIE_SECRET=${cookie_secret}
ENCRYPTION_KEY=${encryption_key}

# ============ 应用配置 ============
APP_PORT=${DEFAULT_PORT}
ADMIN_PASSWORD=${admin_password}
LOG_LEVEL=info
DISABLE_REQUEST_LOG=true

# ============ CORS 配置（必须修改为实际域名！）============
# 支付回调地址也会使用这个域名，必须是公网可访问的地址
FRONTEND_URL=

# ============ 监控告警（可选）============
# ALERT_WEBHOOK_URL=https://your-webhook-url
EOF

    chmod 600 "$ENV_FILE"
    chown "${RUN_USER}:${RUN_USER}" "$ENV_FILE"

    log "环境配置文件生成完成: ${ENV_FILE}"
}

# ========================== 配置 Redis 密码 ==========================
setup_redis() {
    local redis_password="$1"

    step "配置 Redis..."

    local redis_conf="/etc/redis/redis.conf"
    if [[ -f "$redis_conf" ]]; then
        # 设置密码
        if grep -q "^requirepass" "$redis_conf" 2>/dev/null; then
            sed -i "s/^requirepass.*/requirepass ${redis_password}/" "$redis_conf"
        elif grep -q "^# requirepass" "$redis_conf" 2>/dev/null; then
            sed -i "s/^# requirepass.*/requirepass ${redis_password}/" "$redis_conf"
        else
            echo "requirepass ${redis_password}" >> "$redis_conf"
        fi

        systemctl restart redis-server
        log "Redis 密码配置完成"
    else
        warn "Redis 配置文件不存在，跳过密码配置"
    fi
}

# ========================== 运行数据库迁移 ==========================
run_migrations() {
    step "执行数据库迁移..."

    cd "${INSTALL_DIR}/server"
    local prisma_cli="${INSTALL_DIR}/server/node_modules/.bin/prisma"
    local database_url

    if [[ ! -x "$prisma_cli" ]]; then
        error "发行包缺少固定版本 Prisma CLI: ${prisma_cli}"
        return 1
    fi
    database_url="$(get_env_value DATABASE_URL)"
    if [[ -z "$database_url" ]]; then
        error "环境配置缺少 DATABASE_URL"
        return 1
    fi

    # 以 incudal 用户身份调用发行包内固定版本 CLI，禁止运行时联网安装。
    if ! sudo -u "$RUN_USER" env \
        HOME="${INSTALL_DIR}" \
        NPM_CONFIG_CACHE="${INSTALL_DIR}/.npm" \
        DATABASE_URL="$database_url" \
        "$prisma_cli" migrate deploy; then
        error "数据库迁移失败"
        return 1
    fi

    log "数据库迁移完成"
}

# ========================== 创建 systemd 服务 ==========================
create_service() {
    step "创建 systemd 服务..."

    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Incudal 容器虚拟化管理平台
Documentation=https://github.com/${GITHUB_REPO}
After=network.target postgresql.service redis-server.service
Requires=postgresql.service redis-server.service

[Service]
Type=simple
User=${RUN_USER}
Group=${RUN_USER}
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${ENV_FILE}

# 确保 npm 缓存目录可写
Environment=HOME=${INSTALL_DIR}
Environment=NPM_CONFIG_CACHE=${INSTALL_DIR}/.npm

# 启动前自动执行数据库迁移
ExecStartPre=/usr/bin/bash -c 'cd ${INSTALL_DIR}/server && exec ${INSTALL_DIR}/server/node_modules/.bin/prisma migrate deploy'

# 启动主程序
ExecStart=/usr/bin/node ${INSTALL_DIR}/server/dist/app.js

# 优雅关闭
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=30

# 自动重启
Restart=on-failure
RestartSec=10
StartLimitBurst=5
StartLimitIntervalSec=300

# 安全加固；站点更新通过 sudoers 限制的 root 执行器显式触发
NoNewPrivileges=false
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${INSTALL_DIR}/server/certs /var/lib/incudal/web-updates
PrivateTmp=true

# 资源限制
LimitNOFILE=65536

# 日志
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SERVICE_NAME}

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME" >/dev/null 2>&1

    log "systemd 服务创建完成"
}

# ========================== Nginx + Certbot ==========================
setup_nginx_certbot() {
    info "准备配置 Nginx 反代及 Let's Encrypt SSL 自动证书"
    echo -ne "  ${BOLD}请输入你要绑定的域名 (例如 panel.yourdomain.com): ${NC}"
    read -r DOMAIN

    if [[ -z "$DOMAIN" ]]; then
        error "域名不能为空！"
        return 1
    fi

    echo -ne "  ${BOLD}请输入你的邮箱 (用于证书过期通知，可留空): ${NC}"
    read -r EMAIL

    info "安装 Nginx 与 Certbot..."
    apt-get install -y -qq nginx certbot python3-certbot-nginx >/dev/null 2>&1

    # 更新 FRONTEND_URL
    sed -i "s|^FRONTEND_URL=.*|FRONTEND_URL=https://${DOMAIN}|" "$ENV_FILE"

    log "配置 Nginx 站点..."
    cat > /etc/nginx/sites-available/incudal.conf <<NGINX
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};

    # 安全头
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;

    location / {
        proxy_pass http://127.0.0.1:${DEFAULT_PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;

        # WebSocket 超时
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }
}
NGINX

    ln -sf /etc/nginx/sites-available/incudal.conf /etc/nginx/sites-enabled/
    # 移除默认站点（避免冲突）
    rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true
    nginx -t >/dev/null 2>&1
    systemctl reload nginx

    log "申请 Let's Encrypt SSL 证书..."
    if [[ -n "$EMAIL" ]]; then
        certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "$EMAIL" --redirect
    else
        certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email --redirect
    fi

    log "HTTPS 配置完成！访问地址: https://${DOMAIN}"
}

# ========================== Cloudflare Tunnel ==========================
setup_cf_tunnel() {
    info "准备配置 Cloudflare Tunnel 内网穿透"
    echo -e "  ${DIM}请先在 Cloudflare Zero Trust 管理后台创建 Tunnel${NC}"
    echo -e "  ${DIM}并将 Public Hostname 的目标路由设置为 http://localhost:${DEFAULT_PORT}${NC}"
    echo ""
    echo -ne "  ${BOLD}请输入 Cloudflare Tunnel Token: ${NC}"
    read -r CF_TOKEN

    if [[ -z "$CF_TOKEN" ]]; then
        error "Token 不能为空！"
        return 1
    fi

    echo -ne "  ${BOLD}请输入绑定的域名 (例: panel.yourdomain.com): ${NC}"
    read -r DOMAIN

    if [[ -n "$DOMAIN" ]]; then
        sed -i "s|^FRONTEND_URL=.*|FRONTEND_URL=https://${DOMAIN}|" "$ENV_FILE"
    fi

    # 安装 cloudflared
    if ! command -v cloudflared &>/dev/null; then
        info "安装 cloudflared..."
        curl -fsSL https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCH} \
            -o /usr/local/bin/cloudflared
        chmod +x /usr/local/bin/cloudflared
    fi

    # 创建 cloudflared systemd 服务
    cloudflared service install "$CF_TOKEN" 2>/dev/null || true

    log "Cloudflare Tunnel 配置完成！"
    if [[ -n "$DOMAIN" ]]; then
        echo -e "  访问地址: ${GREEN}https://${DOMAIN}${NC}"
    fi
}

# ========================== 启动服务 ==========================
start_service() {
    step "启动 Incudal 服务..."

    systemctl start "$SERVICE_NAME"

    # 等待几秒检查状态
    sleep 3

    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log "Incudal 服务启动成功！"
    else
        error "服务启动失败，查看日志："
        journalctl -u "$SERVICE_NAME" --no-pager -n 20
        return 1
    fi
}

rollback_upgrade() {
    if [[ -z "$UPGRADE_BACKUP_DIR" || ! -d "$UPGRADE_BACKUP_DIR" ]]; then
        error "找不到可恢复的旧版本目录: ${UPGRADE_BACKUP_DIR:-<empty>}"
        return 1
    fi

    rm -rf "$INSTALL_DIR"
    mv "$UPGRADE_BACKUP_DIR" "$INSTALL_DIR"
    UPGRADE_BACKUP_DIR=""
    chown -R "${RUN_USER}:${RUN_USER}" "$INSTALL_DIR"
    log "已恢复旧版本文件"
}

# ========================== 显示安装结果 ==========================
show_result() {
    echo ""
    divider
    echo -e "  ${GREEN}${BOLD}✅ Incudal 面板部署成功！${NC}"
    divider
    echo ""
    echo -e "  ${BOLD}面板信息${NC}"
    echo -e "  安装路径  :  ${GREEN}${INSTALL_DIR}${NC}"
    echo -e "  配置文件  :  ${GREEN}${ENV_FILE}${NC}"
    echo -e "  服务名称  :  ${GREEN}${SERVICE_NAME}${NC}"
    echo -e "  监听端口  :  ${GREEN}${DEFAULT_PORT}${NC}"
    echo ""
    local admin_password
    admin_password="$(get_env_value ADMIN_PASSWORD)"
    echo -e "  ${BOLD}管理员账号${NC}"
    echo -e "  用户名    :  ${GREEN}admin${NC}"
    echo -e "  初始密码  :  ${GREEN}${admin_password}${NC}"
    echo ""
    echo -e "  ${BOLD}常用命令${NC}"
    echo -e "  启动服务  :  ${CYAN}systemctl start ${SERVICE_NAME}${NC}"
    echo -e "  停止服务  :  ${CYAN}systemctl stop ${SERVICE_NAME}${NC}"
    echo -e "  重启服务  :  ${CYAN}systemctl restart ${SERVICE_NAME}${NC}"
    echo -e "  查看状态  :  ${CYAN}systemctl status ${SERVICE_NAME}${NC}"
    echo -e "  查看日志  :  ${CYAN}journalctl -u ${SERVICE_NAME} -f${NC}"
    echo -e "  远程更新  :  ${CYAN}curl -fsSL https://raw.githubusercontent.com/${GITHUB_REPO}/${DEFAULT_UPDATE_REF}/scripts/remote-update.sh | sudo bash -s -- --ref ${DEFAULT_UPDATE_REF}${NC}"
    echo ""
    divider
}

# ========================== 升级流程 ==========================
do_upgrade() {
    show_banner
    check_os

    if ! check_existing; then
        error "未检测到已安装的 Incudal，请先执行全新安装"
        exit 1
    fi

    info "检测到已安装的 Incudal，准备升级..."

    # 停止服务
    info "停止当前服务..."
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true

    # 获取产物包（自动下载或手动放置）
    local tar_file
    if ! tar_file=$(obtain_release); then
        start_service || true
        exit 1
    fi
    if [[ -z "$tar_file" ]]; then
        start_service || true
        exit 1
    fi

    if ! install_release "$tar_file" true; then
        rm -f "$tar_file" 2>/dev/null || true
        start_service || true
        exit 1
    fi

    # 解压成功后，迁移和启动任一失败都恢复旧版本。
    if ! chown -R "${RUN_USER}:${RUN_USER}" "$INSTALL_DIR"; then
        error "升级包权限修复失败"
        start_service || true
        exit 1
    fi

    install_web_update_helper
    configure_web_update_service

    if ! run_migrations || ! start_service; then
        error "升级后的版本未通过迁移或启动检查，开始回滚..."
        if rollback_upgrade; then
            install_web_update_helper
            configure_web_update_service
            start_service || error "旧版本恢复后也无法启动，请立即检查 systemd 日志"
        fi
        exit 1
    fi

    rm -rf "$UPGRADE_BACKUP_DIR"
    UPGRADE_BACKUP_DIR=""

    echo ""
    divider
    echo -e "  ${GREEN}${BOLD}✅ Incudal 升级完成！${NC}"
    divider
}

# ========================== 卸载流程 ==========================
do_uninstall() {
    show_banner

    echo -e "  ${RED}${BOLD}⚠️  警告：卸载将执行以下操作：${NC}"
    echo -e "  ${RED}  1. 停止并删除 Incudal systemd 服务${NC}"
    echo -e "  ${RED}  2. 删除安装目录 ${INSTALL_DIR}${NC}"
    echo -e "  ${RED}  3. 删除系统用户 ${RUN_USER}${NC}"
    echo -e "  ${YELLOW}  注意：PostgreSQL/Redis 和数据库数据不会被删除${NC}"
    echo ""
    echo -ne "  ${BOLD}确认卸载？${NC}[y/N]: "
    read -r confirm
    if [[ ! "$confirm" =~ ^[yY]$ ]]; then
        info "已取消卸载"
        exit 0
    fi

    # 停止服务
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    rm -f "$SERVICE_FILE"
    rm -rf "/etc/systemd/system/${SERVICE_NAME}.service.d"
    rm -f /usr/local/sbin/incudal-web-update /usr/local/libexec/incudal-remote-update.sh /etc/sudoers.d/incudal-web-update
    rm -rf /var/lib/incudal/web-updates
    systemctl daemon-reload

    # 删除安装目录
    rm -rf "$INSTALL_DIR"

    # 删除用户
    userdel "$RUN_USER" 2>/dev/null || true

    # 清理 Nginx 配置
    rm -f /etc/nginx/sites-enabled/incudal.conf 2>/dev/null || true
    rm -f /etc/nginx/sites-available/incudal.conf 2>/dev/null || true
    systemctl reload nginx 2>/dev/null || true

    echo ""
    log "Incudal 已完全卸载"
    info "数据库数据保留在 PostgreSQL 中，如需删除请手动执行："
    echo -e "  ${CYAN}sudo -u postgres psql -c \"DROP DATABASE incudal;\"${NC}"
    echo -e "  ${CYAN}sudo -u postgres psql -c \"DROP USER incudal;\"${NC}"
}

# ========================== 全新安装流程 ==========================
do_install() {
    show_banner
    check_os

    if check_existing; then
        warn "检测到已安装的 Incudal (${INSTALL_DIR})"
        info "产物包已解压就绪，将跳过下载步骤，直接从配置阶段继续"
        info "如需全新安装，请先运行: sudo bash $0 --uninstall"
        echo "" >&2
    fi

    # 密码处理：如果 .env 已存在则复用旧密码，避免密码不一致
    local db_password
    local redis_password

    if [[ -f "$ENV_FILE" ]]; then
        info "检测到已有 .env 配置，复用现有密码"
        # 从 DATABASE_URL 提取密码: postgresql://user:PASSWORD@host:port/db
        db_password=$(grep -oP 'DATABASE_URL=postgresql://[^:]+:\K[^@]+' "$ENV_FILE" 2>/dev/null || echo "")
        # 从 REDIS_URL 提取密码: redis://:PASSWORD@host:port
        redis_password=$(grep -oP 'REDIS_URL=redis://:\K[^@]+' "$ENV_FILE" 2>/dev/null || echo "")

        if [[ -z "$db_password" ]]; then
            warn "无法从 .env 提取数据库密码，将生成新密码并重写 .env"
            db_password=$(gen_password 24)
            rm -f "$ENV_FILE"
        fi
        if [[ -z "$redis_password" ]]; then
            redis_password=$(gen_password 24)
        fi
    else
        db_password=$(gen_password 24)
        redis_password=$(gen_password 24)
    fi

    # 安装依赖
    step "更新系统包索引..."
    apt-get update -qq >/dev/null 2>&1

    install_nodejs
    install_postgresql
    install_redis

    # 仅在全新安装时获取和解压产物包（已安装则跳过）
    if ! check_existing; then
        # 获取产物包（自动下载或手动放置）
        local tar_file
        tar_file=$(obtain_release) || exit 1
        if [[ -z "$tar_file" ]]; then
            exit 1
        fi

        # 解压安装
        install_release "$tar_file" false
    else
        log "产物包已就绪，跳过下载和解压"
    fi

    # 创建用户
    create_user

    # 配置站点管理员显式触发更新所需的 root 执行器
    install_web_update_helper
    configure_web_update_service

    # 生成面板客户端证书（与 Incus API mTLS 通信所需）
    generate_panel_cert

    # 配置数据库
    setup_database "$db_password"

    # 配置 Redis
    setup_redis "$redis_password"

    # 生成 .env
    generate_env "$db_password" "$redis_password"

    # 创建 systemd 服务
    create_service

    # 运行数据库迁移
    run_migrations

    # 选择网络方案
    echo ""
    divider
    echo -e "  ${BOLD}请选择外部访问方案：${NC}"
    divider
    echo -e "  ${CYAN}[1]${NC} Nginx + Certbot   ${YELLOW}（推荐：自动 HTTPS，需要公网 IP 和域名）${NC}"
    echo -e "  ${CYAN}[2]${NC} Cloudflare Tunnel  ${YELLOW}（适合无公网 IP 或隐藏源站 IP）${NC}"
    echo -e "  ${CYAN}[3]${NC} 仅启动服务        ${DIM}（手动配置反代）${NC}"
    echo ""
    echo -ne "  ${BOLD}请选择 [1-3]: ${NC}"
    read -r net_opt

    case "${net_opt:-3}" in
        1) setup_nginx_certbot ;;
        2) setup_cf_tunnel ;;
        3) info "跳过网络配置，服务将监听 127.0.0.1:${DEFAULT_PORT}" ;;
        *) info "无效选项，跳过网络配置" ;;
    esac

    # 启动服务
    start_service

    # 显示结果
    show_result
}

# ========================== 主入口 ==========================
main() {
    check_root

    case "${1:-}" in
        --upgrade|-u)
            do_upgrade
            ;;
        --uninstall|--remove)
            do_uninstall
            ;;
        --help|-h)
            echo "Incudal 面板部署脚本 v${SCRIPT_VERSION}"
            echo ""
            echo "用法: sudo bash $0 [选项]"
            echo ""
            echo "选项:"
            echo "  (无参数)      全新安装"
            echo "  --upgrade     升级已有安装"
            echo "  --uninstall   卸载 Incudal"
            echo "  --help        显示帮助"
            ;;
        *)
            do_install
            ;;
    esac
}

main "$@"
