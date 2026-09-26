# Storage selection module, prepended to the common installer by the panel.

storage_is_valid_name() { [[ "${1:-}" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$ ]]; }
storage_is_valid_value() { [[ "${1:-}" =~ ^[A-Za-z0-9_./:+=@%~-]+$ ]]; }

normalize_storage_size() {
    local value="${1:-}"
    if [[ "$value" =~ ^[0-9]+$ ]]; then
        printf '%sGiB\n' "$value"
        return 0
    fi
    [[ "$value" =~ ^[0-9]+([KMGTP]i?B?)$ ]] && printf '%s\n' "$value"
}

storage_set_defaults() {
    STORAGE_DRIVER="${STORAGE_DRIVER:-dir}"
    STORAGE_POOL_NAME="${STORAGE_POOL_NAME:-default}"
    STORAGE_SOURCE="${STORAGE_SOURCE:-}"
    STORAGE_SIZE="${STORAGE_SIZE:-60GiB}"
    if [[ "$STORAGE_DRIVER" == "dir" && -z "$STORAGE_SOURCE" ]]; then
        STORAGE_SOURCE="/var/lib/incus/storage-pools/${STORAGE_POOL_NAME}"
    fi
}

prompt_storage_pool() {
    local specified_source="${STORAGE_SOURCE:-}"
    storage_set_defaults
    [[ -t 0 ]] || return 0

    echo -e "\n${CYAN}==> 存储池配置${NC}"
    echo -e "  ${DIM}不会默认安装 ZFS；请选择要创建的 Incus 存储池，也可以跳过后在面板创建。${NC}"
    echo -e "    ${CYAN}1)${NC} DIR    ${DIM}目录存储，不额外安装文件系统模块${NC}"
    echo -e "    ${CYAN}2)${NC} Btrfs  ${DIM}支持快照/子卷，需要 btrfs-progs${NC}"
    echo -e "    ${CYAN}3)${NC} ZFS    ${DIM}支持快照/克隆/配额，需要 ZFS 内核模块${NC}"
    echo -e "    ${CYAN}4)${NC} LVM    ${DIM}适合已有 VG/物理盘，需要 lvm2${NC}"
    echo -e "    ${CYAN}5)${NC} 跳过   ${DIM}不创建存储池，稍后手动配置${NC}"

    local choice=""
    while true; do
        echo -ne "  ${BOLD}请选择 [1-5，默认 1]: ${NC}"
        read -r choice
        case "${choice:-1}" in
            1) STORAGE_DRIVER=dir; break ;;
            2) STORAGE_DRIVER=btrfs; break ;;
            3) STORAGE_DRIVER=zfs; break ;;
            4) STORAGE_DRIVER=lvm; break ;;
            5) STORAGE_DRIVER=none; STORAGE_SOURCE=""; return 0 ;;
            *) warn "无效选项，请输入 1-5" ;;
        esac
    done

    if [[ "$STORAGE_DRIVER" == zfs && "$OS_ID" == alpine ]]; then
        warn "Alpine 当前安装器不自动部署 ZFS，已切换为 DIR。"
        STORAGE_DRIVER=dir
    fi

    while true; do
        echo -ne "  ${BOLD}存储池名称 [默认 default]: ${NC}"
        read -r STORAGE_POOL_NAME
        STORAGE_POOL_NAME="${STORAGE_POOL_NAME:-default}"
        storage_is_valid_name "$STORAGE_POOL_NAME" && break
        warn "名称只能包含字母、数字、下划线和短横线，长度不超过 63。"
    done

    if [[ "$STORAGE_DRIVER" == dir ]]; then
        STORAGE_SOURCE="$specified_source"
        echo -ne "  ${BOLD}目录路径 [默认 /var/lib/incus/storage-pools/${STORAGE_POOL_NAME}]: ${NC}"
        read -r STORAGE_SOURCE
        STORAGE_SOURCE="${STORAGE_SOURCE:-/var/lib/incus/storage-pools/${STORAGE_POOL_NAME}}"
        while ! storage_is_valid_value "$STORAGE_SOURCE" || [[ "$STORAGE_SOURCE" != /* ]]; do
            warn "请输入以 / 开头且不含空格的绝对路径。"
            echo -ne "  ${BOLD}目录路径: ${NC}"
            read -r STORAGE_SOURCE
        done
        return 0
    fi

    echo -e "  ${DIM}可输入物理设备/已有 VG（例如 /dev/sdb、vg0）；留空则创建 Loop 文件。${NC}"
    echo -ne "  ${BOLD}存储源 [留空使用 Loop 文件]: ${NC}"
    read -r STORAGE_SOURCE
    if [[ -n "$STORAGE_SOURCE" ]]; then
        while ! storage_is_valid_value "$STORAGE_SOURCE"; do
            warn "存储源不能包含空格或 YAML 特殊字符。"
            echo -ne "  ${BOLD}存储源: ${NC}"
            read -r STORAGE_SOURCE
        done
    else
        while true; do
            echo -ne "  ${BOLD}Loop 大小（GiB）[默认 60]: ${NC}"
            read -r STORAGE_SIZE
            STORAGE_SIZE="${STORAGE_SIZE:-60}"
            STORAGE_SIZE="$(normalize_storage_size "$STORAGE_SIZE")" && break
            warn "请输入正整数，或带单位的大小（例如 60GiB）。"
        done
    fi
}

validate_storage_selection() {
    storage_set_defaults
    case "$STORAGE_DRIVER" in
        none) return 0 ;;
        dir)
            storage_is_valid_name "$STORAGE_POOL_NAME" || return 1
            [[ "$STORAGE_SOURCE" == /* ]] && storage_is_valid_value "$STORAGE_SOURCE"
            ;;
        zfs|lvm|btrfs)
            storage_is_valid_name "$STORAGE_POOL_NAME" || return 1
            if [[ -n "$STORAGE_SOURCE" ]]; then
                storage_is_valid_value "$STORAGE_SOURCE"
            else
                STORAGE_SIZE="$(normalize_storage_size "$STORAGE_SIZE")"
            fi
            ;;
        *) return 1 ;;
    esac
}

storage_preseed_yaml() {
    validate_storage_selection || { error "存储池配置无效"; return 1; }
    [[ "$STORAGE_DRIVER" == none ]] && return 0
    printf '  - name: %s\n    driver: %s\n    config:\n' "$STORAGE_POOL_NAME" "$STORAGE_DRIVER"
    if [[ -n "$STORAGE_SOURCE" ]]; then
        printf '      source: %s\n' "$STORAGE_SOURCE"
    else
        printf '      size: %s\n' "$STORAGE_SIZE"
    fi
    if [[ "$STORAGE_DRIVER" == lvm ]]; then
        printf '      lvm.use_thinpool: "true"\n'
    fi
    # A command substitution returns the status of its final command.  The
    # old `[[ ... ]] && printf ...` form returned 1 for btrfs/dir, which made
    # the preseed assembly abort before Incus was even called.
    return 0
}

install_selected_storage_deps() {
    case "${STORAGE_DRIVER:-none}" in
        none|dir) return 0 ;;
        btrfs)
            case "$OS_ID" in
                alpine) apk add --no-cache btrfs-progs >/dev/null ;;
                rocky) dnf install -y -q btrfs-progs >/dev/null 2>&1 ;;
                *) apt-get install -y -qq btrfs-progs >/dev/null 2>&1 ;;
            esac
            ;;
        lvm)
            case "$OS_ID" in
                alpine) apk add --no-cache lvm2 >/dev/null ;;
                rocky) dnf install -y -q lvm2 >/dev/null 2>&1 ;;
                *) apt-get install -y -qq lvm2 >/dev/null 2>&1 ;;
            esac
            ;;
        zfs) return 0 ;;
        *) error "未知存储驱动: ${STORAGE_DRIVER}"; return 1 ;;
    esac || { error "${STORAGE_DRIVER} 存储池依赖安装失败"; return 1; }
    log "已安装 ${STORAGE_DRIVER} 存储池所需依赖"
}

ensure_selected_storage_pool() {
    [[ "${STORAGE_DRIVER:-none}" != none ]] || {
        info "已跳过存储池创建，可在面板节点详情的“存储”页继续配置"
        return 0
    }
    validate_storage_selection || return 1
    if incus storage show "$STORAGE_POOL_NAME" >/dev/null 2>&1; then
        info "存储池 ${STORAGE_POOL_NAME} 已存在，跳过创建"
        return 0
    fi
    [[ "$STORAGE_DRIVER" == dir ]] && mkdir -p "$STORAGE_SOURCE"
    local options=()
    [[ -n "$STORAGE_SOURCE" ]] && options+=("source=${STORAGE_SOURCE}") || options+=("size=${STORAGE_SIZE}")
    [[ "$STORAGE_DRIVER" == lvm ]] && options+=("lvm.use_thinpool=true")
    info "创建 ${STORAGE_DRIVER} 存储池: ${STORAGE_POOL_NAME}"
    incus storage create "$STORAGE_POOL_NAME" "$STORAGE_DRIVER" "${options[@]}"
    log "存储池 ${STORAGE_POOL_NAME} 创建完成"
}
