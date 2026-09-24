# ZFS 加载成功后固化开机加载，并刷新当前内核的 initramfs。
persist_zfs_module() {
    if ! modprobe zfs 2>/dev/null; then
        return 1
    fi

    mkdir -p /etc/modules-load.d
    printf '%s\n' zfs > /etc/modules-load.d/zfs.conf
    info "已配置 ZFS 模块开机自动加载"

    if command -v update-initramfs &>/dev/null; then
        info "正在将 ZFS 模块写入当前内核 initramfs..."
        update-initramfs -u -k "$(uname -r)" >/dev/null 2>&1 || \
            warn "initramfs 刷新失败；modules-load 配置仍会在开机时加载 ZFS"
    elif command -v dracut &>/dev/null; then
        info "正在使用 dracut 刷新当前内核 initramfs..."
        dracut -f --kver "$(uname -r)" >/dev/null 2>&1 || \
            warn "dracut 刷新失败；modules-load 配置仍会在开机时加载 ZFS"
    fi
}

# ---- Debian ZFS 策略 1: 预编译模块安装 ----
install_zfs_prebuilt() {
    local kernel_ver="$1"
    # 预编译包没有随脚本提供独立、固定的校验清单，不能直接以 root 解压并安装。
    # 返回失败后由调用方使用 Debian APT/DKMS 的签名包流程。
    info "跳过未提供独立 SHA-256 清单的预编译 ZFS 模块 (${kernel_ver})"
    return 1
}

# ---- Debian ZFS 策略 2: DKMS 即时编译（回退方案）----
install_zfs_dkms() {
    info "安装 DKMS 编译依赖（linux-headers、build-essential）..."
    local kernel_ver
    kernel_ver=$(uname -r)

    # 优先安装通用编译核心工具，防止一处失败导致全部跳过
    if ! apt-get install -y -qq build-essential dkms >/dev/null 2>&1; then
        warn "DKMS 编译工具安装失败"
        return 1
    fi

    # 只能针对正在运行的精确内核构建；元包安装出的新内核不能冒充当前 headers。
    if [[ ! -e "/lib/modules/${kernel_ver}/build/Makefile" ]]; then
        apt-get install -y -qq "linux-headers-${kernel_ver}" >/dev/null 2>&1 || true
    fi

    if [[ ! -e "/lib/modules/${kernel_ver}/build/Makefile" ]]; then
        local deb_arch flavor_meta=""
        deb_arch=$(dpkg --print-architecture 2>/dev/null || echo amd64)
        case "$kernel_ver" in
            *-cloud-*) flavor_meta="linux-headers-cloud-${deb_arch}" ;;
            *-virtual) flavor_meta="linux-headers-virtual" ;;
            *-aws) flavor_meta="linux-headers-aws" ;;
            *-azure) flavor_meta="linux-headers-azure" ;;
            *-gcp) flavor_meta="linux-headers-gcp" ;;
            *-oracle) flavor_meta="linux-headers-oracle" ;;
        esac
        if [[ -n "$flavor_meta" ]]; then
            info "尝试安装 Cloud 内核 headers 元包: ${flavor_meta}"
            apt-get install -y -qq "$flavor_meta" >/dev/null 2>&1 || true
        fi
    fi

    if [[ ! -e "/lib/modules/${kernel_ver}/build/Makefile" ]]; then
        warn "软件源没有与当前运行内核完全匹配的 headers: linux-headers-${kernel_ver}"
        warn "可能是 DD 后遗留的定制/云厂商内核；跳过 ZFS，避免错误编译或卡住安装"
        return 1
    fi

    info "开始 DKMS 编译 ZFS 模块（CPU 将跑满，请耐心等待）..."
    local start_time=$SECONDS

    if apt-get install -y -qq zfsutils-linux >/dev/null 2>&1; then
        local elapsed=$(( SECONDS - start_time ))
        info "编译耗时: ${elapsed} 秒"

        # 验证 ZFS 模块
        if modprobe zfs 2>/dev/null; then
            log "ZFS DKMS 编译成功（模块已加载）"
            persist_zfs_module || true
            return 0
        else
            warn "ZFS 工具已安装但内核模块加载失败（DKMS 编译可能不完整）"
            info "面板仍可使用 dir/btrfs 存储池，ZFS 可稍后手动修复"
            return 1
        fi
    else
        warn "ZFS 安装失败，已跳过（面板可使用 dir/btrfs 存储池）"
        return 1
    fi
}

# 等待 daemon 的 Unix socket 和 API 真正就绪，避免服务管理器已返回但 Incus 尚未可用。
wait_for_incus_daemon() {
    local attempt
    for attempt in $(seq 1 30); do
        if incus version 2>/dev/null | grep -q -E "Server version: [0-9]"; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# Incus 的非特权容器需要 root 拥有 subordinate UID/GID 范围。
# 部分 RPM 包不会像 Debian/Alpine 包一样自动建立它们。
ensure_root_idmap() {
    local changed="false"
    touch /etc/subuid /etc/subgid
    if ! awk -F: '$1 == "root" && $3 > 0 { found=1 } END { exit !found }' /etc/subuid; then
        echo "root:1000000:1000000000" >> /etc/subuid
        changed="true"
    fi
    if ! awk -F: '$1 == "root" && $3 > 0 { found=1 } END { exit !found }' /etc/subgid; then
        echo "root:1000000:1000000000" >> /etc/subgid
        changed="true"
    fi
    [[ "$changed" == "true" ]]
}

# Repair the default profile when re-running the installer against a partially
# initialized daemon.  A previous preseed attempt may have created the bridge
# or pool before failing, so the early-return path must not leave the profile
# unusable.
ensure_default_profile() {
    [[ "${STORAGE_DRIVER:-none}" != "none" ]] || return 0

    if ! incus profile show default >/dev/null 2>&1; then
        incus profile create default >/dev/null
    fi

    local profile_config
    profile_config=$(incus profile show default 2>/dev/null || true)
    if ! grep -qE '^[[:space:]]+root:' <<< "$profile_config"; then
        incus profile device add default root disk path=/ pool="$STORAGE_POOL_NAME" >/dev/null
    fi
    if ! grep -qE '^[[:space:]]+eth0:' <<< "$profile_config"; then
        incus profile device add default eth0 nic name=eth0 network="$BRIDGE_NAME" >/dev/null
    fi
}

# 步骤 3: 安装 Incus
install_incus() {
    step "步骤 [3/5]  安装 Incus..."

    # 幂等性：已安装且服务端正常运行则跳过
    if incus version 2>/dev/null | grep -q -E "Server version: [0-9]"; then
        if ensure_root_idmap; then
            if [[ "$OS_ID" == "alpine" ]]; then
                rc-service incusd restart >/dev/null 2>&1 || true
            else
                systemctl restart incus.service 2>/dev/null || systemctl restart incus 2>/dev/null || true
            fi
            wait_for_incus_daemon || true
        fi
        local current_ver
        current_ver=$(incus version 2>/dev/null | awk '/Client version/ {print $3}' || echo "未知")
        info "Incus 服务已安装并运行（版本: ${current_ver}），跳过安装"
        return 0
    fi

    if [[ "$OS_ID" == "alpine" ]]; then
        local alpine_branch="v$(printf '%s' "$OS_VERSION" | cut -d. -f1,2)"
        local alpine_repo="https://dl-cdn.alpinelinux.org/alpine/${alpine_branch}"
        grep -qxF "${alpine_repo}/main" /etc/apk/repositories || echo "${alpine_repo}/main" >> /etc/apk/repositories
        grep -qxF "${alpine_repo}/community" /etc/apk/repositories || echo "${alpine_repo}/community" >> /etc/apk/repositories
        apk update >/dev/null
        apk add --no-cache incus incus-client incus-openrc >/dev/null || {
            error "Alpine Incus 安装失败，请检查 ${alpine_branch} main/community 仓库"
            return 1
        }
        ensure_root_idmap || true
        rc-update add incusd default >/dev/null 2>&1 || true
        rc-service incusd restart >/dev/null 2>&1 || rc-service incusd start >/dev/null 2>&1
        if ! wait_for_incus_daemon; then
            error "Alpine Incus 服务启动超时，请运行 rc-service incusd status 检查"
            return 1
        fi
        log "Incus 安装完成（Alpine OpenRC）"
        return 0
    fi

    if [[ "$OS_ID" == "rocky" ]]; then
        local rocky_major="${OS_VERSION%%.*}"
        local rocky_copr_repo=""
        if [[ "$rocky_major" == "9" ]]; then
            rocky_copr_repo="https://copr.fedorainfracloud.org/coprs/neelc/incus/repo/epel-9/neelc-incus-epel-9.repo"
        else
            rocky_copr_repo="https://copr.fedorainfracloud.org/coprs/neelc/incus/repo/rhel+epel-10/neelc-incus-rhel+epel-10.repo"
        fi
        dnf install -y -q epel-release wget dnf-plugins-core >/dev/null 2>&1
        mkdir -p /etc/yum.repos.d
        curl -fsSL "$rocky_copr_repo" -o /etc/yum.repos.d/neelc-incus.repo
        dnf install -y -q incus incus-tools >/dev/null 2>&1 || {
            error "Rocky Linux Incus 安装失败，请检查 EPEL/COPR 网络连接"
            return 1
        }
        ensure_root_idmap || true
        systemctl enable --now incus.service incus.socket 2>/dev/null || systemctl enable --now incus 2>/dev/null || true
        if ! wait_for_incus_daemon; then
            error "Rocky Linux Incus 服务启动超时，请运行 systemctl status incus 检查"
            return 1
        fi
        log "Incus 安装完成（Rocky Linux COPR）"
        return 0
    fi

    # 导入 Zabbly GPG 密钥
    mkdir -p /etc/apt/keyrings
    curl -fsSL https://pkgs.zabbly.com/key.asc \
        | gpg --yes --dearmor -o /etc/apt/keyrings/zabbly.gpg

    # 添加 Zabbly APT 源（同时支持 Ubuntu 和 Debian）
    cat > /etc/apt/sources.list.d/zabbly-incus-stable.sources <<SRC
Enabled: yes
Types: deb
URIs: https://pkgs.zabbly.com/incus/stable
Suites: ${OS_CODENAME}
Components: main
Architectures: ${ARCH}
Signed-By: /etc/apt/keyrings/zabbly.gpg
SRC

    apt-get update -qq 2>/dev/null
    apt-get install -y -qq incus >/dev/null
    ensure_root_idmap || true
    systemctl enable --now incus.service incus.socket 2>/dev/null || systemctl enable --now incus 2>/dev/null || true
    if ! wait_for_incus_daemon; then
        error "Incus 服务启动超时，请运行 systemctl status incus 检查"
        return 1
    fi
    log "Incus 安装完成"
}

# 步骤 4: 初始化 Incus
init_incus() {
    step "步骤 [4/5]  初始化 Incus..."

    prepare_incus_dnsmasq

    # 幂等性：网桥已存在时仍补齐用户选择的存储池。
    if incus network show "$BRIDGE_NAME" &>/dev/null; then
        info "网桥 ${BRIDGE_NAME} 已存在，跳过网络初始化"
        ensure_selected_storage_pool || return 1
        ensure_default_profile || return 1
        return 0
    fi

    # 生成 preseed 配置
    local ipv6_block
    if [[ "$MODE" == "nat_ipv6" ]]; then
        info "面板受控模式 (IPv4 NAT + IPv6 环境): 准备建立内核转发链路"
        if [[ -n "${IPV6_SUBNET:-}" ]]; then
            # 有独立子网：routed 模式走 eth1 独立分配 IPv6，但网桥同时启用 IPv6 NAT 作为保底
            # 这样 nat_ipv6_nat 模式的实例也能在同一节点上通过桥共享 IPv6 出口
            ipv6_block="ipv6.address: auto\n      ipv6.nat: \"true\"\n      ipv6.dhcp: \"true\""
            info "▶ [IPv6 配置分支] 独立路由网段 + 网桥 NAT 双通道模式，routed 直通与 NAT 共享可共存。"
        else
            # 用户选择单 IP 共享，网桥需要负责分发 ULA (内部 IPv6) 并 NAT 出口
            ipv6_block="ipv6.address: auto\n      ipv6.nat: \"true\"\n      ipv6.dhcp: \"true\""
            info "▶ [IPv6 配置分支] 单一公共 IP 模式 (Bridge: Auto+NAT)，已激活内部 IPv6 出站共享代理功能。"
        fi

        # [核心修复区] Debian 默认闭合的内核转发
        sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
        sysctl -w net.ipv6.conf.default.forwarding=1 >/dev/null 2>&1 || true
        sysctl -w net.ipv6.conf.all.proxy_ndp=1 >/dev/null 2>&1 || true
        sysctl -w net.ipv6.conf.default.proxy_ndp=1 >/dev/null 2>&1 || true

        # 配置 ndppd (邻居发现)，这是对非直连路由云主机的保底策略
        if [[ -n "${IPV6_SUBNET:-}" && -n "${IPV6_IFACE:-}" ]]; then
            if [[ "$OS_ID" == "alpine" ]]; then
                apk add --no-cache ndppd >/dev/null 2>&1 || true
            elif [[ "$OS_ID" == "rocky" ]]; then
                dnf install -y -q ndppd >/dev/null 2>&1 || true
            else
                export DEBIAN_FRONTEND=noninteractive
                apt-get install -y -qq ndppd >/dev/null 2>&1 || true
            fi
            cat > /etc/ndppd.conf <<EOF
proxy ${IPV6_IFACE} {
    rule ${IPV6_SUBNET} {
        auto
    }
}
EOF
            if [[ "$OS_ID" == "alpine" ]]; then
                rc-update add ndppd default >/dev/null 2>&1 || true
                rc-service ndppd restart >/dev/null 2>&1 || rc-service ndppd start >/dev/null 2>&1 || true
            else
                systemctl restart ndppd 2>/dev/null || true
                systemctl enable ndppd 2>/dev/null || true
            fi
            info "NDPPD 路由代理保活已附加配置"
        fi
    else
        # MODE=nat（仅 IPv4）：检测是否为纯 IPv6 环境
        if [[ "$IS_PURE_IPV6" == "true" ]]; then
            # 纯 IPv6 宿主机即使选了"仅 IPv4"，也必须启用桥 IPv6 NAT，否则容器完全断网
            ipv6_block="ipv6.address: auto\n      ipv6.nat: \"true\"\n      ipv6.dhcp: \"true\""
            info "▶ [IPv6 自动修正] 检测到纯 IPv6 环境，已自动启用网桥 IPv6 NAT 防止容器断网。"
        else
            ipv6_block="ipv6.address: none"
        fi
    fi

    # 纯 IPv6 环境：网桥必须强制配置 100% 纯 NAT64 提供商，防止容器内的双栈域名引发 IPv4 DNS 污染死锁超时
    local dns_block=""
    if [[ "$IS_PURE_IPV6" == "true" ]]; then
        dns_block="dns.nameservers: 2a00:1098:2b::1,2a01:4f8:c2c:123f::1,2001:67c:2b0::4"
        info "纯 IPv6 环境：已为网桥独家配置纯公益 NAT64/DNS64 集群，护航出站"
    fi

    local storage_block=" []"
    if [[ "${STORAGE_DRIVER:-none}" != "none" ]]; then
        storage_block=$'\n'
        storage_block+="$(storage_preseed_yaml)"
    fi

    # A preseed with an empty profile list leaves a fresh Incus installation
    # without a usable default profile.  Create the root disk and bridge
    # devices together with the selected storage pool so the first instance
    # can be launched immediately after installation.
    local profile_block=" []"
    if [[ "${STORAGE_DRIVER:-none}" != "none" ]]; then
        profile_block=$'\n'
        profile_block+=$'  - name: default\n'
        profile_block+=$'    devices:\n'
        profile_block+=$'      eth0:\n'
        profile_block+=$'        name: eth0\n'
        profile_block+="        network: ${BRIDGE_NAME}"$'\n'
        profile_block+=$'        type: nic\n'
        profile_block+=$'      root:\n'
        profile_block+=$'        path: /\n'
        profile_block+="        pool: ${STORAGE_POOL_NAME}"$'\n'
        profile_block+="        type: disk"
    fi

    # 写入文件
    cat > "$PRESEED_FILE" <<YAML
config:
  core.https_address: '[::]:${LISTEN_PORT}'
networks:
  - name: ${BRIDGE_NAME}
    type: bridge
    config:
      ipv4.address: ${BRIDGE_SUBNET}
      ipv4.nat: "true"
      ipv4.dhcp: "true"
      $(echo -e "$ipv6_block")
      ${dns_block:+$dns_block}
storage_pools:${storage_block}
profiles:${profile_block}
cluster: null
YAML

    info "正在执行 Incus preseed 初始化（文件: ${PRESEED_FILE}）..."

    # Incus 7.x also accepts the preseed path directly.  Passing the file as
    # an argument avoids a nested stdin/pipe when this installer itself is
    # launched through `curl | bash`; otherwise a failed preseed can make the
    # parent shell return to its prompt without showing the actual Incus error.
    local init_rc
    INCUS_PRESEED_ACTIVE="true"
    if incus admin init --preseed "$PRESEED_FILE" </dev/null; then
        INCUS_PRESEED_ACTIVE="false"
        log "Incus preseed 初始化命令已返回成功"
    else
        init_rc=$?
        error "Incus 初始化失败（退出码 ${init_rc}；请检查上方 Incus 原始错误），预置配置如下："
        sed 's/^/  | /' "$PRESEED_FILE" >&2
        return "$init_rc"
    fi
    ensure_selected_storage_pool || return 1
    ensure_default_profile || return 1
    log "Incus 初始化完成"
}
