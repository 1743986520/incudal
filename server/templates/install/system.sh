# ========================== 安装步骤 ==========================

# 步骤 1: 配置内核参数
setup_kernel() {
    step "步骤 [1/5]  配置内核参数..."

    # 加载网桥过滤模块
    echo "br_netfilter" > /etc/modules-load.d/br_netfilter.conf
    modprobe br_netfilter || true

    # 基础 sysctl 参数 + BBR 拥塞控制 + TCP 缓冲区优化
    cat > /etc/sysctl.d/99-incus.conf <<EOF
# Incudal 节点内核参数 - 由安装脚本自动生成
# ======== 文件系统 ========
fs.inotify.max_user_instances = 1048576
fs.file-max = 6815744

# ======== 网桥过滤 ========
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-arptables = 1

# ======== IPv4 转发与路由 ========
net.ipv4.ip_forward = 1
net.ipv4.conf.all.route_localnet = 1
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.default.forwarding = 1

# ======== BBR 拥塞控制 ========
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# ======== TCP 性能优化 ========
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_ecn = 0
net.ipv4.tcp_frto = 0
net.ipv4.tcp_mtu_probing = 0
net.ipv4.tcp_rfc1337 = 0
net.ipv4.tcp_sack = 1
net.ipv4.tcp_fack = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_adv_win_scale = 1
net.ipv4.tcp_moderate_rcvbuf = 1

# ======== 网络缓冲区 ========
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 16384 33554432
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192

# ======== IPv6 转发（所有模式默认启用） ========
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1
EOF

    # IPv6 NAT 模式追加代理与路由通告参数
    if [[ "$MODE" == "nat_ipv6" ]]; then
        cat >> /etc/sysctl.d/99-incus.conf <<EOF

# IPv6 NAT 模式专用参数
net.ipv6.conf.all.proxy_ndp = 1
net.ipv6.conf.all.accept_ra = 2
net.ipv6.conf.default.accept_ra = 2
net.ipv6.conf.${DEFAULT_IFACE}.accept_ra = 2
net.ipv6.conf.${DEFAULT_IFACE}.proxy_ndp = 1
EOF
    fi

    sysctl -p >/dev/null 2>&1 || true
    sysctl --system >/dev/null 2>&1 || true

    # 验证 BBR 是否生效
    if lsmod | grep -q bbr 2>/dev/null || sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
        log "BBR 拥塞控制已启用 ✓"
    else
        warn "BBR 未能自动加载（内核可能不支持），TCP 将使用默认拥塞算法"
    fi

    log "内核参数配置完成（含 BBR + TCP 优化）"
}

# 步骤 2: 安装系统依赖
install_deps() {
    step "步骤 [2/5]  安装系统依赖..."

    if [[ "$OS_ID" == "alpine" ]]; then
        apk update >/dev/null
        apk add --no-cache bash curl ca-certificates openssl python3 iproute2 iptables nftables \
            util-linux coreutils grep sed gawk tar gzip xz shadow-uidmap dnsmasq rsync squashfs-tools \
            >/dev/null || {
            error "Alpine Linux 基础依赖安装失败"
            return 1
        }
        update-ca-certificates >/dev/null 2>&1 || true
        if [[ "$STORAGE_DRIVER" == "zfs" ]]; then
            error "Alpine 暂不支持通过本安装器自动部署 ZFS，请选择 DIR/Btrfs 或跳过存储池"
            return 1
        fi
        install_selected_storage_deps || return 1
        log "Alpine 系统依赖安装完成（存储: ${STORAGE_DRIVER}）"
        return 0
    fi

    if [[ "$OS_ID" == "rocky" ]]; then
        dnf install -y -q epel-release curl gnupg2 python3 iproute iptables nftables dnsmasq tar gzip xz >/dev/null 2>&1 || {
            error "Rocky Linux 基础依赖安装失败"
            return 1
        }
        install_selected_storage_deps || return 1
        if [[ "$STORAGE_DRIVER" == "zfs" ]]; then
            if dnf install -y -q zfs >/dev/null 2>&1 && modprobe zfs 2>/dev/null; then
                persist_zfs_module || true
            else
                error "Rocky Linux 未提供可用的 ZFS 模块，无法创建所选 ZFS 存储池"
                return 1
            fi
        fi
        log "Rocky Linux 系统依赖安装完成（存储: ${STORAGE_DRIVER}）"
        return 0
    fi

    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq 2>/dev/null

    # 仅在用户选择 ZFS 时启用 contrib，避免普通 DIR/Btrfs 安装修改无关的软件源。
    if [[ "$OS_ID" == "debian" && "$STORAGE_DRIVER" == "zfs" ]]; then
        local contrib_enabled=false

        # 检查 DEB822 格式源文件（Debian 12+）
        if [[ -f /etc/apt/sources.list.d/debian.sources ]]; then
            if grep -q "contrib" /etc/apt/sources.list.d/debian.sources 2>/dev/null; then
                contrib_enabled=true
            fi
        fi

        # 检查传统格式源文件
        if [[ -f /etc/apt/sources.list ]]; then
            if grep -q "contrib" /etc/apt/sources.list 2>/dev/null; then
                contrib_enabled=true
            fi
        fi

        if [[ "$contrib_enabled" == "false" ]]; then
            info "Debian 系统：仅因选择 ZFS 才启用 contrib 组件..."
            if [[ -f /etc/apt/sources.list.d/debian.sources ]]; then
                sed -i 's/Components: main$/Components: main contrib/' \
                    /etc/apt/sources.list.d/debian.sources 2>/dev/null || true
            elif [[ -f /etc/apt/sources.list ]]; then
                sed -i '/^deb.*main/ { /contrib/! s/main/main contrib/ }' \
                    /etc/apt/sources.list 2>/dev/null || true
            fi
            apt-get update -qq 2>/dev/null
        fi
    fi

    # 安装基础依赖
    apt-get install -y -qq curl gpg dnsmasq >/dev/null 2>&1 || {
        error "Debian/Ubuntu 基础依赖安装失败"
        return 1
    }
    install_selected_storage_deps || return 1

    if [[ "$STORAGE_DRIVER" == "zfs" && "$OS_ID" == "debian" ]]; then
        local debian_zfs_compiled=false
        local kernel_ver
        kernel_ver=$(uname -r)
        if install_zfs_prebuilt "$kernel_ver"; then
            log "系统依赖安装完成（ZFS 预编译模块）"
        else
            warn "未找到内核 ${kernel_ver} 的预编译 ZFS 模块，尝试 DKMS..."
            if install_zfs_dkms; then
                debian_zfs_compiled=true
            else
                error "当前 Debian 内核无法构建 ZFS，无法创建所选存储池"
                return 1
            fi
        fi
        if [[ "$debian_zfs_compiled" == "true" ]]; then
            apt-get clean 2>/dev/null || true
            info "已保留 DKMS 与当前内核 headers，后续内核升级可自动重建 ZFS 模块"
        fi
    elif [[ "$STORAGE_DRIVER" == "zfs" ]]; then
        if apt-get install -y -qq zfsutils-linux >/dev/null 2>&1; then
            if ! modprobe zfs 2>/dev/null; then
                apt-get install -y -qq "linux-modules-extra-$(uname -r)" >/dev/null 2>&1 || true
            fi
            if modprobe zfs 2>/dev/null; then
                persist_zfs_module || true
            else
                error "当前 Ubuntu 内核没有可加载的 ZFS 模块，无法创建所选存储池"
                return 1
            fi
        else
            error "ZFS 工具安装失败，无法创建所选存储池"
            return 1
        fi
    fi

    log "系统依赖安装完成（存储: ${STORAGE_DRIVER}）"
}

