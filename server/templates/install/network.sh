# ========================== IPv6 子网精准探测模块 ==========================

# 单个 IP 可达性探测
# 返回: 0=可达, 1=不可达
probe_single_ip() {
    local test_ip="$1"
    local iface="$2"

    # 临时绑定测试 IP
    if ! ip -6 addr add "${test_ip}/128" dev "$iface" 2>/dev/null; then
        return 1
    fi

    # 短暂等待 NDP 生效
    sleep 0.5

    # 用该 IP 作为源地址 ping 外网（Google DNS IPv6）
    local ret=1
    if ping6 -c 1 -W 3 -I "$test_ip" 2001:4860:4860::8888 &>/dev/null; then
        ret=0
    fi

    # 无论成功失败，立即清理
    ip -6 addr del "${test_ip}/128" dev "$iface" 2>/dev/null || true
    return $ret
}

# IPv6 子网精准探测主函数
# 输入: $1=宿主机 IPv6 地址(不含前缀) $2=接口掩码前缀 $3=网卡名
# 输出全局变量:
#   PROBE_TYPE:  "full_64" | "small_block" | "single_ip" | "skip"
#   PROBE_CIDR:  安全 CIDR（如 "2604:a880:2:d1::/64"）
#   PROBE_COUNT: 可用地址数量（数字或 "海量"）
PROBE_TYPE=""
PROBE_CIDR=""
PROBE_COUNT="0"

probe_ipv6_subnet() {
    local host_ip="$1"
    local host_prefix="$2"
    local iface="$3"

    PROBE_TYPE=""
    PROBE_CIDR=""
    PROBE_COUNT="0"

    # 前缀 > 64 的直接按小段/单 IP 处理（如 /128）
    if [[ "$host_prefix" -gt 126 ]]; then
        PROBE_TYPE="single_ip"
        PROBE_COUNT="0"
        return 0
    fi

    # 确保 python3 可用（用于 IPv6 地址偏移计算）
    if ! command -v python3 &>/dev/null; then
        if [[ "$OS_ID" == "alpine" ]]; then
            apk add --no-cache python3 >/dev/null 2>&1 || true
        elif [[ "$OS_ID" == "rocky" ]]; then
            dnf install -y -q python3 >/dev/null 2>&1 || true
        else
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq >/dev/null 2>&1 || true
            apt-get install -y -qq python3 >/dev/null 2>&1 || true
        fi
    fi

    if ! command -v python3 &>/dev/null; then
        warn "python3 不可用，无法进行精准探测"
        PROBE_TYPE="skip"
        return 1
    fi

    echo -e "  ${CYAN}▶ 第 1 步：远距探测（验证完整 /64 是否可用）...${NC}"

    # ---- 第 1 级：远距探测 ----
    # 生成一个距离宿主机 IP 尽可能远的同 /64 地址
    local far_ip
    far_ip=$(python3 -c "
import ipaddress
addr = ipaddress.IPv6Address('${host_ip}')
# 取 /64 网络前缀
net = ipaddress.IPv6Network(str(addr) + '/64', strict=False)
# 用网络地址 + 反转的 host 部分生成远端 IP
# 如原始 host 部分为 ::19，则远端为 ::ffff:ffff:ffff:fffe
far = net.network_address + (net.num_addresses - 2)
# 确保不与宿主机 IP 重合
if far == addr:
    far = net.network_address + (net.num_addresses - 3)
print(str(far))
" 2>/dev/null)

    if [[ -z "$far_ip" ]]; then
        PROBE_TYPE="skip"
        return 1
    fi

    if probe_single_ip "$far_ip" "$iface"; then
        echo -e "  ${GREEN}✓ 远距探测通过 → 完整 /64 可用${NC}"
        # 计算 /64 网络地址
        local net64
        net64=$(python3 -c "
import ipaddress
net = ipaddress.IPv6Network('${host_ip}/64', strict=False)
print(str(net))
" 2>/dev/null)
        PROBE_TYPE="full_64"
        PROBE_CIDR="$net64"
        PROBE_COUNT="海量"
        return 0
    fi

    echo -e "  ${YELLOW}✗ 远距探测未通过，非完整 /64${NC}"
    echo -e "  ${CYAN}▶ 第 2 步：近距探测（验证是否有额外可用 IP）...${NC}"

    # ---- 第 2 级：近距探测 ----
    local near_ip
    near_ip=$(python3 -c "
import ipaddress
addr = ipaddress.IPv6Address('${host_ip}')
print(str(addr + 2))
" 2>/dev/null)

    if [[ -z "$near_ip" ]]; then
        PROBE_TYPE="skip"
        return 1
    fi

    if ! probe_single_ip "$near_ip" "$iface"; then
        echo -e "  ${YELLOW}✗ 近距探测未通过 → 仅单个 IP 可用${NC}"
        PROBE_TYPE="single_ip"
        PROBE_COUNT="0"
        return 0
    fi

    echo -e "  ${GREEN}✓ 近距探测通过，存在额外可用 IP${NC}"
    echo -e "  ${CYAN}▶ 第 3 步：边界收敛（精确定位可用范围）...${NC}"

    # ---- 第 3 级：指数探测 + 二分收敛 ----
    local last_pass=2
    local first_fail=0
    local offset=4

    # 指数递增找到第一个失败的偏移
    while [[ $offset -le 65536 ]]; do
        local test_ip_exp
        test_ip_exp=$(python3 -c "
import ipaddress
addr = ipaddress.IPv6Address('${host_ip}')
print(str(addr + ${offset}))
" 2>/dev/null)

        if [[ -z "$test_ip_exp" ]]; then
            first_fail=$offset
            break
        fi

        echo -ne "  测试偏移 +${offset}... "
        if probe_single_ip "$test_ip_exp" "$iface"; then
            echo -e "${GREEN}✓${NC}"
            last_pass=$offset
            offset=$((offset * 2))
        else
            echo -e "${YELLOW}✗${NC}"
            first_fail=$offset
            break
        fi
    done

    # 如果 65536 都通过了，当作大段处理
    if [[ $first_fail -eq 0 ]]; then
        echo -e "  ${GREEN}✓ 可用 IP 数量极大（>65536）${NC}"
        local net64
        net64=$(python3 -c "
import ipaddress
net = ipaddress.IPv6Network('${host_ip}/64', strict=False)
print(str(net))
" 2>/dev/null)
        PROBE_TYPE="full_64"
        PROBE_CIDR="$net64"
        PROBE_COUNT="海量"
        return 0
    fi

    # 二分查找精确边界
    local lo=$last_pass
    local hi=$first_fail

    while [[ $((hi - lo)) -gt 1 ]]; do
        local mid=$(( (lo + hi) / 2 ))
        local test_ip_mid
        test_ip_mid=$(python3 -c "
import ipaddress
addr = ipaddress.IPv6Address('${host_ip}')
print(str(addr + ${mid}))
" 2>/dev/null)

        echo -ne "  二分测试 +${mid}... "
        if probe_single_ip "$test_ip_mid" "$iface"; then
            echo -e "${GREEN}✓${NC}"
            lo=$mid
        else
            echo -e "${YELLOW}✗${NC}"
            hi=$mid
        fi
    done

    # lo 是最后一个通过的偏移，可用总数 = lo + 1（包含偏移 0 即宿主机本身）
    # 但宿主机占用 1 个，所以容器可用 = lo
    local usable_count=$lo

    # 向下取整为最近的安全 CIDR
    # 找到满足 2^n <= usable_count 的最大 n
    local cidr_prefix
    local cidr_count
    cidr_prefix=$(python3 -c "
import ipaddress, math
host = ipaddress.IPv6Address('${host_ip}')
count = ${usable_count}
if count <= 0:
    print('')
else:
    # 找到 2^n <= count 的最大 n
    n = int(math.log2(count)) if count > 0 else 0
    if n < 1:
        n = 1
    prefix_len = 128 - n
    # 计算对齐的网络地址
    net = ipaddress.IPv6Network(str(host) + '/' + str(prefix_len), strict=False)
    # 确保宿主机 IP 在此网络内
    if host in net:
        print(str(net) + '|' + str(2**n))
    else:
        # 尝试向上偏移一位
        prefix_len += 1
        n -= 1
        net = ipaddress.IPv6Network(str(host) + '/' + str(prefix_len), strict=False)
        print(str(net) + '|' + str(2**n))
" 2>/dev/null)

    if [[ -z "$cidr_prefix" || "$cidr_prefix" == "" ]]; then
        PROBE_TYPE="single_ip"
        PROBE_COUNT="0"
        return 0
    fi

    PROBE_TYPE="small_block"
    PROBE_CIDR=$(echo "$cidr_prefix" | cut -d'|' -f1)
    cidr_count=$(echo "$cidr_prefix" | cut -d'|' -f2)
    PROBE_COUNT="$cidr_count"

    echo -e "  ${GREEN}✓ 检测完成：实际可用约 ${usable_count} 个 IP，安全上报为 ${PROBE_CIDR}（${cidr_count} 个）${NC}"
    return 0
}

# ========================== 纯 IPv6 支持功能模块 ==========================

setup_temp_network() {
    step "临时急救：挂载 DNS64 解析补网..."
    # 为能够下载 Github 的代码，临时注入公益 DNS64
    if ! grep -q "2a00:1098:2b::1" /etc/resolv.conf; then
        # 插入 resolv.conf 顶部
        sed -i '1i nameserver 2a00:1098:2b::1\nnameserver 2a01:4f8:c2c:123f::1' /etc/resolv.conf
        info "已临时写入 NAT64 路由节点，恢复对纯 IPv4 站点的访问能力"
    fi
}

setup_warp_v4() {
    step "破壁出击：安装 Cloudflare WARP 提供全局 IPv4 逃生出站隧道..."
    if [[ "$OS_ID" == "alpine" ]]; then
        warn "Alpine 轻量模式暂不自动部署 WARP；保留原生 IPv6 出站"
        warn "Incus、Agent 与 IPv6 NAT 仍会继续安装"
        return 0
    fi

    # 核心修复一：在建隧道前，抓取并物理备份原生态纯净网关参数
    REAL_V6_IFACE=$(ip -6 route show default 2>/dev/null | grep -v wg | grep -oP 'dev \K\S+' | head -1)
    REAL_V6_GW=$(ip -6 route show default 2>/dev/null | grep -v wg | grep -oP 'via \K\S+' | head -1)
    [ -z "$REAL_V6_IFACE" ] && REAL_V6_IFACE=$(ip -o -6 addr show scope global | grep -v wg | awk '{print $2}' | head -1)
    echo "$REAL_V6_IFACE" > /etc/incudal_v6_iface
    echo "$REAL_V6_GW" > /etc/incudal_v6_gw

    # 强制不干涉内核锁版本依赖
    export DEBIAN_FRONTEND=noninteractive
    if [[ "$OS_ID" == "alpine" ]]; then
        apk add --no-cache wireguard-tools >/dev/null 2>&1 || true
    elif [[ "$OS_ID" == "rocky" ]]; then
        dnf install -y -q wireguard-tools >/dev/null 2>&1 || true
    else
        apt-get update -qq 2>/dev/null || true
    fi
    if [[ "$OS_ID" != "rocky" ]] && ! apt-get install -y -qq wireguard-tools openresolv >/dev/null 2>&1; then
        warn "wireguard-tools 安装失败（纯 IPv6 环境 apt 源可能不可达）"
        warn "尝试仅安装 wireguard-tools..."
        apt-get install -y -qq wireguard-tools >/dev/null 2>&1 || true
    fi

    # 检查 wireguard 是否可用
    if ! command -v wg &>/dev/null; then
        warn "WireGuard 工具未安装成功，跳过 WARP 配置"
        warn "容器将仅使用 IPv6 出站，可稍后手动安装 WARP"
        return 0
    fi

    local wgcf_url=""
    if [[ "$ARCH" == "amd64" || "$ARCH" == "x86_64" ]]; then
        wgcf_url="https://github.com/ViRb3/wgcf/releases/download/v2.2.22/wgcf_2.2.22_linux_amd64"
    elif [[ "$ARCH" == "arm64" || "$ARCH" == "aarch64" ]]; then
        wgcf_url="https://github.com/ViRb3/wgcf/releases/download/v2.2.22/wgcf_2.2.22_linux_arm64"
    else
        warn "架构不受支持，跳过 WARP 安装"
        return 0
    fi

    local wgcf_sha256=""
    case "$ARCH" in
        amd64|x86_64)
            wgcf_sha256="268d187e649870b603ad2e5c1b74a696251f6c2f6f075c726a174a0039b0b1e2"
            ;;
        arm64|aarch64)
            wgcf_sha256="e5ff08d3aae5374935211053b2d64d96daaa3f1aec8e9a1dab7418125585a011"
            ;;
    esac

    info "拉取核心组件 wgcf..."
    # 纯 IPv6 下 GitHub 可能不可达，多次重试
    local retry=0
    local max_retry=3
    local wgcf_tmp="/tmp/wgcf-$$"
    rm -f /usr/local/bin/wgcf "$wgcf_tmp" 2>/dev/null || true
    while [[ $retry -lt $max_retry ]]; do
        if curl -fsSL --connect-timeout 30 --max-time 120 "$wgcf_url" -o "$wgcf_tmp" 2>/dev/null; then
            if printf '%s  %s\n' "$wgcf_sha256" "$wgcf_tmp" | sha256sum -c - >/dev/null 2>&1; then
                install -m 0755 "$wgcf_tmp" /usr/local/bin/wgcf
                break
            fi
            warn "wgcf SHA-256 校验失败，拒绝执行下载文件"
        fi
        retry=$((retry + 1))
        if [[ $retry -lt $max_retry ]]; then
            info "下载失败，${retry}/${max_retry} 次重试中（等待 5s）..."
            sleep 5
        fi
    done

    rm -f "$wgcf_tmp" 2>/dev/null || true
    if [[ ! -f /usr/local/bin/wgcf ]] || [[ $(stat -c%s /usr/local/bin/wgcf 2>/dev/null || echo "0") -lt 1048576 ]]; then
        warn "wgcf 下载失败（纯 IPv6 环境无法访问 GitHub CDN）"
        warn "跳过 WARP 配置，容器将仅使用 IPv6 出站"
        warn "解决方案: 手动下载 wgcf 到 /usr/local/bin/wgcf 后运行安装脚本"
        rm -f /usr/local/bin/wgcf 2>/dev/null || true
        return 0
    fi

    chmod +x /usr/local/bin/wgcf

    mkdir -p /etc/wireguard
    cd /etc/wireguard || return 0

    if [[ ! -f wgcf-account.toml ]]; then
        info "底层设备匿名注册申请中..."
        yes | /usr/local/bin/wgcf register --accept-tos >/dev/null 2>&1 || true
    fi

    if [[ ! -f wgcf-profile.conf ]]; then
        info "生成防污染隧道隔离切片..."
        /usr/local/bin/wgcf generate >/dev/null 2>&1 || true
    fi

    if [[ -f wgcf-profile.conf ]]; then
        # 核心切片：剔除接管所有 IPv6，把唯一的源出站权让给宿主机
        sed -i '/AllowedIPs = ::\/0/d' wgcf-profile.conf
        # 删除 IPv6 隧道地址，只保留 IPv4 隧道地址（防止 wg-quick 为 IPv6 地址添加路由规则）
        sed -i 's/Address = \([^,]*\), *fd[0-9a-f:].*$/Address = \1/' wgcf-profile.conf
        # 核心切片：将服务端入口转换为无缝直连 IPv6，防止断流握手
        sed -i 's/Endpoint.*engage.cloudflareclient.com/Endpoint = \[2606:4700:d0::a29f:c001\]/g' wgcf-profile.conf
        # 关键修复：删除 DNS 行，防止 wg-quick 在启停时劫持宿主机 /etc/resolv.conf
        # 如果不删除，wg-quick down 会将 resolv.conf 回滚到原始的纯 IPv4 DNS（如 GCP 的 169.254.169.254），
        # 导致宿主机和所有容器的 DNS 解析全部瘫痪
        sed -i '/^DNS/d' wgcf-profile.conf

        cp wgcf-profile.conf wg0.conf
        chmod 600 wg0.conf

        systemctl enable wg-quick@wg0 >/dev/null 2>&1 || true
        systemctl start wg-quick@wg0 >/dev/null 2>&1 || true

        info "内核级网卡 wg0 启动完毕，您的服务器已具备虚拟双栈特性！"
    else
        warn "WARP 配置文件未能生成（wgcf register 可能失败）"
        warn "容器将仅使用 IPv6 出站，可稍后手动配置 WARP"
    fi

    # 注入出站控制器
    cat > /usr/local/bin/incus-warp << 'EOF'
#!/bin/bash
if [[ "$1" == "on" ]]; then
    systemctl start wg-quick@wg0 2>/dev/null
    echo "🌍 [ON] WARP IPv4 抢救通道已激活。容器支持出海更新包下载。"
elif [[ "$1" == "off" ]]; then
    systemctl stop wg-quick@wg0 2>/dev/null
    # 核心修复二：使用强落地的环境备份读取真实原生网关，拒绝 fe80::1
    REAL_V6_IFACE=$(cat /etc/incudal_v6_iface 2>/dev/null)
    REAL_V6_GW=$(cat /etc/incudal_v6_gw 2>/dev/null)
    [ -z "$REAL_V6_IFACE" ] && REAL_V6_IFACE=$(ip -o -6 addr show scope global | grep -v wg | awk '{print $2}' | head -1)

    if [ -n "$REAL_V6_IFACE" ] && ! ip -6 route | grep "^default" | grep -v wg > /dev/null 2>&1; then
        if [ -n "$REAL_V6_GW" ]; then
            ip -6 route add default via "$REAL_V6_GW" dev "$REAL_V6_IFACE" 2>/dev/null || true
        else
            ip -6 route add default dev "$REAL_V6_IFACE" 2>/dev/null || true
        fi
    fi
    # 核心修复三：全面压实纯 DNS64 集群阵列防止 0% 超时现象
    cat > /etc/resolv.conf <<DNSEOF
# Incudal WARP-OFF 模式 - 纯 NAT64+DNS64 解析器
nameserver 2a00:1098:2b::1
nameserver 2a01:4f8:c2c:123f::1
nameserver 2001:67c:2b0::4
DNSEOF
    echo "🧊 [OFF] WARP IPv4 通道已切断，原生真实 IPv6 路由结构已接管。"
else
    echo -e "用法: \033[1;36mincus-warp [on/off]\033[0m"
    if systemctl is-active wg-quick@wg0 >/dev/null 2>&1; then
        echo -e "当前出站分流状态: \033[1;32m[ON] IPv6 原生 + IPv4 WARP 接驳\033[0m"
    else
        echo -e "当前出站分流状态: \033[1;31m[OFF] 100% 绝对纯净 IPv6 环境回落\033[0m"
    fi
fi
EOF
    chmod +x /usr/local/bin/incus-warp
    info "出站调度指令控制台部署成功: 随时键入 incus-warp 操控"

    # 部署 IPv6 路由恢复守护脚本（兜底保险）
    cat > /usr/local/bin/ipv6-route-guard.sh << 'GUARD_EOF'
#!/bin/bash
# IPv6 路由恢复守护脚本 - 由 Incudal 安装脚本自动部署
# 每 10 秒检测 IPv6 默认路由，丢失则自动恢复

IPV6_IFACE=$(cat /etc/incudal_v6_iface 2>/dev/null)
IPV6_GATEWAY=$(cat /etc/incudal_v6_gw 2>/dev/null)

if [ -z "$IPV6_IFACE" ]; then
    IPV6_IFACE=$(ip -6 route show default 2>/dev/null | grep -v wg | grep -oP 'dev \K\S+' | head -1)
    [ -z "$IPV6_IFACE" ] && IPV6_IFACE=$(ip -o -6 addr show scope global | grep -v wg | awk '{print $2}' | head -1)
fi

[ -z "$IPV6_IFACE" ] && exit 0

while true; do
    # 检查是否存在非 WireGuard 接口的 IPv6 默认路由
    if ! ip -6 route | grep "^default" | grep -v wg > /dev/null 2>&1; then
        if [ -n "$IPV6_GATEWAY" ]; then
            ip -6 route add default via "$IPV6_GATEWAY" dev "$IPV6_IFACE" 2>/dev/null
        else
            ip -6 route add default dev "$IPV6_IFACE" 2>/dev/null
        fi
    fi
    sleep 10
done
GUARD_EOF
    chmod +x /usr/local/bin/ipv6-route-guard.sh

    # 创建 systemd 服务
    cat > /etc/systemd/system/ipv6-route-guard.service << 'SVC_EOF'
[Unit]
Description=IPv6 Route Guard - Incudal 自动恢复 IPv6 默认路由
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ipv6-route-guard.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SVC_EOF

    systemctl daemon-reload
    systemctl enable --now ipv6-route-guard > /dev/null 2>&1 || true
    info "IPv6 路由守护已部署: 即使 WARP 意外断联，IPv6 也将在 10 秒内自愈"
}

