# ========================== 每实例 PPS 防护 ==========================
# 在 Linux bridge 转发层按来源 MAC 独立计数。攻击实例超过阈值时只丢弃
# 该实例的流量，不会限制宿主机管理流量，也不会连带影响其他实例。
disable_pps_guard() {
    if command -v systemctl &>/dev/null; then
        systemctl disable --now incudal-pps-guard 2>/dev/null || true
        rm -f /etc/systemd/system/incudal-pps-guard.service
        systemctl daemon-reload 2>/dev/null || true
    elif command -v rc-service &>/dev/null; then
        rc-service incudal-pps-guard stop 2>/dev/null || true
        rc-update del incudal-pps-guard default 2>/dev/null || true
        rm -f /etc/init.d/incudal-pps-guard
    fi
    nft delete table inet incudal_pps_guard 2>/dev/null || true
    rm -f /usr/local/sbin/incudal-pps-guard /etc/incudal/pps-guard.conf
    PPS_PROTECTION_ENABLED="false"
    log "每实例 PPS 防护已关闭"
}

install_pps_guard() {
    if [[ "$PPS_PROTECTION_ENABLED" != "true" ]]; then
        disable_pps_guard
        return 0
    fi

    step "安装每实例 PPS 防护（${PPS_LIMIT} 包/秒）..."

    if ! command -v nft &>/dev/null; then
        error "未找到 nftables，请先安装 nftables 后重试"
        return 1
    fi

    if ! [[ "$PPS_LIMIT" =~ ^[0-9]+$ ]] || (( PPS_LIMIT < PPS_MIN_LIMIT || PPS_LIMIT > 500000 )); then
        warn "PPS 阈值 ${PPS_LIMIT} 无效，已回退为 20000"
        PPS_LIMIT="$PPS_MIN_LIMIT"
    fi

    mkdir -p /etc/incudal
    cat > /etc/incudal/pps-guard.conf <<EOF
PPS_LIMIT=${PPS_LIMIT}
PPS_MIN_LIMIT=${PPS_MIN_LIMIT}
PPS_BURST_PACKETS=${PPS_BURST_PACKETS}
PPS_SINGLE_TARGET_LIMIT=${PPS_SINGLE_TARGET_LIMIT}
PPS_SINGLE_TARGET_BURST=${PPS_SINGLE_TARGET_BURST}
PPS_BLOCK_SECONDS=${PPS_BLOCK_SECONDS}
PPS_OBSERVE_SECONDS=${PPS_OBSERVE_SECONDS}
BRIDGE_NAME=${BRIDGE_NAME}
EOF
    chmod 0600 /etc/incudal/pps-guard.conf

    cat > /usr/local/sbin/incudal-pps-guard <<'GUARD'
#!/usr/bin/env bash
set -euo pipefail
source /etc/incudal/pps-guard.conf

install_pps_guard() {
  local minimum_limit="${PPS_MIN_LIMIT:-20000}"
  if ! [[ "$PPS_LIMIT" =~ ^[0-9]+$ ]] || (( PPS_LIMIT < minimum_limit || PPS_LIMIT > 500000 )); then
    PPS_LIMIT="$minimum_limit"
    sed -i -E "s/^PPS_LIMIT=[0-9]+$/PPS_LIMIT=${PPS_LIMIT}/" /etc/incudal/pps-guard.conf 2>/dev/null || true
  fi
  nft delete table inet incudal_pps_guard 2>/dev/null || true
  nft -f - <<EOF
table inet incudal_pps_guard {
  set blocked_v4 {
    type ether_addr . ipv4_addr
    size 65535
    flags dynamic,timeout
    timeout ${PPS_BLOCK_SECONDS}s
  }
  set blocked_v6 {
    type ether_addr . ipv6_addr
    size 65535
    flags dynamic,timeout
    timeout ${PPS_BLOCK_SECONDS}s
  }
  set observed_v4 {
    type ether_addr . ipv4_addr
    size 65535
    flags dynamic,timeout
    timeout ${PPS_OBSERVE_SECONDS}s
  }
  set observed_v6 {
    type ether_addr . ipv6_addr
    size 65535
    flags dynamic,timeout
    timeout ${PPS_OBSERVE_SECONDS}s
  }
  chain instance_pps_limit {
    meter per_instance_pps { ether saddr limit rate over ${PPS_LIMIT}/second burst ${PPS_BURST_PACKETS} packets } counter drop
  }
  chain forward {
    type filter hook forward priority -200; policy accept;
    iifname "${BRIDGE_NAME}" ether saddr . ip daddr @blocked_v4 counter drop
    iifname "${BRIDGE_NAME}" ether saddr . ip6 daddr @blocked_v6 counter drop
    # Established TCP traffic is normal high-rate traffic and is not counted here.
    # UDP single-target spikes are observed and reported, but not persistently
    # blocked automatically; the per-instance UDP limiter remains the guardrail.
    iifname "${BRIDGE_NAME}" meta l4proto udp meter per_target_udp_v4 { ether saddr . ip daddr limit rate over ${PPS_SINGLE_TARGET_LIMIT}/second burst ${PPS_SINGLE_TARGET_BURST} packets } update @observed_v4 { ether saddr . ip daddr timeout ${PPS_OBSERVE_SECONDS}s } counter
    iifname "${BRIDGE_NAME}" meta l4proto tcp tcp flags & (syn | ack) == syn meter per_target_syn_v4 { ether saddr . ip daddr limit rate over ${PPS_SINGLE_TARGET_LIMIT}/second burst ${PPS_SINGLE_TARGET_BURST} packets } update @blocked_v4 { ether saddr . ip daddr timeout ${PPS_BLOCK_SECONDS}s } log prefix "INCUDAL_PPS_V4 " counter drop
    iifname "${BRIDGE_NAME}" meta l4proto udp meter per_target_udp_v6 { ether saddr . ip6 daddr limit rate over ${PPS_SINGLE_TARGET_LIMIT}/second burst ${PPS_SINGLE_TARGET_BURST} packets } update @observed_v6 { ether saddr . ip6 daddr timeout ${PPS_OBSERVE_SECONDS}s } counter
    iifname "${BRIDGE_NAME}" meta l4proto tcp tcp flags & (syn | ack) == syn meter per_target_syn_v6 { ether saddr . ip6 daddr limit rate over ${PPS_SINGLE_TARGET_LIMIT}/second burst ${PPS_SINGLE_TARGET_BURST} packets } update @blocked_v6 { ether saddr . ip6 daddr timeout ${PPS_BLOCK_SECONDS}s } log prefix "INCUDAL_PPS_V6 " counter drop
    # Keep one combined per-instance budget for UDP and TCP SYN, while
    # established TCP data packets bypass this limiter.
    iifname "${BRIDGE_NAME}" meta l4proto udp jump instance_pps_limit
    iifname "${BRIDGE_NAME}" meta l4proto tcp tcp flags & (syn | ack) == syn jump instance_pps_limit
  }
}
EOF
}

manage_pps_guard() {
    echo ""
    divider
    echo -e "  ${BOLD}每实例 PPS 防护${NC}"
    divider
    if nft list table inet incudal_pps_guard >/dev/null 2>&1; then
        echo -e "  当前状态  :  ${GREEN}运行中${NC}"
        if [[ -f /etc/incudal/pps-guard.conf ]]; then
            local saved_limit=""
            saved_limit=$(sed -nE 's/^PPS_LIMIT=([0-9]+)$/\1/p' /etc/incudal/pps-guard.conf | head -n1 || true)
            [[ -n "$saved_limit" ]] && PPS_LIMIT="$saved_limit"
        fi
        echo -e "  当前阈值  :  ${GREEN}${PPS_LIMIT} 包/秒${NC}"
    else
        echo -e "  当前状态  :  ${YELLOW}未启用${NC}"
    fi
    echo ""
    echo -e "    ${CYAN}1)${NC} 启用 / 更新防护"
    echo -e "    ${RED}2)${NC} 关闭防护"
    echo -e "    ${CYAN}0)${NC} 返回"
    echo ""
    echo -ne "  ${BOLD}请选择 [0-2]: ${NC}"
    local choice=""
    read -r choice
    case "$choice" in
        1)
            echo -ne "  ${BOLD}每实例 PPS 上限 [默认 ${PPS_LIMIT}]: ${NC}"
            local requested=""
            read -r requested
            if [[ -n "$requested" ]]; then
                if [[ "$requested" =~ ^[0-9]+$ ]] && (( requested >= PPS_MIN_LIMIT && requested <= 500000 )); then
                    PPS_LIMIT="$requested"
                else
                    warn "无效阈值，继续使用 ${PPS_LIMIT}"
                fi
            fi
            PPS_PROTECTION_ENABLED="true"
            if [[ -f /etc/incudal/pps-guard.conf ]]; then
                sed -i -E "s/^PPS_LIMIT=[0-9]+$/PPS_LIMIT=${PPS_LIMIT}/" /etc/incudal/pps-guard.conf
            fi
            install_pps_guard
            ;;
        2)
            disable_pps_guard
            ;;
        0) return 0 ;;
        *) warn "无效选项" ;;
    esac
    pause_return
}
GUARD
    chmod 0755 /usr/local/sbin/incudal-pps-guard

    if command -v systemctl &>/dev/null; then
        cat > /etc/systemd/system/incudal-pps-guard.service <<'EOF'
[Unit]
Description=Incudal per-instance PPS protection
After=network-online.target incus.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/incudal-pps-guard
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        if ! systemctl enable --now incudal-pps-guard.service; then
            error "PPS 防护服务启动失败，最近日志如下："
            systemctl status --no-pager --full incudal-pps-guard.service 2>&1 || true
            journalctl -u incudal-pps-guard.service -n 40 --no-pager 2>&1 || true
            return 1
        fi
    elif command -v rc-service &>/dev/null; then
        cat > /etc/init.d/incudal-pps-guard <<'EOF'
#!/sbin/openrc-run
description="Incudal per-instance PPS protection"
command="/usr/local/sbin/incudal-pps-guard"
command_background="no"
depend() {
    need net
    after incus
}
EOF
        chmod 0755 /etc/init.d/incudal-pps-guard
        rc-update add incudal-pps-guard default >/dev/null 2>&1 || true
        rc-service incudal-pps-guard restart
    else
        /usr/local/sbin/incudal-pps-guard
    fi

    if nft list table inet incudal_pps_guard >/dev/null 2>&1; then
        log "每实例 PPS 防护已启用：${PPS_LIMIT} 包/秒，突发 ${PPS_BURST_PACKETS} 包"
        log "TCP SYN 单一目的 IP 超过 ${PPS_SINGLE_TARGET_LIMIT} 包/秒时，将对该实例封锁目标 ${PPS_BLOCK_SECONDS} 秒；UDP 仅观察告警"
    else
        error "PPS 防护规则未能加载"
        return 1
    fi
}
