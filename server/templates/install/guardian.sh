# -----------------------------------------------------------------------------
# IPv6 Guardian Daemon (双栈端口同步补丁)
# -----------------------------------------------------------------------------
setup_v6_guardian() {
    log "正在部署 IPv6 双栈端口同步守护进程 (Guardian Daemon)..."

    local guardian_script="/usr/local/bin/incus-v6-guardian.sh"
    local guardian_service="/etc/systemd/system/incus-v6-guardian.service"
    [[ "$OS_ID" == "alpine" ]] && guardian_service="/etc/init.d/incus-v6-guardian"

    cat > "$guardian_script" << 'EOF'
#!/bin/bash
# Incudal - IPv6 Dual-Stack Guardian Daemon
# 每 15 秒轮询，将新建的单栈 IPv4 端口映射同步生成一份 IPv6 双栈跨协议互通映射。
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

while true; do
  # 防止云服务商 NetworkManager 因网络波动重置内核参数，导致 proxy_ndp 失效
  if [[ -f /etc/sysctl.d/99-incus.conf ]]; then
      sysctl -p /etc/sysctl.d/99-incus.conf >/dev/null 2>&1 || true
  fi

  for c in $(incus list -c n,s --format=csv 2>/dev/null | awk -F, '$2=="RUNNING" {print $1}'); do
    devices=$(incus config device show "$c" 2>/dev/null) || continue

    ip_v4=$(incus list "$c" -c 4 --format=csv 2>/dev/null | grep -E -o '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || echo "127.0.0.1")

    # TCP 新增同步
    v4_tcp_proxies=$(echo "$devices" | awk -F: '/^proxy-tcp-[0-9]+/ {print $1}' | tr -d ' ')
    for proxy in $v4_tcp_proxies; do
      port=$(echo "$proxy" | awk -F'-' '{print $3}')
      if ! echo "$devices" | grep -q "^proxy-v6-tcp-${port}:$"; then
         original_connect=$(incus config device get "$c" "$proxy" connect 2>/dev/null)
         target_port=$(echo "$original_connect" | awk -F: '{print $NF}')
         [[ -z "$target_port" ]] && target_port="$port"
         incus config device add "$c" proxy-v6-tcp-${port} proxy listen=tcp:[::]:${port} connect=tcp:${ip_v4}:${target_port} >/dev/null 2>&1
      fi
    done

    # UDP 新增同步
    v4_udp_proxies=$(echo "$devices" | awk -F: '/^proxy-udp-[0-9]+/ {print $1}' | tr -d ' ')
    for proxy in $v4_udp_proxies; do
      port=$(echo "$proxy" | awk -F'-' '{print $3}')
      if ! echo "$devices" | grep -q "^proxy-v6-udp-${port}:$"; then
         original_connect=$(incus config device get "$c" "$proxy" connect 2>/dev/null)
         target_port=$(echo "$original_connect" | awk -F: '{print $NF}')
         [[ -z "$target_port" ]] && target_port="$port"
         incus config device add "$c" proxy-v6-udp-${port} proxy listen=udp:[::]:${port} connect=udp:${ip_v4}:${target_port} >/dev/null 2>&1
      fi
    done

    # TCP 孤儿清理
    v6_tcp_proxies=$(echo "$devices" | awk -F: '/^proxy-v6-tcp-[0-9]+/ {print $1}' | tr -d ' ')
    for proxy in $v6_tcp_proxies; do
      port=$(echo "$proxy" | awk -F'-' '{print $4}')
      if ! echo "$devices" | grep -q "^proxy-tcp-${port}:$"; then
         incus config device remove "$c" proxy-v6-tcp-${port} >/dev/null 2>&1
      fi
    done

    # UDP 孤儿清理
    v6_udp_proxies=$(echo "$devices" | awk -F: '/^proxy-v6-udp-[0-9]+/ {print $1}' | tr -d ' ')
    for proxy in $v6_udp_proxies; do
      port=$(echo "$proxy" | awk -F'-' '{print $4}')
      if ! echo "$devices" | grep -q "^proxy-udp-${port}:$"; then
         incus config device remove "$c" proxy-v6-udp-${port} >/dev/null 2>&1
      fi
    done
  done
  sleep 15
done
EOF

    chmod +x "$guardian_script"

    if [[ "$OS_ID" == "alpine" ]]; then
        cat > "$guardian_service" << EOF
#!/sbin/openrc-run
name="Incudal IPv6 Dual-Stack Guardian"
command="$guardian_script"
command_background="yes"
pidfile="/run/incus-v6-guardian.pid"
output_log="/var/log/incus-v6-guardian.log"
error_log="/var/log/incus-v6-guardian.log"
supervisor="supervise-daemon"
respawn_delay=10
respawn_max=0
depend() { need net incusd; }
EOF
        chmod +x "$guardian_service"
        rc-update add incus-v6-guardian default >/dev/null 2>&1 || true
        rc-service incus-v6-guardian restart >/dev/null 2>&1 || rc-service incus-v6-guardian start >/dev/null 2>&1 || true
    else
        cat > "$guardian_service" << EOF
[Unit]
Description=Incudal IPv6 Dual-Stack Guardian Daemon
After=network.target

[Service]
Type=simple
ExecStart=$guardian_script
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload 2>/dev/null || true
        systemctl enable incus-v6-guardian 2>/dev/null || true
        systemctl restart incus-v6-guardian 2>/dev/null || true
    fi

    info "守护神服务已启动：每隔 15 秒自动打通新增容器的反向 IPv6 映射"
}

