# ========================== 安装结果 ==========================
show_result() {
    local mode_label=""
    case "$MODE" in
        nat)      mode_label="NAT（仅 IPv4）" ;;
        nat_ipv6) mode_label="NAT + IPv6" ;;
    esac

    # 安装 incudal 快捷命令
    local script_path=""
    script_path=$(readlink -f "$0" 2>/dev/null || echo "$0")

    # 管道执行（curl | bash）时，$0 指向 bash 本身，不能直接复制
    if [[ -f "$script_path" && ! "$script_path" =~ (bash|sh)$ ]]; then
        # 正常文件执行：直接复制脚本
        cp -f "$script_path" /usr/local/bin/incudal 2>/dev/null || true
        chmod +x /usr/local/bin/incudal 2>/dev/null || true
    elif [[ -f /root/incudal.sh ]]; then
        # 回退方案 1：检查常见的下载位置
        cp -f /root/incudal.sh /usr/local/bin/incudal 2>/dev/null || true
        chmod +x /usr/local/bin/incudal 2>/dev/null || true
    else
        # 回退方案 2：创建自下载包装器，运行时从默认 GitHub 仓库拉取最新脚本
        cat > /usr/local/bin/incudal <<'SHORTCUT'
#!/bin/bash
# Incudal 节点管理快捷入口 - 自动下载最新版本
SCRIPT_CACHE="/root/incudal.sh"
PANEL_URL="${INCUDAL_PANEL_URL:-}"
if [[ -z "$PANEL_URL" && -t 0 ]]; then
    read -r -p "请输入面板 HTTPS 地址: " PANEL_URL
fi
SCRIPT_URL="${PANEL_URL%/}/api/hosts/install.sh"
if [[ -z "$PANEL_URL" ]]; then
    echo "未设置面板地址，无法获取安装引导脚本。"
    exit 1
fi
echo "正在获取最新的节点管理脚本..."
if curl -sSfL "$SCRIPT_URL" -o "$SCRIPT_CACHE" 2>/dev/null; then
    chmod +x "$SCRIPT_CACHE"
    exec bash "$SCRIPT_CACHE" "$@"
else
    echo "下载失败。如果本机是纯 IPv6 环境，请确保 WARP 已开启后重试。"
    echo "或手动从面板获取安装脚本保存到 /root/incudal.sh"
    exit 1
fi
SHORTCUT
        chmod +x /usr/local/bin/incudal 2>/dev/null || true
    fi

    echo ""
    echo -e "${GREEN}  ╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}  ║                                                  ║${NC}"
    echo -e "${GREEN}  ║           ✓  安装完成                            ║${NC}"
    echo -e "${GREEN}  ║                                                  ║${NC}"
    echo -e "${GREEN}  ╚══════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  网桥名称  :  ${GREEN}${BRIDGE_NAME}${NC}"
    echo -e "  网桥子网  :  ${GREEN}${BRIDGE_SUBNET}${NC}"
    echo -e "  API 监听  :  ${GREEN}[::]:${LISTEN_PORT}${NC}"
    echo -e "  网络模式  :  ${GREEN}${mode_label}${NC}"
    if [[ "${STORAGE_DRIVER:-none}" == "none" ]]; then
        echo -e "  存储池    :  ${YELLOW}未创建（可在面板“存储”页配置）${NC}"
    else
        echo -e "  存储池    :  ${GREEN}${STORAGE_POOL_NAME} (${STORAGE_DRIVER})${NC}"
    fi
    echo -e "  Agent     :  ${GREEN}${AGENT_INSTALL_STATUS}${NC}"
    if [[ "$PPS_PROTECTION_ENABLED" == "true" ]]; then
        echo -e "  PPS 防护  :  ${GREEN}已启用（每实例 ${PPS_LIMIT} 包/秒）${NC}"
    else
        echo -e "  PPS 防护  :  ${YELLOW}未启用${NC}"
    fi
    echo -e "  快捷命令  :  ${GREEN}incudal${NC}"
    echo ""
    divider
    echo -e "  ${BOLD}下一步：${NC}请返回 Incudal 面板，点击「验证并连接」按钮完成注册"
    echo -e "  ${DIM}随时输入 incudal 可重新进入此管理脚本${NC}"
    divider
    echo ""
}

# ========================== RFW 防火墙 ==========================

# RFW 下载地址。默认固定到已发布版本，避免安装时静默执行未来的 latest
# 资产；需要升级时显式设置 INCUDAL_RFW_RELEASE_TAG 并同步检查发布物。
readonly RFW_RELEASE_TAG="${INCUDAL_RFW_RELEASE_TAG:-v0.1.9}"
if [[ ! "$RFW_RELEASE_TAG" =~ ^[A-Za-z0-9._-]+$ ]]; then
    error "无效的 RFW_RELEASE_TAG"
    exit 1
fi
readonly RFW_RELEASE_URL="https://github.com/0xdabiaoge/incudal-rfw/releases/download/${RFW_RELEASE_TAG}"
readonly RFW_INSTALL_DIR="/root/rfw"
readonly RFW_SERVICE_FILE="/etc/systemd/system/rfw.service"

# RFW 交互式配置规则
configure_rfw_rules() {
    RFW_ARGS=""
    RFW_SUMMARY_RULES=""
    RFW_SUMMARY_GEO=""
    RFW_SUMMARY_LOG="关闭"

    echo ""
    divider
    echo -e "  ${BOLD}配置 RFW 屏蔽规则${NC}"
    divider
    echo ""

    # 1. 协议屏蔽多选
    echo -e "  ┌─ 协议屏蔽（可多选，输入编号用空格分隔）──────────"
    echo -e "  │"
    echo -e "  │   1) 屏蔽邮件发送       ─  SMTP 25/587/465/2525"
    echo -e "  │   2) 屏蔽 HTTP 入站     ─  明文 HTTP 协议探测"
    echo -e "  │   3) 屏蔽 SOCKS5 入站   ─  代理协议探测"
    echo -e "  │   4) 屏蔽全加密流量     ─  SS/V2Ray（严格模式）"
    echo -e "  │   5) 屏蔽 WireGuard     ─  VPN 协议探测"
    echo -e "  │   6) 屏蔽 QUIC/HTTP3    ─  QUIC 协议"
    echo -e "  │   7) 屏蔽所有入站       ─  最激进模式"
    echo -e "  │"
    echo -e "  │   A) 全选(1-6)  D) 默认(1-5)  C) 清空"
    echo -e "  └──────────────────────────────────────────────────"
    echo ""
    echo -ne "  ${BOLD}请选择 [默认 D]: ${NC}"
    read -r rule_choice || true
    rule_choice=$(echo "${rule_choice:-D}" | tr '[:lower:]' '[:upper:]')

    local selected_rules=()
    local rule_names=()
    local block_all=false

    if [[ "$rule_choice" == "A" ]]; then
        rule_choice="1 2 3 4 5 6"
    elif [[ "$rule_choice" == "D" ]]; then
        rule_choice="1 2 3 4 5"
    elif [[ "$rule_choice" == "C" ]]; then
        rule_choice=""
    fi

    for c in $rule_choice; do
        case "$c" in
            1) selected_rules+=("--block-email"); rule_names+=("Email") ;;
            2) selected_rules+=("--block-http"); rule_names+=("HTTP") ;;
            3) selected_rules+=("--block-socks5"); rule_names+=("SOCKS5") ;;
            4) selected_rules+=("--block-fet-strict"); rule_names+=("FET-Strict") ;;
            5) selected_rules+=("--block-wireguard"); rule_names+=("WireGuard") ;;
            6) selected_rules+=("--block-quic"); rule_names+=("QUIC") ;;
            7) block_all=true ;;
        esac
    done

    if [[ "$block_all" == "true" ]]; then
        RFW_ARGS+=" --block-all"
        RFW_SUMMARY_RULES="所有入站"
    else
        if [[ ${#selected_rules[@]} -gt 0 ]]; then
            RFW_ARGS+=" ${selected_rules[*]}"
            RFW_SUMMARY_RULES=$(IFS=/ ; echo "${rule_names[*]}")
        else
            RFW_SUMMARY_RULES="无协议屏蔽"
        fi
    fi

    # 2. GeoIP 模式
    echo ""
    echo -e "  ┌─ GeoIP 过滤模式 ──────────────────────────────────"
    echo -e "  │"
    echo -e "  │   1) 黑名单模式  ─  屏蔽指定国家（推荐）"
    echo -e "  │   2) 白名单模式  ─  仅允许指定国家"
    echo -e "  │   3) 不使用 GeoIP ─  全局协议过滤"
    echo -e "  │"
    echo -e "  └──────────────────────────────────────────────────"
    echo ""
    echo -ne "  ${BOLD}请选择 [默认 1]: ${NC}"
    read -r geo_choice || true
    geo_choice=${geo_choice:-1}

    local countries=""
    if [[ "$geo_choice" == "1" || "$geo_choice" == "2" ]]; then
        echo -ne "  ${BOLD}请输入国家代码（逗号分隔）[默认 CN]: ${NC}"
        read -r countries || true
        countries=${countries:-CN}
        # 转换为大写并去除多余空格
        countries=$(echo "$countries" | tr '[:lower:]' '[:upper:]' | tr -d ' ')

        if [[ "$geo_choice" == "1" ]]; then
            # 如果选了 block_all，则使用 --block-all-from 作为快捷方式
            if [[ "$block_all" == "true" ]]; then
                RFW_ARGS=$(echo "$RFW_ARGS" | sed 's/ --block-all//')
                RFW_ARGS+=" --block-all-from $countries"
            else
                RFW_ARGS+=" --countries $countries"
            fi
            RFW_SUMMARY_GEO="黑名单 ($countries)"
        else
            RFW_ARGS+=" --allow-only-countries $countries"
            RFW_SUMMARY_GEO="白名单 ($countries)"
        fi
    else
        RFW_SUMMARY_GEO="不使用 GeoIP"
    fi

    # 3. 端口日志
    echo ""
    echo -e "  ┌─ 其他选项 ──────────────────────────────────────"
    echo -e "  │"
    echo -ne "  │   启用端口访问日志？[y/N]: ${NC}"
    read -r log_choice || true
    if [[ "${log_choice:-}" =~ ^[yY]$ ]]; then
        RFW_ARGS+=" --log-port-access"
        RFW_SUMMARY_LOG="开启"
    fi

    # 4. 配置确认
    echo ""
    echo -e "  ┌─ 配置确认 ──────────────────────────────────────"
    echo -e "  │  屏蔽规则  :  ${GREEN}${RFW_SUMMARY_RULES}${NC}"
    echo -e "  │  GeoIP     :  ${GREEN}${RFW_SUMMARY_GEO}${NC}"
    echo -e "  │  端口日志  :  ${GREEN}${RFW_SUMMARY_LOG}${NC}"
    echo -e "  │  "
    echo -e "  │  运行参数  :  ${DIM}${RFW_ARGS}${NC}"
    echo -e "  └──────────────────────────────────────────────────"
    echo ""
    echo -ne "  ${YELLOW}确认安装此配置？${NC}[Y/n]: "
    read -r confirm || true
    if [[ "${confirm:-Y}" =~ ^[nN]$ ]]; then
        info "已取消配置"
        return 1
    fi
    return 0
}

# 安装 RFW 防火墙
install_rfw() {
    if [[ "$OS_ID" == "alpine" ]]; then
        warn "Alpine 轻量母机暂不支持 RFW systemd 扩展；Incus NAT 与 nftables 不受影响"
        return 0
    fi
    echo ""
    divider
    echo -e "  ${BOLD}安装 RFW 入站流量屏蔽防火墙${NC}"
    divider
    echo ""

    # 检查是否已安装
    if [[ -f "${RFW_INSTALL_DIR}/rfw" ]] && systemctl is-active --quiet rfw 2>/dev/null; then
        local rfw_status
        rfw_status=$(systemctl is-active rfw 2>/dev/null || echo "未知")
        warn "RFW 已安装且正在运行（状态: ${rfw_status}）"
        echo -ne "  ${BOLD}是否重新安装？${NC}[y/N]: "
        read -r reinstall || true
        if [[ ! "${reinstall:-}" =~ ^[yY]$ ]]; then
            info "已取消"
            return 0
        fi
        # 先停止旧服务
        systemctl stop rfw 2>/dev/null || true
        systemctl disable rfw 2>/dev/null || true
    fi

    # 检测架构
    step "检测系统架构..."
    local arch_suffix=""
    case "$(uname -m)" in
        x86_64)
            arch_suffix="x86_64"
            ;;
        aarch64|arm64)
            arch_suffix="aarch64"
            ;;
        *)
            error "不支持的架构: $(uname -m)（仅支持 x86_64 / aarch64）"
            return 1
            ;;
    esac
    log "系统架构: $(uname -m) (${arch_suffix})"

    # 选择网络接口
    step "选择网络接口..."
    local interfaces=()
    while IFS= read -r iface; do
        [[ -z "$iface" ]] && continue
        interfaces+=("$iface")
    done < <(ip -o link show | awk -F': ' '{print $2}' | grep -v lo)

    if [[ ${#interfaces[@]} -eq 0 ]]; then
        error "未找到可用的网络接口"
        return 1
    fi

    local selected_interface=""

    if [[ ${#interfaces[@]} -eq 1 ]]; then
        # 只有一个接口，自动选择
        selected_interface="${interfaces[0]}"
        info "自动选择网卡: ${selected_interface}"
    else
        echo ""
        echo -e "  可用的网络接口："
        local i
        for i in "${!interfaces[@]}"; do
            local num=$((i + 1))
            # 获取该接口的 IP
            local iface_ip
            iface_ip=$(ip -4 addr show "${interfaces[$i]}" 2>/dev/null | awk '/inet / {print $2}' | head -n1 || echo "")
            if [[ -n "$iface_ip" ]]; then
                echo -e "    ${CYAN}${num})${NC}  ${interfaces[$i]}  ${DIM}(${iface_ip})${NC}"
            else
                echo -e "    ${CYAN}${num})${NC}  ${interfaces[$i]}"
            fi
        done
        echo ""

        while true; do
            echo -ne "  ${BOLD}请选择网卡编号 [1-${#interfaces[@]}]: ${NC}"
            read -r iface_choice || true
            if [[ "${iface_choice:-}" =~ ^[0-9]+$ ]] && \
               [[ "$iface_choice" -ge 1 ]] && \
               [[ "$iface_choice" -le "${#interfaces[@]}" ]]; then
                selected_interface="${interfaces[$((iface_choice - 1))]}"
                break
            else
                warn "无效输入，请重新选择"
            fi
        done
    fi

    log "使用网卡: ${selected_interface}"

    # 下载 RFW 二进制文件
    step "下载 RFW 程序..."
    mkdir -p "$RFW_INSTALL_DIR"

    local rfw_url="${RFW_RELEASE_URL}/rfw-${arch_suffix}-unknown-linux-musl"
    local rfw_tmp="${RFW_INSTALL_DIR}/rfw.tmp"
    local rfw_checksum_tmp="${RFW_INSTALL_DIR}/checksums.txt.tmp"
    local rfw_asset_name="rfw-${arch_suffix}-unknown-linux-musl"
    local download_ok=false
    local attempt

    for attempt in 1 2 3; do
        info "下载 RFW (第 ${attempt} 次)..."
        rm -f "$rfw_tmp" "$rfw_checksum_tmp"
        if curl -sSfL --connect-timeout 15 --max-time 120 \
            "$rfw_url" -o "$rfw_tmp" 2>/dev/null && \
           curl -sSfL --connect-timeout 15 --max-time 30 \
            "${RFW_RELEASE_URL}/checksums.txt" -o "$rfw_checksum_tmp" 2>/dev/null; then
            local expected_checksum
            expected_checksum=$(awk -v file="$rfw_asset_name" '{ gsub(/\r$/, "", $2); if ($2 == file) { print $1; exit } }' "$rfw_checksum_tmp")
            if [[ "$expected_checksum" =~ ^[A-Fa-f0-9]{64}$ ]] && \
               printf '%s  %s\n' "$expected_checksum" "$rfw_tmp" | sha256sum -c - >/dev/null 2>&1; then
                mv -f "$rfw_tmp" "${RFW_INSTALL_DIR}/rfw"
                download_ok=true
                break
            fi
            warn "RFW SHA-256 校验失败"
        else
            warn "第 ${attempt} 次下载失败"
        fi
        rm -f "$rfw_tmp" "$rfw_checksum_tmp"
        [[ "$attempt" -lt 3 ]] && sleep 3
    done

    rm -f "$rfw_tmp" "$rfw_checksum_tmp"

    if [[ "$download_ok" != "true" ]]; then
        error "RFW 下载失败（已重试 3 次）"
        error "下载地址: ${rfw_url}"
        return 1
    fi

    chmod +x "${RFW_INSTALL_DIR}/rfw"
    log "RFW 下载完成"

    # 交互式配置 RFW 规则
    if ! configure_rfw_rules; then
        return 0
    fi

    # 创建 systemd 服务
    step "配置 RFW 服务..."

    cat > "$RFW_SERVICE_FILE" <<EOF
[Unit]
Description=RFW Firewall Service
After=network.target

[Service]
Type=simple
User=root
Environment=RUST_LOG=info
ExecStart=${RFW_INSTALL_DIR}/rfw --iface ${selected_interface}${RFW_ARGS}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload

    # 启动服务
    step "启动 RFW 服务..."
    systemctl start rfw
    systemctl enable rfw 2>/dev/null || true

    # 验证
    sleep 2
    if systemctl is-active --quiet rfw 2>/dev/null; then
        echo ""
        echo -e "${GREEN}  ╔══════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}  ║                                                  ║${NC}"
        echo -e "${GREEN}  ║           ✓  RFW 防火墙安装完成                  ║${NC}"
        echo -e "${GREEN}  ║                                                  ║${NC}"
        echo -e "${GREEN}  ╚══════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  监听网卡  :  ${GREEN}${selected_interface}${NC}"
        echo -e "  服务状态  :  ${GREEN}运行中${NC}"
        echo -e "  屏蔽规则  :  ${GREEN}${RFW_SUMMARY_RULES}${NC}"
        echo -e "  GeoIP配置 :  ${GREEN}${RFW_SUMMARY_GEO}${NC}"
        echo -e "  端口日志  :  ${GREEN}${RFW_SUMMARY_LOG}${NC}"
        echo ""
        divider
        echo -e "  ${DIM}查看日志: journalctl -u rfw -f${NC}"
        echo -e "  ${DIM}查看状态: systemctl status rfw${NC}"
        if [[ "$RFW_SUMMARY_LOG" == "开启" ]]; then
            echo -e "  ${DIM}查看拦截: ${RFW_INSTALL_DIR}/rfw stats${NC}"
        fi
        divider
        echo ""
    else
        error "RFW 服务启动失败"
        error "请运行 journalctl -u rfw -n 20 查看日志"
    fi
}

# 卸载 RFW 防火墙
uninstall_rfw() {
    echo ""

    # 检查是否安装
    if [[ ! -f "${RFW_INSTALL_DIR}/rfw" ]] && \
       ! systemctl list-unit-files 2>/dev/null | grep -q "rfw.service"; then
        warn "RFW 未安装，无需卸载"
        return 0
    fi

    divider
    echo -e "  ${RED}${BOLD}卸载 RFW 防火墙${NC}"
    divider
    echo ""
    echo -e "  ${RED}将删除以下内容：${NC}"
    echo -e "    ${RED}•${NC}  RFW 二进制文件 (${RFW_INSTALL_DIR}/)"
    echo -e "    ${RED}•${NC}  RFW systemd 服务文件"
    echo ""
    echo -ne "  ${BOLD}确认卸载 RFW？${NC}[y/N]: "
    read -r rfw_confirm || true
    if [[ ! "${rfw_confirm:-}" =~ ^[yY]$ ]]; then
        info "已取消"
        return 0
    fi

    do_rfw_cleanup
}

# RFW 清理（供独立卸载和主卸载共用）
do_rfw_cleanup() {
    info "停止 RFW 服务..."
    systemctl stop rfw 2>/dev/null || true
    systemctl disable rfw 2>/dev/null || true

    # 删除服务文件
    rm -f /etc/systemd/system/rfw.service 2>/dev/null || true
    rm -f /usr/lib/systemd/system/rfw.service 2>/dev/null || true
    rm -f /lib/systemd/system/rfw.service 2>/dev/null || true

    # 删除程序目录
    rm -rf "$RFW_INSTALL_DIR" 2>/dev/null || true

    systemctl daemon-reload 2>/dev/null || true

    log "RFW 防火墙已卸载"
}
