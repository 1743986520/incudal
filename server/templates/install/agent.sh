# 步骤 5: 导入面板证书
report_server_certificate() {
    [[ -n "$PANEL_URL" && -n "$TOKEN" ]] || return 0
    local server_cert="/var/lib/incus/server.crt"
    [[ -f "$server_cert" ]] || server_cert="/var/snap/lxd/common/lxd/server.crt"
    if [[ ! -f "$server_cert" ]]; then
        error "无法找到 Incus 服务端证书，不能建立面板 TLS 信任锚"
        exit 1
    fi
    local certificate_b64
    certificate_b64=$(base64 < "$server_cert" | tr -d '\r\n')
    local storage_payload="null"
    if [[ "${STORAGE_DRIVER:-none}" != "none" ]]; then
        validate_storage_selection || {
            error "存储池参数无效，不能回传安装结果"
            exit 1
        }
        if [[ -n "${STORAGE_SOURCE:-}" ]]; then
            storage_payload=$(printf '{"name":"%s","driver":"%s","config":{"source":"%s"},"purpose":"instance_data"}' \
                "$STORAGE_POOL_NAME" "$STORAGE_DRIVER" "$STORAGE_SOURCE")
        else
            storage_payload=$(printf '{"name":"%s","driver":"%s","config":{"size":"%s"},"purpose":"instance_data"}' \
                "$STORAGE_POOL_NAME" "$STORAGE_DRIVER" "$STORAGE_SIZE")
        fi
    fi
    local bootstrap_payload
    bootstrap_payload=$(printf '{"certificate":"%s","storagePool":%s}' "$certificate_b64" "$storage_payload")
    if ! curl -sSf -X POST -H 'Content-Type: application/json' \
        --data "$bootstrap_payload" \
        "${PANEL_URL}/api/hosts/tls-bootstrap/${TOKEN}" >/dev/null; then
        error "服务端证书回传失败，安装会话不会被标记为完成"
        exit 1
    fi
    log "Incus 服务端证书已通过一次性安装通道回传"
}

import_cert() {
    step "步骤 [5/5]  导入面板信任证书..."

    # 幂等性：证书已存在则跳过
    if incus config trust list --format csv 2>/dev/null | grep -q "panel"; then
        info "面板证书已存在，跳过导入"
        return 0
    fi

    local cert_url="${PANEL_URL}/api/hosts/cert/${TOKEN}"

    if ! curl -sSf "$cert_url" \
        | incus config trust add-certificate - --name panel >/dev/null 2>&1; then
        error "证书导入失败！请检查："
        error "  1. Token 是否正确"
        error "  2. 面板 ${PANEL_URL} 是否可达"
        error "  3. 网络连接是否正常"
        exit 1
    fi

    log "面板证书导入成功"
}

# 附加步骤：安装宿主机 Agent
install_incudal_agent() {
    if [[ "$AGENT_ENABLED" != "true" ]]; then
        AGENT_INSTALL_STATUS="已跳过"
        info "宿主机 Agent 自动安装已关闭，跳过"
        return 0
    fi

    if [[ -z "$PANEL_URL" || ( -z "$AGENT_INSTALL_TOKEN" && ( -z "$AGENT_ID" || -z "$AGENT_SECRET" ) ) ]]; then
        AGENT_INSTALL_STATUS="已跳过"
        warn "未注入 Agent 安装 token 或凭据，跳过宿主机 Agent 安装"
        return 0
    fi

    step "附加步骤  安装宿主机 Agent..."

    local agent_install_url="${PANEL_URL}/api/agent/install.sh"
    if curl -fsSL "$agent_install_url" | \
        INCUDAL_PANEL_URL="$PANEL_URL" \
        INCUDAL_AGENT_INSTALL_TOKEN="$AGENT_INSTALL_TOKEN" \
        INCUDAL_AGENT_ID="$AGENT_ID" \
        INCUDAL_AGENT_SECRET="$AGENT_SECRET" \
        INCUDAL_AGENT_BINARY_URL="$AGENT_BINARY_URL" \
        INCUDAL_AGENT_BINARY_SHA256="$AGENT_BINARY_SHA256" \
        INCUDAL_HEARTBEAT_INTERVAL_SECONDS="$AGENT_HEARTBEAT_INTERVAL_SECONDS" \
        bash; then
        AGENT_INSTALL_STATUS="已安装"
        log "宿主机 Agent 安装完成"
    else
        AGENT_INSTALL_STATUS="安装失败"
        warn "宿主机 Agent 安装失败，Incus 节点初始化已完成，可稍后在面板重新生成 Agent 安装命令"
    fi

    return 0
}

# Agent 独立安装器调用
run_incudal_agent_installer() {
    local panel_url="${1%/}"
    local install_token="${2:-}"
    local agent_id="${3:-}"
    local agent_secret="${4:-}"
    local heartbeat_interval="${5:-30}"
    local binary_url="${6:-}"
    local binary_sha256="${7:-}"

    if [[ -z "$panel_url" ]]; then
        error "面板地址不能为空"
        return 1
    fi
    if ! is_https_url "$panel_url"; then
        error "面板地址格式无效: ${panel_url}"
        return 1
    fi
    if [[ -z "$install_token" && ( -z "$agent_id" || -z "$agent_secret" ) ]]; then
        error "缺少 Agent 安装 token 或本机 Agent 凭据"
        return 1
    fi

    heartbeat_interval=$(normalize_agent_interval "$heartbeat_interval")
    local agent_install_url="${panel_url}/api/agent/install.sh"

    step "安装 / 更新宿主机 Agent..."
    info "面板地址: ${panel_url}"
    if [[ -n "$install_token" ]]; then
        info "安装 token: $(mask_value "$install_token")"
    else
        info "Agent ID: $(mask_value "$agent_id")"
    fi

    if curl -fsSL "$agent_install_url" | \
        INCUDAL_PANEL_URL="$panel_url" \
        INCUDAL_AGENT_INSTALL_TOKEN="$install_token" \
        INCUDAL_AGENT_ID="$agent_id" \
        INCUDAL_AGENT_SECRET="$agent_secret" \
        INCUDAL_AGENT_BINARY_URL="$binary_url" \
        INCUDAL_AGENT_BINARY_SHA256="$binary_sha256" \
        INCUDAL_HEARTBEAT_INTERVAL_SECONDS="$heartbeat_interval" \
        bash; then
        log "宿主机 Agent 安装 / 更新完成"
        return 0
    fi

    error "宿主机 Agent 安装 / 更新失败"
    return 1
}

show_incudal_agent_status() {
    divider
    echo -e "  ${BOLD}Agent 状态${NC}"
    divider

    local panel_url=""
    local agent_id=""
    local heartbeat_interval=""
    panel_url=$(read_agent_config_value "panel_url" || true)
    agent_id=$(read_agent_config_value "agent_id" || true)
    heartbeat_interval=$(read_agent_config_value "heartbeat_interval_seconds" || true)
    heartbeat_interval=$(normalize_agent_interval "${heartbeat_interval:-30}")

    if [[ -f "$AGENT_CONFIG_FILE" ]]; then
        echo -e "  配置文件  :  ${GREEN}${AGENT_CONFIG_FILE}${NC}"
        echo -e "  面板地址  :  ${GREEN}${panel_url:-未知}${NC}"
        echo -e "  Agent ID :  ${GREEN}$(mask_value "$agent_id")${NC}"
        echo -e "  上报间隔  :  ${GREEN}${heartbeat_interval} 秒${NC}"
    else
        echo -e "  配置文件  :  ${DIM}未找到 (${AGENT_CONFIG_FILE})${NC}"
    fi

    if [[ -x "$AGENT_BIN_PATH" ]]; then
        echo -e "  二进制    :  ${GREEN}${AGENT_BIN_PATH}${NC}"
    else
        echo -e "  二进制    :  ${DIM}未安装 (${AGENT_BIN_PATH})${NC}"
    fi

    if command -v systemctl &>/dev/null; then
        if systemctl is-active --quiet "$AGENT_SERVICE_NAME" 2>/dev/null; then
            echo -e "  服务状态  :  ${GREEN}运行中${NC}"
        elif systemctl list-unit-files "${AGENT_SERVICE_NAME}.service" --no-legend 2>/dev/null | grep -q "^${AGENT_SERVICE_NAME}.service"; then
            echo -e "  服务状态  :  ${YELLOW}已安装（未运行）${NC}"
        else
            echo -e "  服务状态  :  ${DIM}未安装${NC}"
        fi
    elif command -v rc-service &>/dev/null; then
        if rc-service "$AGENT_SERVICE_NAME" status >/dev/null 2>&1; then
            echo -e "  服务状态  :  ${GREEN}运行中 (OpenRC)${NC}"
        elif [[ -x "/etc/init.d/${AGENT_SERVICE_NAME}" ]]; then
            echo -e "  服务状态  :  ${YELLOW}已安装（未运行）${NC}"
        else
            echo -e "  服务状态  :  ${DIM}未安装${NC}"
        fi
    else
        echo -e "  服务状态  :  ${DIM}服务管理器不可用${NC}"
    fi

    divider
}

prompt_agent_panel_url() {
    local default_panel_url="${1:-}"
    local panel_url=""

    if [[ -t 0 ]]; then
        if [[ -n "$default_panel_url" ]]; then
            echo -ne "  ${BOLD}面板地址 [默认 ${default_panel_url}]: ${NC}" >&2
        else
            echo -ne "  ${BOLD}面板地址 (例如 https://panel.example.com): ${NC}" >&2
        fi
        read -r panel_url
    fi

    panel_url="${panel_url:-$default_panel_url}"
    panel_url="${panel_url%/}"
    if [[ -z "$panel_url" ]]; then
        echo -e "${RED}[✗]${NC} 无法确定面板地址，请输入完整 https:// 地址" >&2
        return 1
    fi
    if ! is_https_url "$panel_url"; then
        echo -e "${RED}[✗]${NC} 面板地址格式无效: ${panel_url}" >&2
        return 1
    fi

    echo "$panel_url"
}

update_incudal_agent_from_config() {
    local panel_url=""
    local agent_id=""
    local agent_secret=""
    local heartbeat_interval=""

    panel_url=$(read_agent_config_value "panel_url" || true)
    agent_id=$(read_agent_config_value "agent_id" || true)
    agent_secret=$(read_agent_config_value "agent_secret" || true)
    heartbeat_interval=$(read_agent_config_value "heartbeat_interval_seconds" || true)
    heartbeat_interval=$(normalize_agent_interval "${heartbeat_interval:-30}")

    if [[ -z "$panel_url" || -z "$agent_id" || -z "$agent_secret" ]]; then
        warn "本机没有完整的 Agent 配置，无法直接更新"
        info "如需补装，请先在面板为该宿主机生成 Agent 安装命令，再选择 token 补装"
        return 1
    fi

    prompt_agent_heartbeat_interval "$heartbeat_interval"
    run_incudal_agent_installer "$panel_url" "" "$agent_id" "$agent_secret" "$AGENT_HEARTBEAT_INTERVAL_SECONDS" "$AGENT_BINARY_URL" "$AGENT_BINARY_SHA256"
}

install_incudal_agent_with_token() {
    echo ""
    divider
    echo -e "  ${BOLD}输入 Agent 一次性安装 token${NC}"
    echo -e "  ${DIM}可粘贴 ait_... token，也可粘贴面板生成的完整 Agent 安装命令。${NC}"
    divider
    echo ""
    echo -ne "  ${CYAN}Token / 命令: ${NC}"
    local token_input=""
    read -r token_input

    local install_token=""
    install_token=$(extract_agent_install_token "$token_input")
    if [[ -z "$install_token" ]]; then
        error "未找到 Agent 安装 token。Agent token 应以 ait_ 开头。"
        return 1
    fi

    local extracted_panel_url=""
    local default_panel_url=""
    extracted_panel_url=$(extract_agent_panel_url "$token_input" || true)
    default_panel_url="${extracted_panel_url:-$(get_agent_panel_url || true)}"

    local panel_url=""
    panel_url=$(prompt_agent_panel_url "$default_panel_url") || return 1

    local current_interval=""
    current_interval=$(read_agent_config_value "heartbeat_interval_seconds" || true)
    prompt_agent_heartbeat_interval "${current_interval:-30}"

    run_incudal_agent_installer "$panel_url" "$install_token" "" "" "$AGENT_HEARTBEAT_INTERVAL_SECONDS" "$AGENT_BINARY_URL" "$AGENT_BINARY_SHA256"
}

show_incudal_agent_logs() {
    step "查看 Agent 最近日志"
    if command -v journalctl &>/dev/null; then
        journalctl -u "$AGENT_SERVICE_NAME" --no-pager -n 80 || true
    elif [[ -f "/var/log/${AGENT_SERVICE_NAME}.log" ]]; then
        tail -n 80 "/var/log/${AGENT_SERVICE_NAME}.log" || true
    else
        error "未找到 Agent 日志"
        return 1
    fi
}

manage_incudal_agent() {
    while true; do
        show_incudal_agent_status
        echo -e "  ${BOLD}请选择 Agent 操作：${NC}"
        echo ""
        echo -e "    ${CYAN}1)${NC}  更新 / 重装已安装 Agent  ${DIM}─  使用本机配置${NC}"
        echo -e "    ${CYAN}2)${NC}  使用一次性 token 补装 / 重装 Agent"
        echo -e "    ${CYAN}3)${NC}  查看 Agent 日志"
        echo -e "    ${CYAN}0)${NC}  返回主菜单"
        echo ""
        echo -ne "  ${BOLD}请输入选项 [0-3]: ${NC}"
        local choice=""
        read -r choice
        echo ""

        case "$choice" in
            1) update_incudal_agent_from_config || true; pause_return ;;
            2) install_incudal_agent_with_token || true; pause_return ;;
            3) show_incudal_agent_logs || true; pause_return ;;
            0) return 0 ;;
            *) warn "无效选项，请重新选择" ;;
        esac
    done
}

