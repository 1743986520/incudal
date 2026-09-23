# ========================== 主流程入口 ==========================
main() {
    # 显示横幅
    show_banner

    # Root 权限检查
    if [[ "$EUID" -ne 0 ]]; then
        error "请以 root 权限运行此脚本"
        echo -e "  ${DIM}用法: sudo bash $0${NC}"
        exit 1
    fi

    # 检测系统环境
    detect_system

    # ---- 解析命令行参数（兼容非交互模式）----
    local ACTION="install"   # 默认动作为安装
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --mode)
                MODE="$2"; shift 2 ;;
            --token)
                TOKEN="$2"; shift 2 ;;
            --ipv6-subnet)
                IPV6_SUBNET="$2"; shift 2 ;;
            --ipv6-iface)
                IPV6_IFACE="$2"; shift 2 ;;
            --port|-p)
                LISTEN_PORT="$2"; shift 2 ;;
            --pps-limit)
                PPS_LIMIT="$2"; PPS_PROTECTION_ENABLED="true"; PPS_OPTION_EXPLICIT="true"; shift 2 ;;
            --disable-pps-protection)
                PPS_PROTECTION_ENABLED="false"; PPS_OPTION_EXPLICIT="true"; shift ;;
            --storage-driver|--storage)
                [[ $# -ge 2 ]] || { error "$1 缺少参数"; exit 1; }
                STORAGE_DRIVER="$2"; shift 2 ;;
            --storage-pool|--storage-pool-name)
                [[ $# -ge 2 ]] || { error "$1 缺少参数"; exit 1; }
                STORAGE_POOL_NAME="$2"; shift 2 ;;
            --storage-source)
                [[ $# -ge 2 ]] || { error "$1 缺少参数"; exit 1; }
                STORAGE_SOURCE="$2"; shift 2 ;;
            --storage-size)
                [[ $# -ge 2 ]] || { error "$1 缺少参数"; exit 1; }
                STORAGE_SIZE="$2"; shift 2 ;;
            --uninstall)
                ACTION="uninstall"; shift ;;
            --agent|--agent-menu)
                ACTION="agent"; shift ;;
            --help|-h)
                echo "用法: $0 [选项]"
                echo ""
                echo "选项:"
                echo "  --mode <nat|nat_ipv6>   网络模式（不指定则交互选择）"
                echo "  --token <TOKEN>         面板认证 Token"
                echo "  --ipv6-subnet <CIDR>    IPv6 子网段（例如 2001:db8::/64）"
                echo "  --ipv6-iface <IFACE>    IPv6 路由父网卡（例如 eth0）"
                echo "  --port <PORT>           自定义 Incus 运行端口 (默认 8443)"
                echo "  --pps-limit <PPS>       每实例 PPS 上限（默认 20000，范围 20000-500000）"
                echo "  --disable-pps-protection 关闭每实例 PPS 防护（不建议）"
                echo "  --storage-driver <dir|btrfs|zfs|lvm|none> 存储池类型"
                echo "  --storage-pool <NAME>   存储池名称（默认 default）"
                echo "  --storage-source <PATH> 物理盘、VG 或目录路径"
                echo "  --storage-size <SIZE>   Loop 存储大小（默认 60GiB）"
                echo "  --uninstall             卸载 Incus 节点并还原系统"
                echo "  --agent                 打开 Agent 安装 / 更新菜单"
                echo "  --help, -h              显示帮助信息"
                echo ""
                echo "交互模式: sudo bash $0"
                echo "命令行:   sudo bash $0 --mode nat --token <YOUR_TOKEN> --port 10001"
                echo "卸载:     sudo bash $0 --uninstall"
                exit 0
                ;;
            *)
                error "未知参数: $1"
                echo -e "  ${DIM}使用 --help 查看帮助${NC}"
                exit 1
                ;;
        esac
    done

    # 如果通过命令行指定了卸载，直接执行
    if [[ "$ACTION" == "uninstall" ]]; then
        do_uninstall
        exit 0
    fi
    if [[ "$ACTION" == "agent" ]]; then
        manage_incudal_agent
        exit 0
    fi

    # ---- 交互式流程 ----

    # 如果 stdin 不是终端且缺少参数，给出提示
    if [[ ! -t 0 ]]; then
        if [[ -z "$MODE" || -z "$TOKEN" ]]; then
            error "通过管道执行时，必须提供 --mode 和 --token 参数"
            echo -e "  ${DIM}示例: curl -sL <URL> | sudo bash -s -- --mode nat --token <TOKEN>${NC}"
            exit 1
        fi
    fi

    # 合并注入变量与 CLI 参数
    TOKEN="${INJECT_TOKEN:-${TOKEN:-}}"
    MODE="${INJECT_MODE:-${MODE:-}}"
    IPV6_SUBNET="${INJECT_IPV6_SUBNET:-${IPV6_SUBNET:-}}"
    IPV6_IFACE="${INJECT_IPV6_IFACE:-${IPV6_IFACE:-}}"

    # 模式选择（未通过 CLI 或面板注入指定时进入菜单）
    if [[ -z "$MODE" ]]; then
        show_system_info

        while true; do
            show_menu
            read -r choice
            echo ""

            case "$choice" in
                1)  MODE="nat";      break ;;
                2)
                    MODE="nat_ipv6"
                    echo -e "\n${CYAN}正在检测宿主机 IPv6 网络配置...${NC}"

                    local detect_iface=""
                    local detect_ip=""
                    detect_iface=$(ip -6 route show default 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1 || true)
                    if [[ -z "$detect_iface" ]]; then
                        detect_iface=$(ip route show default 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1 || true)
                    fi

                    if [[ -n "$detect_iface" ]]; then
                        detect_ip=$(ip -6 addr show dev "$detect_iface" scope global 2>/dev/null | awk '/inet6/ {print $2}' | grep -vEi "^(fd|fe80)" | head -n1 || true)
                    fi

                    echo ""
                    echo -e "  ${CYAN}==> IPv6 实例附加子网配置${NC}"
                    if [[ -n "$detect_ip" ]]; then
                        echo -e "  检测到当前服务器分配的 IPv6 全段为: ${GREEN}${detect_ip}${NC}，网卡: ${GREEN}${detect_iface}${NC}。"
                    else
                        echo -e "  ${YELLOW}未检测到公网 IPv6 地址${NC}"
                    fi
                    echo -e "  ${DIM}若要开启真实 IPv6 入站/出站路由分配，请直接回车采用默认值即可，或手动输入。${NC}"
                    echo -e "  ${DIM}格式须带有网络前缀长度（例如 2a01:4f9.../64），若不需要额外分发 IPv6 请留空跳过。${NC}"
                    echo -ne "  ${BOLD}请输入分配给虚拟机的 IPv6 子网 [回车默认: ${detect_ip:-留空}]: ${NC}"
                    read -r IPV6_SUBNET
                    if [[ -z "$IPV6_SUBNET" ]]; then
                        IPV6_SUBNET="$detect_ip"
                    fi

                    if [[ -n "$IPV6_SUBNET" ]]; then
                        echo -ne "  ${BOLD}请输入此 IPv6 使用的物理网卡名 [回车默认: ${detect_iface:-无}]: ${NC}"
                        read -r IPV6_IFACE
                        if [[ -z "$IPV6_IFACE" ]]; then
                            IPV6_IFACE="$detect_iface"
                        fi
                    fi
                    break
                    ;;
                3)  install_rfw; continue ;;
                4)  show_system_info; continue ;;
                5)  uninstall_rfw; continue ;;
                6)  do_uninstall; exit 0 ;;
                7)  show_network_mode_help; continue ;;
                8)  manage_incudal_agent; continue ;;
                9)  manage_pps_guard; continue ;;
                0)  info "再见！"; exit 0 ;;
                *)  warn "无效选项，请重新选择"; continue ;;
            esac
        done
    fi

    # 模式参数合法性验证
    if [[ "$MODE" != "nat" && "$MODE" != "nat_ipv6" ]]; then
        error "--mode 必须为 'nat' 或 'nat_ipv6'"
        exit 1
    fi

    # Token 输入（未通过 CLI 指定或面板注入时交互输入）
    if [[ -z "$TOKEN" ]]; then
        read_token
    else
        local token_masked="${TOKEN:0:8}…${TOKEN: -4}"
        info "Token 已自动配置: ${token_masked}"
    fi

    # 端口修改逻辑
    if [[ -z "${LISTEN_PORT:-}" ]]; then
        echo -e "\n${CYAN}==> (可选) 自定义通信端口${NC}"
        echo -e "  ${DIM}默认 8443，若被防火墙屏蔽可改为 10000+ 端口${NC}"
        echo -ne "  ${BOLD}通信端口 [默认 8443]: ${NC}"
        read -r USER_PORT
        if [[ -n "$USER_PORT" && "$USER_PORT" =~ ^[0-9]+$ ]]; then
            LISTEN_PORT="$USER_PORT"
        else
            LISTEN_PORT="8443"
        fi
    fi

    configure_agent_heartbeat_interval

    # 每实例 PPS 防护默认开启；交互安装允许调整，面板/管道安装直接采用安全默认值。
    if [[ -t 0 && -z "${INJECT_PPS_LIMIT:-}" && "$PPS_OPTION_EXPLICIT" != "true" ]]; then
        echo -e "\n${CYAN}==> 每实例 PPS 发包保护${NC}"
        echo -e "  ${DIM}默认开启并限制每台实例 20000 包/秒；最低阈值为 20000，避免过低配置误伤正常流量${NC}"
        echo -ne "  ${BOLD}启用 PPS 防护？[Y/n]: ${NC}"
        read -r PPS_CHOICE
        if [[ "${PPS_CHOICE:-Y}" =~ ^[nN]$ ]]; then
            PPS_PROTECTION_ENABLED="false"
        else
            echo -ne "  ${BOLD}每实例 PPS 上限 [默认 ${PPS_LIMIT}，范围 ${PPS_MIN_LIMIT}-500000]: ${NC}"
            read -r USER_PPS_LIMIT
            if [[ -n "${USER_PPS_LIMIT:-}" ]]; then
                if [[ "$USER_PPS_LIMIT" =~ ^[0-9]+$ ]] && (( USER_PPS_LIMIT >= PPS_MIN_LIMIT && USER_PPS_LIMIT <= 500000 )); then
                    PPS_LIMIT="$USER_PPS_LIMIT"
                else
                    warn "PPS 阈值无效，继续使用 ${PPS_LIMIT}"
                fi
            fi
        fi
    fi

    # WARP 询问逻辑（纯 IPv6 专供）
    if [[ "$IS_PURE_IPV6" == "true" ]]; then
        if [[ -t 0 ]]; then
            echo -e "\n${CYAN}==> 检测到系统为【纯 IPv6 出站】环境${NC}"
            echo -e "  基于预设，脚本将默认请求 Cloudflare WARP 提供 IPv4 虚拟接驳支持。"
            echo -e "  若您的业务需求须使用纯净原生 IPv6，可选择跳过。"
            echo -ne "  ${BOLD}是否为目前宿主机接驳安装 WARP IPv4 出站通道？[Y/n]: ${NC}"
            read -r WARP_CHOICE
            if [[ "${WARP_CHOICE:-Y}" =~ ^[nN]$ ]]; then
                SKIP_WARP="true"
            else
                SKIP_WARP="false"
            fi
        else
            SKIP_WARP="false"
        fi
    else
        SKIP_WARP="false"
    fi

    # 存储池选择必须发生在依赖安装和 Incus preseed 之前。
    if ! prompt_storage_pool; then
        error "存储池配置失败"
        exit 1
    fi
    if ! validate_storage_selection; then
        error "存储池参数无效"
        exit 1
    fi

    select_bridge_subnet

    # 安装前确认
    confirm_install

    # ---- 执行安装 ----
    echo ""
    divider
    echo -e "  ${BOLD}开始安装...${NC}"
    divider

    if [[ "$IS_PURE_IPV6" == "true" ]]; then
        setup_temp_network  # 接入临时出海通道
        if [[ "${SKIP_WARP:-false}" != "true" ]]; then
            setup_warp_v4     # 搭建底层双规双栈通道
        else
            info "用户已选择跳过 WARP 安装，保留原生纯 IPv6 环境出站"
        fi
    fi

    setup_kernel      # 1/5 内核参数

    # 2/5 系统依赖（用户可能拒绝 DKMS 编译并返回主菜单）
    if ! install_deps; then
        warn "安装已中断，返回主菜单..."
        echo ""
        exec "$0"  # 重新启动脚本回到主菜单
        exit 0
    fi

    install_incus     # 3/5 安装 Incus
    init_incus        # 4/5 初始化 Incus
    import_cert       # 5/5 导入证书
    report_server_certificate # 一次性通道回传并固定 Incus 服务端证书
    install_pps_guard # 默认启用：按实例限制异常 PPS

    # 仅当启用了 IPv6 相关功能时，挂载 IPv6 双栈同步守护神
    if [[ "$MODE" == "nat_ipv6" ]]; then
        setup_v6_guardian
    fi

    install_incudal_agent

    show_result
}

main "$@"
