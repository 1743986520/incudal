# Changelog

## 2026-09-01 — PPS 误封修正

- Agent 启动和自动升级后会同步 PPS Guard 规则，并将旧配置中的最低阈值迁移到 20,000 PPS，避免节点升级后继续使用旧规则。
- PPS 最低阈值统一提高到 20,000 PPS；全局保护只统计 UDP 与 TCP SYN，不再把已建立的 TCP 下载流量计入限速。
- TCP SYN 单目标超限才执行 MAC → 目的 IP 封锁；UDP 单目标超限改为观察并告警，降低 UDP 业务误封风险。
- PPS 事件只执行网络层目标封锁或观察告警，并通知管理员；不再仅凭单次 PPS 事件自动封禁用户账户，避免正常高速下载造成误封。

## 2026-08-24 — 安全、节点兼容性与面板体验更新

本次更新汇总了生产环境中发现的安全、计费、节点安装、Agent 运维和用户界面问题。目标是减少误操作和人工 SQL 处理，提升异常节点的自恢复能力，并让安全补丁可以由面板统一下发。

### 安全与防滥用

- 在节点安装脚本中默认启用每实例 PPS 防护。默认总限制为 20,000 PPS、突发 5,000 包；单一实例到单一目的 IP 的限制为 10,000 PPS、突发 2,500 包，超限组合封锁 3,600 秒。
- nftables 规则按来源 MAC 区分实例，并以 `MAC + 目的 IP` 为最小封锁范围，避免一个用户的异常流量影响同节点其他实例。
- Agent 新增安全事件采集，上报封锁类型、IP 协议族、来源 MAC、目的 IP、剩余封锁时间及判定阈值。
- 面板通过 Agent 上报的 MAC 精确对应 Incus 实例，不再依赖主机名或人工猜测。
- PPS 滥用事件会调用面板的用户封禁逻辑：封禁账户、清除认证缓存、撤销访问及刷新令牌、关闭终端会话，并保存具体封禁原因。
- 封禁后向用户发送邮件，同时向全局 Telegram 通知群发送节点、实例、用户、判定依据、处理结果和邮件状态。管理员账户受保护，不会被自动封禁，只会上报告警。
- 新增独立的用户安全封禁邮件模板，避免把安全事件错误描述为到期暂停。

涉及位置：`server/templates/install.sh`、`agent/internal/report/security.go`、`agent/internal/report/incus.go`、`server/src/routes/agent.ts`、`server/src/services/traffic-notifier.ts`、`server/src/lib/mailer.ts`。

### Agent 强制更新

- Agent 版本提升至 `v0.0.3`，实例报告增加网卡 MAC，供安全事件精确定位。
- 节点管理页增加管理员专用的“强制更新 Agent”按钮，可向所有已启用 Agent 下发最新版本。
- 更新请求写入数据库；离线节点不会丢失任务，会在恢复心跳后执行。
- Agent 下载更新时验证来源、版本和 SHA-256，替换二进制后重启服务。
- 面板记录目标版本、请求时间和强制更新状态，并在管理审计日志中记录批量操作。

涉及位置：`agent/VERSION`、`server/prisma/migrations/20260824014000_add_agent_forced_upgrade/`、`server/src/routes/agent.ts`、`client/src/views/resources/MyHostsView.vue`。

### 节点安装与系统兼容性

- 安装脚本从仅面向 Ubuntu 扩展为支持 Debian、Ubuntu、Rocky Linux 9/10 和 Alpine Linux 3.20+。
- Alpine 使用 OpenRC 管理 Incus、Agent 和 PPS 防护服务，默认采用轻量存储方案，不强制安装 ZFS。
- Rocky Linux 使用 EPEL/COPR 安装 Incus，并补齐 RPM 环境不会自动创建的路径和服务配置。
- 识别 cloud、virtual、AWS、Azure、GCP、Oracle、KVM 和 Xen 内核；无法加载 ZFS 时自动回退到 dir/btrfs，而不是令整次节点安装失败。
- Debian/Ubuntu 的 ZFS 处理增加 cloud 内核头文件匹配及预构建模块回退。
- Agent 安装器增强状态、日志、更新与重装处理，并兼容 systemd/OpenRC。
- PPS 防护提供交互式管理菜单、CLI 参数、开关、状态显示和卸载清理，且只删除 Incudal 自有 nftables 表。

涉及位置：`server/templates/install.sh`、`server/templates/agent-install.sh`。

### 实例创建、异常处理与计费安全

- 创建失败页面增加“重试”入口，使失败实例可以重新进入创建流程，不必先删除退款。
- 创建超时和异步创建失败统一使用带数据库锁的结算流程，避免多个 Worker 同时处理导致重复退款。
- 退款金额会扣除已有退款记录，只退还尚未退回的实际购买金额。
- 异常创建状态更新使用条件声明，只有仍处于 `creating` 的实例可以被当前处理器领取。
- 离线节点上的方案禁止继续购买，减少付款后才发现无法创建的情况。

涉及位置：`server/src/db/billing-operations.ts`、`server/src/services/schedulers.ts`、`server/src/routes/instances/create-async.ts`、`server/src/routes/packages.ts`、`client/src/views/InstancesView.vue`、`client/src/views/InstanceDetailView.vue`。

### 批量端口映射

- 添加端口窗口增加“单个端口／批量端口”切换。
- 批量模式明确提供外部起始、外部结束、内部起始和内部结束四个字段，并按顺序一一对应映射。
- 前后端均验证两段端口数量相同、范围为 1–65535、起始不大于结束、外部端口位于节点允许范围内，且一次最多创建 100 个连续端口。
- 同时检查 TCP/UDP 冲突和端口配额；创建中途失败会回滚已经添加的 Incus 设备和数据库记录。
- 冲突重试提交也必须与原始内部端口集合一致，不能利用重试参数绕过范围验证。

涉及位置：`client/src/components/instance/modals/AddPortModal.vue`、`client/src/views/InstanceDetailView.vue`、`server/src/routes/instances.ts`。

### 人工充值与账单管理

- 新增人工充值渠道，用户可以填写付款说明并提交待审核记录，操作方式与工单流程相近。
- 前后端验证人工付款说明长度与必填状态，管理账单页面显示人工备注和付款信息。
- 充值渠道类型白名单加入 `manual`，并保留易支付、Heleket 和充值卡渠道。

涉及位置：`server/src/routes/recharge.ts`、`server/src/routes/admin-billing.ts`、`client/src/views/WalletView.vue`、`client/src/views/admin/BillingView.vue`。

### 登录、真实访客 IP 与会话稳定性

- 用户名登录保持大小写敏感，避免大小写不同的账户被错误合并或认证到其他用户。
- 新增统一客户端 IP 解析，按受信任代理链读取 Cloudflare/CDN 转发地址，不再把 CDN 边缘 IP 当作访客 IP。
- 调整 Cookie 与认证处理，降低用户偶发被登出的情况。

涉及位置：`server/src/lib/client-ip.ts`、`server/src/app.ts`、`server/src/routes/auth.ts`、`server/src/lib/security.ts`、`server/src/lib/cookie-config.ts`。

### 节点健康监控

- 新增节点健康监控服务，以连续失败和连续成功次数切换上下线状态，避免一次网络抖动立即改变节点状态。
- 状态变化接入现有调度与通知体系，供方案购买限制和管理端判断使用。

涉及位置：`server/src/services/host-health-monitor.ts`、`server/src/services/schedulers.ts`、`server/src/app.ts`。

### Agent 定时审查与按需网络策略

- 原有手动实例审查继续保留；手动扫描同时触发 Incus 即时扫描与 Agent 强制采集，减少单一路径不可用时的盲区。
- 可在维护面板按节点启用 Agent 定时审查，并配置 60–86400 秒周期及每批 1–32 个实例。默认关闭，不产生额外扫描负载。
- Agent 分批采集进程、网络连接、监听端口和启动项原始数据；面板统一套用内置规则、自定义规则、节点覆盖规则和白名单，并写入原有审查历史。
- 新增按需 IP/CIDR 封锁、强制平台 DNS、域名返回指定 IP、NXDOMAIN 和零地址策略。
- 策略可应用于单一、多选、当前全部或当前及今后全部实例；按实例 MAC 在宿主机强制执行，不修改客户系统。
- DNS 策略要求操作者自行配置上游 DNS；可选同时阻挡 DoT TCP 853。DoH HTTPS 不默认阻挡。
- 所有策略默认关闭，启用后才下发 Agent；停用或删除后 Agent 在下一次心跳撤销。面板展示 pending、applied、failed、disabled 状态及错误原因。
- nftables 使用独立 `incudal_managed_policy` 表并以事务方式替换，避免破坏现有 NAT、端口转发和 PPS 防护规则。

涉及位置：`agent/internal/audit/`、`agent/internal/policy/`、`server/src/services/host-network-policy.ts`、`server/src/routes/agent.ts`、`server/src/routes/hosts.ts`、`client/src/components/host/HostOpsTab.vue`。

### 公共页面与方案展示

- 优化未登录落地页、公共导航、概览和方案预览，使其跟随原有主题和图标体系。
- 商品描述限制为两行，超出内容使用省略号，避免卡片被长文本拉高。
- 方案流量不再错误显示“无限”；同一节点存在多个计划时，展示最低到最高流量范围。
- 调整方案卡片、选中状态、明暗主题、移动端布局和页面路由。
- 地区名称统一显示“台湾”。

涉及位置：`client/src/components/public/`、`client/src/views/LandingView.vue`、`client/src/views/MarketView.vue`、`client/src/views/PortalView.vue`、`client/src/utils/publicCatalog.ts`、三套语言文件。

### Telegram Bot

- 增加独立 Bot 项目文件，用于群组管理和验证流程；运行时密钥保存在被 Git 忽略的 `.env` 中，不提交到仓库。
- 面板的安全事件通知使用全局通知 Bot，而不是邀请码 Bot。

涉及位置：`invite-bot/`、`server/src/services/traffic-notifier.ts`、`server/src/db/notifications.ts`。

### 数据库与部署

部署本版本时需要：

1. 在 `server/` 目录执行 `npx prisma migrate deploy`。
2. 执行 `npx prisma generate`。
3. 重新构建并重启服务端。
4. 重新构建前端。
5. 将节点 Agent 更新到 `v0.0.3`；旧 Agent 不会上报实例 MAC，因此无法使用精确的自动封禁链路。

生产环境中已完成 Prisma 迁移、Agent Go 测试、服务端 TypeScript 编译、前端 Vue/Vite 构建与 API 健康检查。

### 安全说明

- 仓库不包含面板 `.env`、Bot `.env`、SMTP 密钥、Telegram Token、数据库连接串、宿主机密码或 GitHub 部署私钥。
- 自动封禁依赖 Agent 上报的来源 MAC 与同一节点的 Incus 实例报告；无法对应时只执行网络层目标封锁并通知管理员，不猜测实例。
- 当前保护重点为 PPS 与单一目的 IP 异常发包；并发连接数限制尚未启用，避免未经实测的阈值误伤正常长连接业务。
