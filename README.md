# Incudal

Incudal 是一个基于 Incus 的容器与 KVM 虚拟机管理、销售和托管平台，包含用户面板、管理后台、节点 Agent、计费系统、NAT 端口映射、通知系统及节点安装工具。

> 本分支包含生产环境持续维护的安全、节点兼容性、计费与界面改进。完整修改原因和部署说明见 [CHANGELOG.md](./CHANGELOG.md)。

## 主要功能

- Incus 容器与 KVM 虚拟机生命周期管理
- IPv4 NAT、IPv4 NAT + IPv6、IPv4 NAT + IPv6 NAT、IPv6 Only 等网络模式
- 单端口及批量端口映射，支持 TCP、UDP、对等范围映射和冲突回滚
- 套餐、余额、续费、退款、人工充值与账单管理
- 套餐流量及按量流量计费、欠费提醒与自主还款
- 创建失败重试及防重复退款
- 数据库原子 IP 预留及 IPv4/IPv6 防碰撞
- 节点资源、流量和在线状态监控
- 节点 Agent 心跳、安全事件上报及管理员强制更新
- Telegram、邮件、站内信等通知方式
- 中英文界面、公共落地页、方案概览与预览页

## 当前版本的重要改进

### 计费与资源一致性

- 套餐流量与按量流量使用同一套结算基础设施，支持阈值结算、小时兜底、低余额提醒和欠费恢复。
- 流量重置和套餐切换不会再把未付款流量标记为已结算；切换到包量套餐时会处理遗留 pending 账单。
- 余额、退款、VIP 奖励、资源池、宿主机资源计数和 NAT port 预留均使用事务及原子增减。
- 延迟支付回调可以处理已过期清理的订单，重复回调保持幂等。

### IPAM 与实例交付

- IPv4/IPv6 会在创建 Incus 实例前完成数据库原子预留，并由唯一索引仲裁并发请求。
- 同一宿主机不能重复分配相同地址；Routed IPv6 在全部宿主机之间保持唯一。
- 创建失败重试复用有效预留；无预留的历史字段会重新分配，避免反复尝试同一个冲突 IP。
- `ipv6_only` 容器和虚拟机均会生成完整 guest 网络配置。
- 创建、升级、停止、销毁和退款操作采用状态认领与补偿路径，减少进程崩溃或 Worker 竞争留下半完成状态。

### 并发与数据库稳定性

- 热点 advisory lock 使用快速失败模式，API 返回可重试的 `409`，后台任务退避后重试，不让锁等待耗尽连接池。
- Prisma 连接池默认 `DB_POOL_MIN=0`，并可分别配置连接、空闲、statement 和 query timeout。
- 流量及实例 Worker 按宿主机限制并发，避免调度高峰同时占满 PostgreSQL 和 Incus 连接。

### 节点安全

- 新节点默认启用每实例 PPS 防护：总限制和单一目的 IP 最低阈值均为 `20,000 PPS`；全局保护只计 UDP 与 TCP SYN，避免正常 TCP 下载被误伤。
- nftables 按实例来源 MAC 和目的 IP 精确封锁，不影响同节点其他实例。
- Agent 将安全事件上报面板，面板精确关联实例和用户。
- TCP SYN 单目标超限才执行网络层目标封锁；UDP 单目标超限只记录并通知管理员，需人工确认后再执行用户封禁，避免正常高速下载或 UDP 业务造成误封。
- 无法关联实例时只执行网络层封锁和管理员告警，不猜测或误封。

### Agent 运维

- Agent `v0.0.7` 支持实例 MAC、安全事件、网络策略、任务租约及实例报告去重校验。
- 管理员可从节点列表一键强制下发 Agent 更新。
- 离线节点会保留待更新任务，恢复心跳后继续执行。
- 更新包校验来源与 SHA-256 后才会替换程序并重启。

### 节点系统兼容性

安装脚本支持 Debian、Ubuntu、Rocky Linux 9/10 和 Alpine Linux 3.20+。脚本可识别 cloud、virtual、AWS、Azure、GCP、Oracle、KVM 和 Xen 内核。ZFS 不可用时会回退到 dir/btrfs。Alpine 使用 OpenRC，并提供轻量化部署路径。

### 端口映射

添加端口时可选择“单个端口”或“批量端口”。批量模式分别填写外部起始／结束和内部起始／结束端口，两段数量必须相同并按顺序对应。前后端都会验证范围、配额、协议冲突和节点允许端口；失败时回滚已创建内容。

### 公共页面与方案预览

- 公共落地页、概览页、方案预览页统一主题与图标风格。
- 方案描述最多显示两行，超出部分使用省略号。
- 多计划方案按最低至最高流量显示，不再把有限套餐错误标记为“无限”。
- 离线节点方案禁止购买。

## 技术栈

- 前端：Vue 3、TypeScript、Vite、Pinia、Vue Router、Tailwind CSS
- 服务端：Node.js 20+、Fastify、TypeScript、Prisma
- 数据库：PostgreSQL 16；缓存：Redis 7
- 节点：Incus、nftables、Go Agent

## 快速部署

```bash
git clone https://github.com/1743986520/incudal.git
cd incudal
cp .env.example .env
bash scripts/init-env.sh
docker compose up -d --build
```

默认仅监听 `127.0.0.1:3000`，生产环境应通过受信任反向代理提供 HTTPS。启动前至少确认 `POSTGRES_PASSWORD`、`JWT_SECRET`、`ENCRYPTION_KEY`、`ADMIN_PASSWORD`、`FRONTEND_URL` 和 `SITE_URL` 已正确配置。不要提交生产环境 `.env`。

Docker 入口脚本会在启动应用前自动执行 Prisma migration。首次升级到 2026-09-16 版本时，IP 唯一索引迁移会检查历史数据；如果已有活动实例撞 IP，迁移会停止并要求人工核对，不会自动覆盖运行中实例的地址。

## 本地开发

要求 Node.js 20+ 和 pnpm 9：

```bash
corepack enable
pnpm install
cp .env.example .env
pnpm dev
```

构建全部项目：`pnpm build`。

## 升级现有部署

```bash
pnpm install
cd server
npx prisma migrate deploy
npx prisma generate
cd ..
pnpm build
```

随后重启服务端，并通过管理员节点页面向节点强制下发最新版 Agent。数据库升级前请先备份 PostgreSQL；`ENCRYPTION_KEY` 不可随意更换。

### 远程更新

已部署的面板可以直接从 GitHub 仓库下载最新更新脚本并执行升级。默认来源为本仓库，也可以通过 `--source` 指定其他 GitHub 仓库：

```bash
curl -fsSL https://raw.githubusercontent.com/1743986520/incudal/main/scripts/remote-update.sh | sudo bash

# 从指定仓库更新
curl -fsSL https://raw.githubusercontent.com/1743986520/incudal/main/scripts/remote-update.sh \
  | sudo bash -s -- --source https://github.com/owner/repo
```

脚本会自动识别 Docker Compose 与 systemd 产物包部署，并在升级前保留现有 `.env`、证书和数据库数据。

管理员也可以登录站点，在「管理 → 系统更新」中手动检查版本、选择更新来源和部署模式，再点击「立即更新」。更新需要明确确认，不会在后台静默执行；如果当前部署没有站点更新执行器，页面会提供可复制的 root 命令。

## 项目结构

```text
agent/          节点 Agent（Go）
client/         用户面板与管理后台（Vue）
server/         API、任务调度、计费和节点安装模板
invite-bot/     Telegram 群组 Bot
scripts/        部署与环境初始化工具
CHANGELOG.md    完整变更、原因和部署注意事项
```

## 安全建议

- 面板必须使用 HTTPS，并正确配置受信任代理。
- Agent 密钥、SMTP 密码、Telegram Token、数据库连接和 SSH 私钥只应保存在环境变量或受限配置文件中。
- PPS 阈值应根据上游封锁线调整，不要在未实测前随意提高。
- 当前尚未默认启用并发连接数封锁，避免误伤正常长连接业务。
- 不要用数据库级 `idle_in_transaction_session_timeout` 掩盖连接池耗尽；应优先保持短事务、限制 Worker 并发，并使用快速失败锁与退避重试。

## 许可证与免责声明

本项目使用 [BSD 3-Clause License](./LICENSE)。项目按“现状（As-is）”提供，部署者自行承担运行、数据、安全、计费及合规风险。Incudal 名称不构成对任何衍生网站、程序或仓库的认可或背书。
