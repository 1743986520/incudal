# Incudal

Incudal 是一个基于 Incus 的容器与 KVM 虚拟机管理、销售和托管平台，包含用户面板、管理后台、节点 Agent、计费系统、NAT 端口映射、通知系统及节点安装工具。

> 本分支包含生产环境持续维护的安全、节点兼容性、计费与界面改进。完整修改原因和部署说明见 [CHANGELOG.md](./CHANGELOG.md)。

## 主要功能

- Incus 容器与 KVM 虚拟机生命周期管理
- IPv4 NAT、IPv4 NAT + IPv6、IPv4 NAT + IPv6 NAT、IPv6 Only 等网络模式
- 单端口及批量端口映射，支持 TCP、UDP、对等范围映射和冲突回滚
- 套餐、余额、续费、退款、人工充值与账单管理
- 创建失败重试及防重复退款
- 节点资源、流量和在线状态监控
- 节点 Agent 心跳、安全事件上报及管理员强制更新
- Telegram、邮件、站内信等通知方式
- 中英文界面、公共落地页、方案概览与预览页

## 本分支的重要改进

### 节点安全

- 新节点默认启用每实例 PPS 防护：总限制 `20,000 PPS`，单一目的 IP 限制 `10,000 PPS`。
- nftables 按实例来源 MAC 和目的 IP 精确封锁，不影响同节点其他实例。
- Agent 将安全事件上报面板，面板精确关联实例和用户。
- PPS 事件只执行网络层目标封锁并通知管理员，需人工确认后再执行用户封禁，避免正常高速下载造成误封。
- 无法关联实例时只执行网络层封锁和管理员告警，不猜测或误封。

### Agent 运维

- Agent `v0.0.3` 支持实例 MAC 与安全事件上报。
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

## 许可证与免责声明

本项目使用 [BSD 3-Clause License](./LICENSE)。项目按“现状（As-is）”提供，部署者自行承担运行、数据、安全、计费及合规风险。Incudal 名称不构成对任何衍生网站、程序或仓库的认可或背书。
