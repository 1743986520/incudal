// HostOps 面板共享的展示格式化函数(纯函数,无 i18n 依赖)。
// Incus/数据库状态与实例类型的中文映射,供实例操作与审查面板复用。

// 实例类型中文映射
export function localizeType(type: string): string {
  if (type === 'container') return '容器'
  if (type === 'virtual-machine') return '虚拟机'
  return type
}

// 实例状态中文映射
export function localizeStatus(status: string): string {
  const map: Record<string, string> = {
    Running: '运行中',
    Stopped: '已停止',
    Frozen: '已冻结',
    Error: '异常',
    running: '运行中',
    stopped: '已停止',
    suspended: '已封停',
    creating: '创建中',
    error: '异常',
    deleted: '已删除',
  }
  return map[status] || status
}
