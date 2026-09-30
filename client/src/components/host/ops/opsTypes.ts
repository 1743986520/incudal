// HostOpsTab 拆分面板共享的类型定义。
// 仅承载类型,不包含运行时逻辑;供容器与三个功能面板共同引用。

export type OpsActionKey =
  | 'discover'
  | 'baseline'
  | 'network'
  | 'preview'
  | 'instanceSync'
  | 'instanceRestart'
  | 'instanceDanger'
  | 'auditScan'
  | 'auditKill'

export type AuditSeverity = 'info' | 'low' | 'medium' | 'high'

export interface DiscoverManagedItem {
  incusName: string
  incusType: string
  incusStatus: string
  dbId: number
  dbStatus: string
  userId: number
}

export interface DiscoverOrphanedItem {
  incusName: string
  incusType: string
  incusStatus: string
}

export interface DiscoverMissingItem {
  dbId: number
  dbName: string
  incusId: string
  dbStatus: string
}

export interface DiscoverResult {
  managed: DiscoverManagedItem[]
  orphaned: DiscoverOrphanedItem[]
  missing: DiscoverMissingItem[]
  summary: {
    totalIncus: number
    totalDb: number
    managedCount: number
    orphanedCount: number
    missingCount: number
  }
}

export interface BaselineSyncResult {
  message: string
  resources: {
    cpuUsed: number
    memoryUsed: number
    diskUsed: number
  }
  instanceSync: {
    total: number
    synced: number
    ipChanged: number
  }
}

export interface NetworkRepairRow {
  id: number
  name: string
  success: boolean
  statusChanged?: boolean
  oldStatus?: string
  newStatus?: string
  ipv4Changed?: boolean
  oldIpv4?: string | null
  newIpv4?: string | null
  ipv6Changed?: boolean
  oldIpv6?: string | null
  newIpv6?: string | null
  error?: string
}

export interface NetworkRepairResult {
  message: string
  results: NetworkRepairRow[]
  summary: {
    total: number
    success: number
    failed: number
    changed: number
  }
}

export interface InstanceOpsPreview {
  instanceId: number
  instanceName: string
  incusId: string
  instanceStatus: string
  hostName: string
  hostId: number
  imageAlias?: string | null
  canSync: boolean
  canRestart: boolean
  canForceRestart: boolean
  canRebuild: boolean
  canRecreate: boolean
  activeTask?: {
    id: number
    taskType: string
    status: string
  } | null
  risk: {
    status: string
    isStopped: boolean
    hasActiveTask: boolean
    suggestedAction: 'rebuild' | 'recreate' | 'sync' | 'restart' | 'none'
    notes: string[]
  }
}

export interface InstanceOpsActionResult {
  success?: boolean
  message?: string
  taskId?: number
  status?: string
  statusChanged?: boolean
  from?: string
  to?: string
  currentStatus?: string
  ipv4Changed?: boolean
  oldIpv4?: string | null
  newIpv4?: string | null
  ipv6Changed?: boolean
  oldIpv6?: string | null
  newIpv6?: string | null
}

export interface AvailableInitCommand {
  id: number
  name: string
  commandLineCount: number
  distros: string[]
  description: string | null
}

export interface InstanceAuditFinding {
  id: string
  severity: AuditSeverity
  category: string
  title: string
  detail: string
  targetType: 'process' | 'network' | 'startup' | 'capability'
  ruleId?: string
  ruleName?: string
  ruleSource?: 'builtin' | 'custom'
  matchedText?: string
  recommendation?: string | null
  pid?: number
  evidence: string
  ignored?: boolean
  ignoreReason?: string | null
}

export interface InstanceAuditProcess {
  pid: number
  ppid: number | null
  user: string
  stat: string
  cpuPercent: number | null
  memoryPercent: number | null
  elapsed: string
  command: string
  args: string
  raw: string
  findings: string[]
}

export interface InstanceAuditConnection {
  protocol: string
  state: string
  local: string
  peer: string
  process: string | null
  pid: number | null
  raw: string
}

export interface InstanceAuditStartupItem {
  source: string
  command: string
  raw: string
  findings: string[]
}

export interface InstanceAuditRule {
  id: string | number
  ruleId?: string
  source: 'builtin' | 'custom'
  scope?: 'builtin' | 'global' | 'host'
  readOnly?: boolean
  hostId?: number | null
  overridden?: boolean
  overrideId?: number | null
  originalName?: string | null
  originalSeverity?: AuditSeverity
  originalCategory?: string | null
  originalTargetTypes?: Array<'process' | 'network' | 'startup'>
  originalMatchType?: 'contains' | 'regex' | 'exact'
  originalPattern?: string | null
  originalCaseSensitive?: boolean
  originalRecommendation?: string | null
  name: string
  description?: string | null
  severity: AuditSeverity
  category: string
  targetTypes: Array<'process' | 'network' | 'startup'>
  matchType: 'contains' | 'regex' | 'exact'
  pattern: string
  caseSensitive: boolean
  recommendation?: string | null
  enabled: boolean
}

export interface InstanceAuditResult {
  success: boolean
  scanId: number
  scannedAt: string
  capability: string
  instance: {
    id: number
    name: string
    incusId: string
    type: string
    status: string
  }
  summary: {
    riskLevel: AuditSeverity
    processCount: number
    connectionCount: number
    listeningCount: number
    startupItemCount: number
    findingCount: number
  }
  ignoredCount?: number
  rules?: InstanceAuditRule[]
  findings: InstanceAuditFinding[]
  processes: InstanceAuditProcess[]
  connections: InstanceAuditConnection[]
  startupItems: InstanceAuditStartupItem[]
  stderr?: string[]
}

export interface AuditRuleTemplate {
  name: string
  severity: AuditSeverity
  category: string
  targetTypes: Array<'process' | 'network' | 'startup'>
  matchType: 'contains' | 'regex' | 'exact'
  pattern: string
  recommendation: string
}

export interface InstanceAuditIgnore {
  id: number
  ruleId?: string | null
  targetType?: string | null
  matchText?: string | null
  scope: string
  reason?: string | null
  enabled: boolean
  expiresAt?: string | null
}

export interface InstanceAuditHistory {
  scans: Array<any>
  actions: Array<any>
}
