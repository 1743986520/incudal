<script setup lang="ts">
// 实例审查面板:审查扫描、发现项与进程处置、规则库、白名单与历史。
// 面板自身负责数据加载与操作;盘点结果与实例选择来自容器,
// 操作互斥锁与最近执行记录通过函数属性与容器交互。
import { ref, watch } from 'vue'
import api from '@/api'
import { useAuthStore } from '@/stores/auth'
import { useThemeStore } from '@/stores/theme'
import { useToast } from '@/stores/toast'
import type {
  AuditRuleTemplate,
  AuditSeverity,
  DiscoverResult,
  InstanceAuditFinding,
  InstanceAuditHistory,
  InstanceAuditIgnore,
  InstanceAuditProcess,
  InstanceAuditResult,
  InstanceAuditRule,
  OpsActionKey
} from '@/components/host/ops/opsTypes'
import { localizeStatus, localizeType } from '@/components/host/ops/opsDisplay'

defineOptions({
  name: 'HostAuditPanel'
})

const props = defineProps<{
  hostId: number
  active: boolean
  discoverResult: DiscoverResult | null
  selectedManaged: DiscoverResult['managed'][number] | null
  selectedManagedDbId: number | null
  loadingAction: string
  beginAction: (key: OpsActionKey) => boolean
  endAction: () => void
  touchLastRun: (key: OpsActionKey) => void
  runDiscover: () => Promise<void>
}>()

const emit = defineEmits<{
  'select-managed': [dbId: number]
}>()

const themeStore = useThemeStore()
const toast = useToast()
const authStore = useAuthStore()

const auditResult = ref<InstanceAuditResult | null>(null)
const auditPanel = ref<'scan' | 'rules' | 'whitelist' | 'history'>('scan')
const auditRules = ref<InstanceAuditRule[]>([])
const auditIgnores = ref<InstanceAuditIgnore[]>([])
const auditHistory = ref<InstanceAuditHistory>({ scans: [], actions: [] })
const loadingAuditMeta = ref(false)
const expandedAuditFindingIds = ref<string[]>([])

const selectedAuditPid = ref<number | null>(null)
const selectedAuditProcess = ref<InstanceAuditProcess | null>(null)
const auditSignal = ref<'TERM' | 'KILL'>('TERM')
const auditReason = ref('')
const auditConfirmationText = ref('')
const auditRuleForm = ref({
  id: null as number | null,
  builtinRuleId: '' as string,
  scope: 'host' as 'host' | 'global',
  name: '',
  severity: 'medium' as AuditSeverity,
  category: 'custom',
  targetTypes: ['process'] as Array<'process' | 'network' | 'startup'>,
  matchType: 'contains' as 'contains' | 'regex' | 'exact',
  pattern: '',
  caseSensitive: false,
  recommendation: '',
  enabled: true
})
const ignoreForm = ref({
  scope: 'instance' as 'instance' | 'host',
  ruleId: '',
  targetType: '',
  matchText: '',
  reason: '',
  expiresInDays: 30
})
const auditRuleTemplates: AuditRuleTemplate[] = [
  {
    name: '疑似代理核心进程',
    severity: 'medium',
    category: '代理/面板',
    targetTypes: ['process', 'startup'],
    matchType: 'regex',
    pattern: '\\b(xray|v2ray|sing-box|trojan|hysteria2?|shadowsocks|gost)\\b',
    recommendation: '请结合客户用途、节点政策和实际流量人工确认。'
  },
  {
    name: '疑似挖矿进程',
    severity: 'high',
    category: '资源滥用',
    targetTypes: ['process', 'startup'],
    matchType: 'regex',
    pattern: '\\b(xmrig|xmr-stak|cpuminer|minerd|ethminer|lolminer|nbminer)\\b',
    recommendation: '请核对 CPU 占用和运行时间，确认违规后再处置。'
  },
  {
    name: '疑似发包或扫描工具',
    severity: 'high',
    category: '网络滥用',
    targetTypes: ['process', 'startup'],
    matchType: 'regex',
    pattern: '\\b(hping3?|nping|masscan|zmap|udp[-_]?flood|syn[-_]?flood)\\b',
    recommendation: '请保留进程参数和连接证据，并核实是否有授权测试场景。'
  },
  {
    name: '命中特定关键词',
    severity: 'medium',
    category: '自定义',
    targetTypes: ['process'],
    matchType: 'contains',
    pattern: '请替换为需要匹配的关键词',
    recommendation: '请结合实例用途和业务背景人工确认。'
  }
]

function localizeSeverity(severity: AuditSeverity): string {
  const map: Record<AuditSeverity, string> = {
    info: '信息',
    low: '低',
    medium: '中',
    high: '高'
  }
  return map[severity] || severity
}

function severityClass(severity: AuditSeverity): string {
  if (severity === 'high') return 'text-red-500'
  if (severity === 'medium') return 'text-amber-500'
  if (severity === 'low') return 'text-blue-500'
  return 'text-themed-muted'
}

function localizeRuleSource(source?: string): string {
  if (source === 'builtin') return '系统内置'
  if (source === 'custom') return '自定义'
  return '-'
}

function localizeRuleScope(scope?: string): string {
  if (scope === 'global') return '管理员全局'
  if (scope === 'host') return '当前节点'
  if (scope === 'builtin') return '系统内置'
  if (scope === 'instance') return '当前实例'
  return scope || '-'
}

function localizeAuditCategory(category?: string): string {
  const map: Record<string, string> = {
    'network-abuse': '网络滥用',
    'proxy-panel': '代理/面板',
    'resource-abuse': '资源滥用',
    'credential-attack': '凭据攻击',
    'network-anomaly': '网络异常',
    'resource-anomaly': '资源异常',
    custom: '自定义'
  }
  return category ? (map[category] || category) : '-'
}

function localizeAuditMatchType(matchType?: string): string {
  if (matchType === 'contains') return '包含关键词'
  if (matchType === 'regex') return '正则表达式'
  if (matchType === 'exact') return '精确匹配'
  return matchType || '-'
}

function localizeAuditTarget(target?: string | null): string {
  if (target === 'process') return '进程'
  if (target === 'network') return '网络连接'
  if (target === 'startup') return '启动项'
  if (target === 'capability') return '执行能力'
  return target || '全部'
}

function localizeAuditTargets(targets?: string[]): string {
  if (!targets?.length) return '-'
  return targets.map(target => localizeAuditTarget(target)).join('、')
}

const legacyFindingTextMap: Record<string, string> = {
  'Packet generation tool detected': '疑似发包工具进程',
  'Mass scanning tool detected': '疑似大规模扫描工具',
  'Flood program name detected': '疑似 Flood/DDoS 程序',
  'Proxy or panel process detected': '疑似代理面板程序',
  'Proxy core process detected': '疑似代理核心进程',
  'Mining process detected': '疑似挖矿进程',
  'Credential attack tool detected': '疑似爆破/撞库工具',
  'High UDP connection count': 'UDP 连接数量偏高',
  'High CPU process': 'CPU 占用偏高的进程',
  'Confirm the process owner and traffic purpose before taking manual action.': '请先确认进程归属、流量用途和客户业务背景，再决定是否手动处置。',
  'Review whether the scan is authorized. Check network connections and customer intent.': '请核实扫描是否经过授权，并结合网络连接、工单或客户说明判断。',
  'Treat as high risk. Capture evidence before any manual process stop.': '建议按高风险处理。手动停止前请先保留进程参数和连接证据。',
  'Confirm whether the node policy allows this application.': '请确认当前节点规则是否允许此类应用，并结合客户业务说明判断。',
  'Check the customer use case and host policy before manual disposal.': '处置前请核对客户用途、节点政策和实际流量，避免误伤正常服务。',
  'Review CPU usage and suspend policy manually if the behavior violates terms.': '请结合 CPU 占用、运行时间和服务条款人工确认，违规后再执行处置。',
  'Check outbound connections and account activity before taking manual action.': '请检查外连目标、登录尝试记录和客户说明，再决定是否手动处理。'
}

function localizeAuditText(text?: string | null): string {
  if (!text) return '-'
  return legacyFindingTextMap[text] || text
}

function localizeFindingDetail(detail?: string | null): string {
  if (!detail) return '-'
  const ruleMatch = detail.match(/^(.+) matched audit rule (.+)\.$/)
  if (ruleMatch) {
    const subject = ruleMatch[1]
      .replace(/^Startup item from /, '启动项来源 ')
      .replace(/^([A-Z]+ .+ -> .+)$/, '网络连接 $1')
    return `${subject} 命中审查规则 ${ruleMatch[2]}。`
  }
  const udpMatch = detail.match(/^(\d+) UDP rows were returned by ss\/netstat during the scan\.$/)
  if (udpMatch) return `本次扫描从 ss/netstat 返回 ${udpMatch[1]} 条 UDP 连接记录，请结合业务用途判断是否异常。`
  const cpuMatch = detail.match(/^PID (\d+) is using ([\d.]+)% CPU\.$/)
  if (cpuMatch) return `PID ${cpuMatch[1]} 当前 CPU 占用为 ${cpuMatch[2]}%。`
  return detail
}

function localizeProcessFindings(findings: string[]): string {
  return findings.map(item => localizeAuditText(item)).join('、')
}

function localizeAuditStatus(status?: string): string {
  if (status === 'success') return '成功'
  if (status === 'failed') return '失败'
  return status || '-'
}

function localizeAuditActionType(actionType?: string): string {
  if (actionType === 'kill_process') return '停止进程'
  return actionType || '-'
}

function localizeAuditActionResult(result?: string): string {
  if (result === 'success') return '成功'
  if (result === 'failed') return '失败'
  return result || '-'
}

function localizeAuditSignal(signal?: string | null): string {
  if (signal === 'TERM') return '安全停止（TERM）'
  if (signal === 'KILL') return '强制停止（KILL）'
  return signal || '-'
}

function resetAuditRuleForm() {
  auditRuleForm.value = {
    id: null,
    builtinRuleId: '',
    scope: 'host',
    name: '',
    severity: 'medium',
    category: 'custom',
    targetTypes: ['process'],
    matchType: 'contains',
    pattern: '',
    caseSensitive: false,
    recommendation: '',
    enabled: true
  }
}

function fillAuditRuleForm(params: {
  id?: number | null
  builtinRuleId?: string
  scope?: 'host' | 'global'
  name: string
  severity: AuditSeverity
  category: string
  targetTypes: Array<'process' | 'network' | 'startup'>
  matchType: 'contains' | 'regex' | 'exact'
  pattern: string
  caseSensitive?: boolean
  recommendation?: string | null
  enabled?: boolean
}) {
  auditRuleForm.value = {
    id: params.id ?? null,
    builtinRuleId: params.builtinRuleId || '',
    scope: params.scope || 'host',
    name: localizeAuditText(params.name),
    severity: params.severity,
    category: params.category ? localizeAuditCategory(params.category) : '自定义',
    targetTypes: [...params.targetTypes],
    matchType: params.matchType,
    pattern: params.pattern,
    caseSensitive: Boolean(params.caseSensitive),
    recommendation: params.recommendation ? localizeAuditText(params.recommendation) : '',
    enabled: params.enabled ?? true
  }
  auditPanel.value = 'rules'
}

function editAuditRule(rule: InstanceAuditRule) {
  if (rule.readOnly || rule.source !== 'custom') return
  fillAuditRuleForm({
    id: Number(rule.id),
    scope: rule.scope === 'global' ? 'global' : 'host',
    name: rule.name,
    severity: rule.severity,
    category: rule.category,
    targetTypes: [...rule.targetTypes],
    matchType: rule.matchType,
    pattern: rule.pattern,
    caseSensitive: rule.caseSensitive,
    recommendation: rule.recommendation || '',
    enabled: rule.enabled
  })
}

function editBuiltinRuleOverride(rule: InstanceAuditRule) {
  if (rule.source !== 'builtin') return
  fillAuditRuleForm({
    builtinRuleId: String(rule.id),
    scope: 'host',
    name: localizeAuditText(rule.name),
    severity: rule.severity,
    category: rule.category,
    targetTypes: [...rule.targetTypes],
    matchType: rule.matchType,
    pattern: rule.pattern,
    caseSensitive: rule.caseSensitive,
    recommendation: rule.recommendation || '',
    enabled: rule.enabled
  })
  toast.success('已载入本节点覆盖配置，保存后只影响当前节点')
}

function createRuleFromExisting(rule: InstanceAuditRule) {
  fillAuditRuleForm({
    name: localizeAuditText(rule.name),
    severity: rule.severity,
    category: rule.category,
    targetTypes: [...rule.targetTypes],
    matchType: rule.matchType,
    pattern: rule.pattern,
    caseSensitive: rule.caseSensitive,
    recommendation: rule.recommendation || '',
    enabled: true
  })
  toast.success('已填入规则编辑表单，调整后可另存为自定义规则')
}

async function resetBuiltinRuleOverride(rule: InstanceAuditRule) {
  if (!props.hostId || rule.source !== 'builtin') return
  loadingAuditMeta.value = true
  try {
    await api.hosts.opsAuditResetBuiltinRule(props.hostId, String(rule.id))
    toast.success('已恢复系统默认规则')
    if (auditRuleForm.value.builtinRuleId === String(rule.id)) resetAuditRuleForm()
    await loadAuditRules()
  } catch (err: any) {
    toast.error('恢复系统默认失败: ' + (err?.message || String(err)))
  } finally {
    loadingAuditMeta.value = false
  }
}

function applyAuditRuleTemplate(template: AuditRuleTemplate) {
  fillAuditRuleForm({
    name: template.name,
    severity: template.severity,
    category: template.category,
    targetTypes: [...template.targetTypes],
    matchType: template.matchType,
    pattern: template.pattern,
    recommendation: template.recommendation,
    enabled: true
  })
}

function isAuditEvidenceExpanded(id: string): boolean {
  return expandedAuditFindingIds.value.includes(id)
}

function toggleAuditEvidence(id: string) {
  const next = new Set(expandedAuditFindingIds.value)
  if (next.has(id)) next.delete(id)
  else next.add(id)
  expandedAuditFindingIds.value = Array.from(next)
}

function toggleRuleTarget(target: 'process' | 'network' | 'startup') {
  const next = [...auditRuleForm.value.targetTypes]
  const index = next.indexOf(target)
  if (index >= 0) next.splice(index, 1)
  else next.push(target)
  auditRuleForm.value.targetTypes = next.length ? next : ['process']
}

function resetAuditActionState() {
  selectedAuditPid.value = null
  selectedAuditProcess.value = null
  auditSignal.value = 'TERM'
  auditReason.value = ''
  auditConfirmationText.value = ''
}

function selectAuditProcess(process: InstanceAuditProcess) {
  selectedAuditPid.value = process.pid
  selectedAuditProcess.value = process
  auditConfirmationText.value = ''
}

async function loadAuditRules() {
  if (!props.hostId) return
  loadingAuditMeta.value = true
  try {
    const res = await api.hosts.opsAuditRules(props.hostId)
    auditRules.value = [...(res.builtin || []), ...(res.custom || [])]
  } catch (err: any) {
    toast.error('加载审查规则失败: ' + (err?.message || String(err)))
  } finally {
    loadingAuditMeta.value = false
  }
}

async function saveAuditRule() {
  if (!props.hostId || !auditRuleForm.value.name.trim() || !auditRuleForm.value.pattern.trim()) {
    toast.error('请填写规则名称和匹配内容')
    return
  }
  loadingAuditMeta.value = true
  const payload = {
    scope: auditRuleForm.value.builtinRuleId ? 'host' : auditRuleForm.value.scope,
    name: auditRuleForm.value.name.trim(),
    severity: auditRuleForm.value.severity,
    category: auditRuleForm.value.category.trim() || 'custom',
    targetTypes: auditRuleForm.value.targetTypes,
    matchType: auditRuleForm.value.matchType,
    pattern: auditRuleForm.value.pattern.trim(),
    caseSensitive: auditRuleForm.value.caseSensitive,
    recommendation: auditRuleForm.value.recommendation.trim() || undefined,
    enabled: auditRuleForm.value.enabled
  }
  try {
    if (auditRuleForm.value.builtinRuleId) await api.hosts.opsAuditUpdateBuiltinRule(props.hostId, auditRuleForm.value.builtinRuleId, payload)
    else if (auditRuleForm.value.id) await api.hosts.opsAuditUpdateRule(props.hostId, auditRuleForm.value.id, payload)
    else await api.hosts.opsAuditCreateRule(props.hostId, payload)
    toast.success(auditRuleForm.value.builtinRuleId ? '本节点内置规则配置已保存' : '审查规则已保存')
    resetAuditRuleForm()
    await loadAuditRules()
  } catch (err: any) {
    toast.error('保存审查规则失败: ' + (err?.message || String(err)))
  } finally {
    loadingAuditMeta.value = false
  }
}

async function deleteAuditRule(rule: InstanceAuditRule) {
  if (!props.hostId || rule.readOnly || rule.source !== 'custom') return
  loadingAuditMeta.value = true
  try {
    await api.hosts.opsAuditDeleteRule(props.hostId, Number(rule.id))
    toast.success('审查规则已删除')
    if (auditRuleForm.value.id === Number(rule.id)) resetAuditRuleForm()
    await loadAuditRules()
  } catch (err: any) {
    toast.error('删除审查规则失败: ' + (err?.message || String(err)))
  } finally {
    loadingAuditMeta.value = false
  }
}

async function loadAuditIgnores() {
  if (!props.hostId) return
  loadingAuditMeta.value = true
  try {
    const res = await api.hosts.opsAuditIgnores(props.hostId, props.selectedManaged ? { instanceId: props.selectedManaged.dbId } : undefined)
    auditIgnores.value = res.ignores || []
  } catch (err: any) {
    toast.error('加载白名单失败: ' + (err?.message || String(err)))
  } finally {
    loadingAuditMeta.value = false
  }
}

function addIgnoreFromFinding(finding?: InstanceAuditFinding) {
  if (finding) {
    ignoreForm.value.ruleId = finding.ruleId || ''
    ignoreForm.value.targetType = finding.targetType || ''
    ignoreForm.value.matchText = finding.matchedText || ''
    ignoreForm.value.reason = finding.ignoreReason || ''
    auditPanel.value = 'whitelist'
  }
}

async function saveAuditIgnore() {
  if (!props.hostId) return
  const scope = ignoreForm.value.scope
  if (scope === 'instance' && !props.selectedManaged) {
    toast.error('请先选择实例')
    return
  }
  if (!ignoreForm.value.ruleId.trim() && !ignoreForm.value.matchText.trim()) {
    toast.error('请填写规则编号或匹配文本')
    return
  }
  loadingAuditMeta.value = true
  try {
    await api.hosts.opsAuditCreateIgnore(props.hostId, {
      scope,
      instanceId: scope === 'instance' ? props.selectedManaged?.dbId : undefined,
      ruleId: ignoreForm.value.ruleId.trim() || undefined,
      targetType: ignoreForm.value.targetType || undefined,
      matchText: ignoreForm.value.matchText.trim() || undefined,
      reason: ignoreForm.value.reason.trim() || undefined,
      expiresInDays: ignoreForm.value.expiresInDays || undefined
    })
    toast.success('白名单已保存')
    ignoreForm.value = { scope: 'instance', ruleId: '', targetType: '', matchText: '', reason: '', expiresInDays: 30 }
    await loadAuditIgnores()
  } catch (err: any) {
    toast.error('保存白名单失败: ' + (err?.message || String(err)))
  } finally {
    loadingAuditMeta.value = false
  }
}

async function deleteAuditIgnore(ignore: InstanceAuditIgnore) {
  if (!props.hostId) return
  loadingAuditMeta.value = true
  try {
    await api.hosts.opsAuditDeleteIgnore(props.hostId, ignore.id)
    toast.success('白名单已停用')
    await loadAuditIgnores()
  } catch (err: any) {
    toast.error('停用白名单失败: ' + (err?.message || String(err)))
  } finally {
    loadingAuditMeta.value = false
  }
}

async function loadAuditHistory() {
  if (!props.hostId) return
  loadingAuditMeta.value = true
  try {
    auditHistory.value = await api.hosts.opsAuditHistory(props.hostId, props.selectedManaged ? { instanceId: props.selectedManaged.dbId, pageSize: 20 } : { pageSize: 20 })
  } catch (err: any) {
    toast.error('加载审查历史失败: ' + (err?.message || String(err)))
  } finally {
    loadingAuditMeta.value = false
  }
}

async function ensureInventoryForAudit() {
  if (props.discoverResult) return
  await props.runDiscover()
}

async function runAuditScan() {
  if (!props.hostId) return
  if (!props.selectedManaged) {
    await ensureInventoryForAudit()
    if (!props.selectedManaged) {
      toast.error('请先盘点并选择一个已纳管实例')
      return
    }
  }

  if (!props.beginAction('auditScan')) return
  try {
    auditResult.value = await api.hosts.opsInstanceAuditScan(props.hostId, props.selectedManaged!.dbId)
    expandedAuditFindingIds.value = []
    resetAuditActionState()
    props.touchLastRun('auditScan')
    void loadAuditHistory()
    toast.success('实例审查扫描完成')
  } catch (err: any) {
    toast.error('实例审查失败: ' + (err?.message || String(err)))
  } finally {
    props.endAction()
  }
}

async function runAuditKillProcess() {
  if (!props.hostId || !props.selectedManaged || !selectedAuditPid.value) return
  if (!auditReason.value.trim()) {
    toast.error('请填写处置原因')
    return
  }
  if (auditConfirmationText.value.trim() !== props.selectedManaged.incusName) {
    toast.error('确认文本不匹配实例名称')
    return
  }

  if (!props.beginAction('auditKill')) return
  try {
    await api.hosts.opsInstanceAuditKillProcess(props.hostId, props.selectedManaged.dbId, {
      pid: selectedAuditPid.value,
      signal: auditSignal.value,
      reason: auditReason.value.trim(),
      confirmationText: auditConfirmationText.value.trim(),
      scanId: auditResult.value?.scanId,
      expectedCommand: selectedAuditProcess.value?.command
    })
    props.touchLastRun('auditKill')
    toast.success('手动处置命令已发送')
    resetAuditActionState()
    props.endAction()
    await runAuditScan()
  } catch (err: any) {
    toast.error('手动处置失败: ' + (err?.message || String(err)))
  } finally {
    props.endAction()
  }
}

// 切换审查子页时按需加载对应数据
watch(auditPanel, (panel) => {
  if (panel === 'rules') void loadAuditRules()
  if (panel === 'whitelist') void loadAuditIgnores()
  if (panel === 'history') void loadAuditHistory()
})

// 面板被激活时,若停留在规则库子页则加载规则(对应原容器的 activeOpsMenu 监听)
watch(() => props.active, (active) => {
  if (active && auditPanel.value === 'rules') void loadAuditRules()
})

// 切换选中实例时重置审查结果,并按当前子页刷新白名单/历史
watch(() => props.selectedManagedDbId, () => {
  auditResult.value = null
  expandedAuditFindingIds.value = []
  resetAuditActionState()
  if (auditPanel.value === 'whitelist') void loadAuditIgnores()
  if (auditPanel.value === 'history') void loadAuditHistory()
})

defineExpose({
  runAuditScan
})
</script>

<template>
  <div class="space-y-6">
    <div class="inline-flex rounded-lg border p-1" :class="themeStore.isDark ? 'border-gray-800 bg-gray-900' : 'border-gray-200 bg-gray-50'">
      <button type="button" class="px-3 py-1.5 rounded-md text-sm font-medium transition" :class="auditPanel === 'scan' ? 'bg-blue-600 text-white' : 'text-themed-muted hover:text-themed'" @click="auditPanel = 'scan'">审查扫描</button>
      <button type="button" class="px-3 py-1.5 rounded-md text-sm font-medium transition" :class="auditPanel === 'rules' ? 'bg-blue-600 text-white' : 'text-themed-muted hover:text-themed'" @click="auditPanel = 'rules'">规则库</button>
      <button type="button" class="px-3 py-1.5 rounded-md text-sm font-medium transition" :class="auditPanel === 'whitelist' ? 'bg-blue-600 text-white' : 'text-themed-muted hover:text-themed'" @click="auditPanel = 'whitelist'">白名单</button>
      <button type="button" class="px-3 py-1.5 rounded-md text-sm font-medium transition" :class="auditPanel === 'history' ? 'bg-blue-600 text-white' : 'text-themed-muted hover:text-themed'" @click="auditPanel = 'history'">审查历史</button>
    </div>

    <div v-if="auditPanel === 'scan'" class="card p-5 space-y-4">
      <div class="flex items-center justify-between gap-3 flex-wrap">
        <div>
          <h3 class="text-base font-semibold text-themed">实例审查</h3>
          <p class="text-xs text-themed-muted mt-1">人工扫描进程、网络连接和启动项，发现可疑项后由运维人员手动处置。</p>
        </div>
        <button class="btn-secondary btn-sm" :disabled="loadingAction !== ''" @click="runDiscover">
          {{ loadingAction === 'discover' ? '...' : '刷新实例列表' }}
        </button>
      </div>

      <div v-if="discoverResult" class="grid gap-4 xl:grid-cols-[minmax(260px,360px)_1fr]">
        <div class="rounded-xl border p-4 space-y-3" :class="themeStore.isDark ? 'border-gray-800' : 'border-gray-200'">
          <div class="font-medium text-themed">选择审查实例</div>
          <div v-if="discoverResult.managed.length" class="space-y-2 max-h-96 overflow-auto">
            <button
              v-for="item in discoverResult.managed"
              :key="`audit-${item.dbId}-${item.incusName}`"
              type="button"
              class="w-full rounded-lg px-3 py-2 text-left text-sm border transition"
              :class="selectedManagedDbId === item.dbId
                ? (themeStore.isDark ? 'border-blue-500 bg-blue-500/10' : 'border-blue-500 bg-blue-50')
                : (themeStore.isDark ? 'border-gray-800 bg-gray-900 hover:border-gray-700' : 'border-gray-200 bg-gray-50 hover:border-gray-300')"
              @click="emit('select-managed', item.dbId)"
            >
              <div class="font-medium text-themed">{{ item.incusName }}</div>
              <div class="text-xs text-themed-muted mt-1">
                {{ localizeType(item.incusType) }} · {{ localizeStatus(item.incusStatus) }} · 用户 ID: {{ item.userId }}
              </div>
            </button>
          </div>
          <div v-else class="text-sm text-themed-muted">当前没有已纳管实例。</div>
        </div>

        <div class="rounded-xl border p-4 space-y-4" :class="themeStore.isDark ? 'border-gray-800' : 'border-gray-200'">
          <div class="flex items-center justify-between gap-3 flex-wrap">
            <div>
              <div class="font-medium text-themed">{{ selectedManaged?.incusName || '未选择实例' }}</div>
              <div class="text-xs text-themed-muted mt-1">扫描不会自动封禁，也不会自动停止进程。</div>
            </div>
            <button class="btn-primary btn-sm" :disabled="loadingAction !== '' || !selectedManaged" @click="runAuditScan">
              {{ loadingAction === 'auditScan' ? '扫描中...' : '开始审查扫描' }}
            </button>
          </div>

          <div v-if="auditResult" class="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
            <div class="rounded-xl p-3" :class="themeStore.isDark ? 'bg-gray-900' : 'bg-gray-50'">
              <div class="text-xs text-themed-muted">风险等级</div>
              <div class="text-lg font-semibold mt-1" :class="severityClass(auditResult.summary.riskLevel)">{{ localizeSeverity(auditResult.summary.riskLevel) }}</div>
            </div>
            <div class="rounded-xl p-3" :class="themeStore.isDark ? 'bg-gray-900' : 'bg-gray-50'">
              <div class="text-xs text-themed-muted">发现项</div>
              <div class="text-lg font-semibold mt-1 text-themed">{{ auditResult.summary.findingCount }}</div>
            </div>
            <div class="rounded-xl p-3" :class="themeStore.isDark ? 'bg-gray-900' : 'bg-gray-50'">
              <div class="text-xs text-themed-muted">进程</div>
              <div class="text-lg font-semibold mt-1 text-themed">{{ auditResult.summary.processCount }}</div>
            </div>
            <div class="rounded-xl p-3" :class="themeStore.isDark ? 'bg-gray-900' : 'bg-gray-50'">
              <div class="text-xs text-themed-muted">连接</div>
              <div class="text-lg font-semibold mt-1 text-themed">{{ auditResult.summary.connectionCount }}</div>
            </div>
            <div class="rounded-xl p-3" :class="themeStore.isDark ? 'bg-gray-900' : 'bg-gray-50'">
              <div class="text-xs text-themed-muted">监听端口</div>
              <div class="text-lg font-semibold mt-1 text-themed">{{ auditResult.summary.listeningCount }}</div>
            </div>
          </div>
        </div>
      </div>

      <div v-else class="rounded-xl border border-dashed p-8 text-center text-sm text-themed-muted" :class="themeStore.isDark ? 'border-gray-800' : 'border-gray-200'">
        请先刷新实例列表，选择一个已纳管实例后再进行人工审查。
      </div>
    </div>

    <div v-if="auditPanel === 'scan' && auditResult" class="grid gap-6 xl:grid-cols-2">
      <div class="card p-5 space-y-4">
        <div>
          <h3 class="text-base font-semibold text-themed">可疑发现</h3>
          <p class="text-xs text-themed-muted mt-1">结果只作为人工判断线索，处置前请结合进程参数和业务背景确认。</p>
        </div>
        <div v-if="auditResult.findings.length" class="space-y-3 max-h-[32rem] overflow-auto">
          <div v-for="finding in auditResult.findings" :key="finding.id" class="rounded-xl border p-3 text-sm" :class="themeStore.isDark ? 'border-gray-800 bg-gray-900' : 'border-gray-200 bg-gray-50'">
            <div class="flex items-center justify-between gap-3">
              <div class="font-medium text-themed">{{ localizeAuditText(finding.title) }}</div>
              <span class="text-xs font-semibold" :class="severityClass(finding.severity)">{{ localizeSeverity(finding.severity) }}</span>
            </div>
            <div class="text-xs text-themed-muted mt-1">{{ localizeFindingDetail(finding.detail) }}</div>
            <div class="mt-2 grid gap-2 text-xs sm:grid-cols-2">
              <div class="text-themed-muted">规则：{{ localizeAuditText(finding.ruleName || finding.ruleId) }} / {{ localizeRuleSource(finding.ruleSource) }}</div>
              <div class="text-themed-muted">分类：{{ localizeAuditCategory(finding.category) }} / 命中：{{ finding.matchedText || '-' }}</div>
              <div v-if="finding.recommendation" class="text-themed-muted sm:col-span-2">建议：{{ localizeAuditText(finding.recommendation) }}</div>
              <div v-if="finding.ignored" class="text-blue-500 sm:col-span-2">已被白名单忽略：{{ finding.ignoreReason || '-' }}</div>
            </div>
            <div class="mt-2 flex justify-between gap-2">
              <button class="btn-ghost btn-sm" @click="toggleAuditEvidence(finding.id)">
                {{ isAuditEvidenceExpanded(finding.id) ? '收起原始证据' : '查看原始证据' }}
              </button>
              <button v-if="!finding.ignored" class="btn-ghost btn-sm" @click="addIgnoreFromFinding(finding)">加入白名单</button>
            </div>
            <pre v-if="isAuditEvidenceExpanded(finding.id)" class="mt-2 text-xs whitespace-pre-wrap break-all text-themed-muted rounded-lg p-3" :class="themeStore.isDark ? 'bg-gray-950' : 'bg-white'">{{ finding.evidence }}</pre>
          </div>
        </div>
        <div v-else class="text-sm text-themed-muted">未命中当前启用的审查规则。</div>
      </div>

      <div class="card p-5 space-y-4">
        <div>
          <h3 class="text-base font-semibold text-themed">手动停止进程</h3>
          <p class="text-xs text-themed-muted mt-1">仅对选中的 PID 发送信号，不会自动封禁实例或用户。</p>
        </div>

        <div class="grid gap-3 sm:grid-cols-2">
          <div>
            <label class="block text-xs text-themed-muted mb-1.5">PID</label>
            <input v-model.number="selectedAuditPid" type="number" min="2" class="input" placeholder="选择或输入 PID" />
          </div>
          <div>
            <label class="block text-xs text-themed-muted mb-1.5">信号</label>
            <select v-model="auditSignal" class="input">
              <option value="TERM">安全停止（TERM）</option>
              <option value="KILL">强制停止（KILL）</option>
            </select>
          </div>
        </div>
        <div>
          <label class="block text-xs text-themed-muted mb-1.5">处置原因</label>
          <textarea v-model="auditReason" class="input min-h-20" placeholder="记录判断依据，便于后续追溯" />
        </div>
        <div>
          <label class="block text-xs text-themed-muted mb-1.5">确认实例名称</label>
          <input v-model="auditConfirmationText" type="text" class="input" :placeholder="selectedManaged?.incusName || ''" />
        </div>
        <div class="flex justify-end">
          <button class="btn-danger btn-sm" :disabled="loadingAction !== '' || !selectedAuditPid || auditConfirmationText.trim() !== selectedManaged?.incusName" @click="runAuditKillProcess">
            {{ loadingAction === 'auditKill' ? '处理中...' : '发送停止信号' }}
          </button>
        </div>
      </div>
    </div>

    <div v-if="auditPanel === 'scan' && auditResult" class="card p-5 space-y-4">
      <div class="flex items-center justify-between gap-3 flex-wrap">
        <div>
          <h3 class="text-base font-semibold text-themed">进程列表</h3>
          <p class="text-xs text-themed-muted mt-1">优先显示命中规则或 CPU 较高的进程。</p>
        </div>
        <button class="btn-ghost btn-sm" :disabled="loadingAction !== '' || !selectedManaged" @click="runAuditScan">
          {{ loadingAction === 'auditScan' ? '刷新中...' : '刷新进程' }}
        </button>
      </div>
      <div class="overflow-x-auto rounded-xl border" :class="themeStore.isDark ? 'border-gray-800' : 'border-gray-200'">
        <table class="min-w-full text-sm">
          <thead :class="themeStore.isDark ? 'bg-gray-900' : 'bg-gray-50'">
            <tr>
              <th class="px-4 py-3 text-left font-medium text-themed">PID</th>
              <th class="px-4 py-3 text-left font-medium text-themed">用户</th>
              <th class="px-4 py-3 text-left font-medium text-themed">CPU</th>
              <th class="px-4 py-3 text-left font-medium text-themed">内存</th>
              <th class="px-4 py-3 text-left font-medium text-themed">命令</th>
              <th class="px-4 py-3 text-left font-medium text-themed">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="process in auditResult.processes" :key="process.pid" class="border-t" :class="themeStore.isDark ? 'border-gray-800' : 'border-gray-200'">
              <td class="px-4 py-3 font-mono text-themed">{{ process.pid }}</td>
              <td class="px-4 py-3 text-themed-muted">{{ process.user }}</td>
              <td class="px-4 py-3 text-themed-muted">{{ process.cpuPercent ?? '-' }}</td>
              <td class="px-4 py-3 text-themed-muted">{{ process.memoryPercent ?? '-' }}</td>
              <td class="px-4 py-3">
                <div class="font-medium text-themed">{{ process.command }}</div>
                <div class="text-xs text-themed-muted max-w-xl truncate">{{ process.args }}</div>
                <div v-if="process.findings.length" class="text-xs text-amber-500 mt-1">{{ localizeProcessFindings(process.findings) }}</div>
              </td>
              <td class="px-4 py-3">
                <button class="btn-ghost btn-sm" @click="selectAuditProcess(process)">选择</button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <div v-if="auditPanel === 'scan' && auditResult" class="grid gap-6 xl:grid-cols-2">
      <div class="card p-5 space-y-4">
        <h3 class="text-base font-semibold text-themed">网络连接</h3>
        <div class="space-y-2 max-h-96 overflow-auto">
          <div v-for="(connection, index) in auditResult.connections" :key="`${connection.raw}-${index}`" class="rounded-lg px-3 py-2 text-xs" :class="themeStore.isDark ? 'bg-gray-900' : 'bg-gray-50'">
            <div class="font-mono text-themed">{{ connection.protocol }} {{ connection.state }} {{ connection.local }} -> {{ connection.peer }}</div>
            <div v-if="connection.process" class="text-themed-muted mt-1">{{ connection.process }}</div>
          </div>
        </div>
      </div>

      <div class="card p-5 space-y-4">
        <h3 class="text-base font-semibold text-themed">启动项摘要</h3>
        <div class="space-y-2 max-h-96 overflow-auto">
          <div v-for="(item, index) in auditResult.startupItems" :key="`${item.source}-${index}`" class="rounded-lg px-3 py-2 text-xs" :class="themeStore.isDark ? 'bg-gray-900' : 'bg-gray-50'">
            <div class="text-themed-muted">{{ item.source }}</div>
            <div class="font-mono text-themed break-all">{{ item.command }}</div>
            <div v-if="item.findings.length" class="text-amber-500 mt-1">{{ localizeProcessFindings(item.findings) }}</div>
          </div>
        </div>
      </div>
    </div>

    <div v-if="auditPanel === 'rules'" class="grid gap-6 xl:grid-cols-[minmax(320px,420px)_1fr]">
      <div class="card p-5 space-y-4">
        <div>
          <h3 class="text-base font-semibold text-themed">规则编辑</h3>
          <p class="text-xs text-themed-muted mt-1">
            {{ auditRuleForm.builtinRuleId ? '正在调整系统内置规则的本节点覆盖配置，只影响当前节点。' : '节点所有者可创建当前节点规则，管理员还可以创建全局规则。' }}
          </p>
        </div>
        <div class="rounded-xl border p-3 space-y-2" :class="themeStore.isDark ? 'border-gray-800 bg-gray-900' : 'border-gray-200 bg-gray-50'">
          <div class="text-xs font-medium text-themed">快速模板</div>
          <div class="flex flex-wrap gap-2">
            <button
              v-for="template in auditRuleTemplates"
              :key="template.name"
              type="button"
              class="btn-ghost btn-sm"
              @click="applyAuditRuleTemplate(template)"
            >
              {{ template.name }}
            </button>
          </div>
        </div>
        <div class="grid gap-3">
          <input v-model="auditRuleForm.name" class="input" placeholder="规则名称" />
          <div class="grid gap-3 sm:grid-cols-2">
            <select v-model="auditRuleForm.scope" class="input" :disabled="!!auditRuleForm.builtinRuleId">
              <option value="host">当前节点</option>
              <option v-if="authStore.user?.role === 'admin'" value="global">管理员全局</option>
            </select>
            <select v-model="auditRuleForm.severity" class="input">
              <option value="info">信息</option>
              <option value="low">低</option>
              <option value="medium">中</option>
              <option value="high">高</option>
            </select>
          </div>
          <input v-model="auditRuleForm.category" class="input" placeholder="分类，例如 网络滥用、代理面板" />
          <div class="flex flex-wrap gap-2">
            <label class="inline-flex items-center gap-2 text-sm text-themed-muted"><input type="checkbox" :checked="auditRuleForm.targetTypes.includes('process')" @change="toggleRuleTarget('process')" />进程</label>
            <label class="inline-flex items-center gap-2 text-sm text-themed-muted"><input type="checkbox" :checked="auditRuleForm.targetTypes.includes('network')" @change="toggleRuleTarget('network')" />网络</label>
            <label class="inline-flex items-center gap-2 text-sm text-themed-muted"><input type="checkbox" :checked="auditRuleForm.targetTypes.includes('startup')" @change="toggleRuleTarget('startup')" />启动项</label>
          </div>
          <div class="grid gap-3 sm:grid-cols-2">
            <select v-model="auditRuleForm.matchType" class="input">
              <option value="contains">包含关键词</option>
              <option value="regex">正则表达式</option>
              <option value="exact">精确匹配</option>
            </select>
            <label class="inline-flex items-center gap-2 text-sm text-themed-muted"><input v-model="auditRuleForm.caseSensitive" type="checkbox" />区分大小写</label>
          </div>
          <textarea v-model="auditRuleForm.pattern" class="input min-h-20" placeholder="匹配内容或正则" />
          <textarea v-model="auditRuleForm.recommendation" class="input min-h-20" placeholder="处理建议，可选" />
          <label class="inline-flex items-center gap-2 text-sm text-themed-muted"><input v-model="auditRuleForm.enabled" type="checkbox" />启用规则</label>
        </div>
        <div class="flex justify-between gap-3">
          <button class="btn-ghost btn-sm" @click="resetAuditRuleForm">清空</button>
          <button class="btn-primary btn-sm" :disabled="loadingAuditMeta" @click="saveAuditRule">
            {{ auditRuleForm.builtinRuleId ? '保存本节点覆盖' : (auditRuleForm.id ? '保存修改' : '新增规则') }}
          </button>
        </div>
      </div>

      <div class="card p-5 space-y-4">
        <div class="flex items-center justify-between">
          <h3 class="text-base font-semibold text-themed">规则库</h3>
          <button class="btn-ghost btn-sm" :disabled="loadingAuditMeta" @click="loadAuditRules">刷新</button>
        </div>
        <div class="space-y-3 max-h-[42rem] overflow-auto">
          <div v-for="rule in auditRules" :key="`${rule.source}-${rule.id}`" class="rounded-xl border p-3 text-sm" :class="themeStore.isDark ? 'border-gray-800 bg-gray-900' : 'border-gray-200 bg-gray-50'">
            <div class="flex items-center justify-between gap-3">
              <div class="font-medium text-themed">{{ localizeAuditText(rule.name) }}</div>
              <span class="text-xs font-semibold" :class="severityClass(rule.severity)">{{ localizeSeverity(rule.severity) }}</span>
            </div>
            <div class="text-xs text-themed-muted mt-1">
              {{ localizeRuleSource(rule.source) }} / {{ localizeRuleScope(rule.scope) }} / {{ localizeAuditCategory(rule.category) }} / {{ localizeAuditMatchType(rule.matchType) }}
            </div>
            <div class="text-xs mt-1" :class="rule.enabled ? 'text-emerald-500' : 'text-red-500'">
              {{ rule.enabled ? '当前启用' : '当前已停用' }}{{ rule.overridden ? ' / 本节点已覆盖' : '' }}
            </div>
            <div class="text-xs text-themed-muted mt-1">检查对象：{{ localizeAuditTargets(rule.targetTypes) }}</div>
            <div class="text-xs font-mono text-themed-muted mt-2 break-all">{{ rule.pattern }}</div>
            <div v-if="rule.recommendation" class="text-xs text-themed-muted mt-2">建议：{{ localizeAuditText(rule.recommendation) }}</div>
            <div class="mt-3 flex justify-end gap-2">
              <button v-if="rule.source === 'builtin'" class="btn-ghost btn-sm" @click="editBuiltinRuleOverride(rule)">调整本节点</button>
              <button v-if="rule.source === 'builtin' && rule.overridden" class="btn-ghost btn-sm" @click="resetBuiltinRuleOverride(rule)">恢复默认</button>
              <button v-if="!rule.readOnly" class="btn-ghost btn-sm" @click="editAuditRule(rule)">编辑</button>
              <button class="btn-ghost btn-sm" @click="createRuleFromExisting(rule)">基于此规则新建</button>
              <button v-if="!rule.readOnly" class="btn-danger btn-sm" @click="deleteAuditRule(rule)">删除</button>
            </div>
          </div>
          <div v-if="!auditRules.length" class="text-sm text-themed-muted">暂无规则，点击刷新加载系统内置规则。</div>
        </div>
      </div>
    </div>

    <div v-if="auditPanel === 'whitelist'" class="grid gap-6 xl:grid-cols-[minmax(320px,420px)_1fr]">
      <div class="card p-5 space-y-4">
        <h3 class="text-base font-semibold text-themed">新增白名单</h3>
        <select v-model="ignoreForm.scope" class="input">
          <option value="instance">当前实例</option>
          <option value="host">当前节点</option>
        </select>
        <input v-model="ignoreForm.ruleId" class="input" placeholder="规则编号，例如 proxy-core 或 custom:1" />
        <select v-model="ignoreForm.targetType" class="input">
          <option value="">所有目标</option>
          <option value="process">进程</option>
          <option value="network">网络</option>
          <option value="startup">启动项</option>
        </select>
        <input v-model="ignoreForm.matchText" class="input" placeholder="匹配文本，可选" />
        <textarea v-model="ignoreForm.reason" class="input min-h-20" placeholder="忽略原因" />
        <input v-model.number="ignoreForm.expiresInDays" type="number" min="0" max="365" class="input" placeholder="有效天数，0 表示永久" />
        <button class="btn-primary btn-sm" :disabled="loadingAuditMeta" @click="saveAuditIgnore">保存白名单</button>
      </div>

      <div class="card p-5 space-y-4">
        <div class="flex items-center justify-between">
          <h3 class="text-base font-semibold text-themed">白名单列表</h3>
          <button class="btn-ghost btn-sm" :disabled="loadingAuditMeta" @click="loadAuditIgnores">刷新</button>
        </div>
        <div class="space-y-3">
          <div v-for="ignore in auditIgnores" :key="ignore.id" class="rounded-xl border p-3 text-sm" :class="themeStore.isDark ? 'border-gray-800 bg-gray-900' : 'border-gray-200 bg-gray-50'">
            <div class="font-medium text-themed">{{ localizeRuleScope(ignore.scope) }} / {{ ignore.ruleId || '任意规则' }}</div>
            <div class="text-xs text-themed-muted mt-1">目标：{{ localizeAuditTarget(ignore.targetType) }} / 文本：{{ ignore.matchText || '-' }}</div>
            <div class="text-xs text-themed-muted mt-1">原因：{{ ignore.reason || '-' }}</div>
            <div class="text-xs text-themed-muted mt-1">到期：{{ ignore.expiresAt ? new Date(ignore.expiresAt).toLocaleString() : '永久' }}</div>
            <div class="mt-3 flex justify-end">
              <button class="btn-danger btn-sm" @click="deleteAuditIgnore(ignore)">停用</button>
            </div>
          </div>
          <div v-if="!auditIgnores.length" class="text-sm text-themed-muted">暂无白名单。</div>
        </div>
      </div>
    </div>

    <div v-if="auditPanel === 'history'" class="grid gap-6 xl:grid-cols-2">
      <div class="card p-5 space-y-4">
        <div class="flex items-center justify-between">
          <h3 class="text-base font-semibold text-themed">扫描历史</h3>
          <button class="btn-ghost btn-sm" :disabled="loadingAuditMeta" @click="loadAuditHistory">刷新</button>
        </div>
        <div class="space-y-3">
          <div v-for="scan in auditHistory.scans" :key="scan.id" class="rounded-xl border p-3 text-sm" :class="themeStore.isDark ? 'border-gray-800 bg-gray-900' : 'border-gray-200 bg-gray-50'">
            <div class="flex justify-between gap-3">
              <div class="font-medium text-themed">#{{ scan.id }} / {{ localizeAuditStatus(scan.status) }}</div>
              <span :class="severityClass(scan.riskLevel)">{{ localizeSeverity(scan.riskLevel) }}</span>
            </div>
            <div class="text-xs text-themed-muted mt-1">{{ new Date(scan.createdAt).toLocaleString() }} / {{ scan.user?.username || scan.userId }}</div>
            <div class="text-xs text-themed-muted mt-1">发现 {{ scan.findingCount }}，忽略 {{ scan.ignoredCount }}，进程 {{ scan.processCount }}，连接 {{ scan.connectionCount }}</div>
          </div>
          <div v-if="!auditHistory.scans.length" class="text-sm text-themed-muted">暂无扫描历史。</div>
        </div>
      </div>

      <div class="card p-5 space-y-4">
        <h3 class="text-base font-semibold text-themed">处置历史</h3>
        <div class="space-y-3">
          <div v-for="action in auditHistory.actions" :key="action.id" class="rounded-xl border p-3 text-sm" :class="themeStore.isDark ? 'border-gray-800 bg-gray-900' : 'border-gray-200 bg-gray-50'">
            <div class="font-medium text-themed">#{{ action.id }} / {{ localizeAuditActionType(action.actionType) }} / {{ localizeAuditActionResult(action.result) }}</div>
            <div class="text-xs text-themed-muted mt-1">{{ new Date(action.createdAt).toLocaleString() }} / {{ action.user?.username || action.userId }}</div>
            <div class="text-xs text-themed-muted mt-1">PID {{ action.pid || '-' }} / {{ localizeAuditSignal(action.signal) }}</div>
            <div class="text-xs text-themed-muted mt-1">原因：{{ action.reason }}</div>
            <div v-if="action.processCommand" class="text-xs font-mono text-themed-muted mt-1 break-all">{{ action.processCommand }}</div>
          </div>
          <div v-if="!auditHistory.actions.length" class="text-sm text-themed-muted">暂无处置历史。</div>
        </div>
      </div>
    </div>
  </div>
</template>
