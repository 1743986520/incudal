<script setup lang="ts">
// 网络策略面板:Agent 定时审查配置、网络策略的建立/启停/删除与目标实例选择。
// 面板自身负责数据加载与操作;仅在面板被激活时拉取数据。
import { ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import api from '@/api'
import { useThemeStore } from '@/stores/theme'
import { useToast } from '@/stores/toast'

defineOptions({
  name: 'HostNetworkPolicyPanel'
})

const props = defineProps<{
  hostId: number
  active: boolean
}>()

const { t } = useI18n()
const themeStore = useThemeStore()
const toast = useToast()

const agentMonitoring = ref({ enabled: false, intervalSeconds: 300, batchSize: 8 })
const networkPolicies = ref<any[]>([])
const networkPolicyInstances = ref<any[]>([])
const networkPolicyLoading = ref(false)
const networkPolicyForm = ref({
  name: '', policyType: 'ip_block', targetMode: 'selected', targetInstanceIds: [] as number[],
  cidrs: '', upstreams: '', domains: '', addresses: '', dnsAction: 'address', blockDot: false, enabled: false
})

async function loadNetworkPolicyPanel() {
  networkPolicyLoading.value = true
  try {
    const [monitoring, policies] = await Promise.all([api.hosts.opsAgentMonitoring(props.hostId), api.hosts.opsNetworkPolicies(props.hostId)])
    agentMonitoring.value = {
      enabled: monitoring.config?.enabled === true,
      intervalSeconds: monitoring.config?.intervalSeconds || 300,
      batchSize: monitoring.config?.batchSize || 8
    }
    networkPolicies.value = policies.policies || []
    networkPolicyInstances.value = policies.instances || []
  } catch (err: any) { toast.error('加载 Agent 监测与网络策略失败: ' + (err?.message || String(err))) }
  finally { networkPolicyLoading.value = false }
}

async function saveAgentMonitoring() {
  networkPolicyLoading.value = true
  try { await api.hosts.opsUpdateAgentMonitoring(props.hostId, agentMonitoring.value); toast.success('Agent 定时监测配置已保存') }
  catch (err: any) { toast.error('保存 Agent 监测失败: ' + (err?.message || String(err))) }
  finally { networkPolicyLoading.value = false }
}

function splitPolicyValues(value: string): string[] { return value.split(/[\s,]+/).map(item => item.trim()).filter(Boolean) }
function toggleNetworkPolicyInstance(id: number) { const values=networkPolicyForm.value.targetInstanceIds; networkPolicyForm.value.targetInstanceIds=values.includes(id)?values.filter(item=>item!==id):[...values,id] }
function networkPolicyTypeLabel(policyType: string): string {
  const labels: Record<string, string> = {
    ip_block: '阻挡 IP / CIDR',
    dns_lock: '强制平台 DNS',
    dns_override: '域名劫持 / 屏蔽',
    udp_block: t('admin.hosts.ops.networkPolicyUdpBlock'),
    ping_block: t('admin.hosts.ops.networkPolicyPingBlock')
  }
  return labels[policyType] || policyType
}
async function createNetworkPolicy() {
  const form=networkPolicyForm.value
  let config: Record<string, unknown>
  if(form.policyType==='ip_block') config={cidrs:splitPolicyValues(form.cidrs)}
  else if(form.policyType==='dns_lock') config={upstreams:splitPolicyValues(form.upstreams),blockDot:form.blockDot}
  else if(form.policyType==='dns_override') config={upstreams:splitPolicyValues(form.upstreams),domains:splitPolicyValues(form.domains),addresses:splitPolicyValues(form.addresses),action:form.dnsAction}
  else config={}
  networkPolicyLoading.value=true
  try {
    await api.hosts.opsCreateNetworkPolicy(props.hostId,{name:form.name,policyType:form.policyType,targetMode:form.targetMode,targetInstanceIds:form.targetInstanceIds,config,enabled:form.enabled})
    toast.success(form.enabled?'策略已建立，等待 Agent 套用':'策略已建立但尚未启用')
    networkPolicyForm.value={name:'',policyType:'ip_block',targetMode:'selected',targetInstanceIds:[],cidrs:'',upstreams:'',domains:'',addresses:'',dnsAction:'address',blockDot:false,enabled:false}
    await loadNetworkPolicyPanel()
  } catch(err:any){toast.error('建立网络策略失败: '+(err?.message||String(err)))} finally{networkPolicyLoading.value=false}
}
async function toggleNetworkPolicy(policy:any){try{await api.hosts.opsUpdateNetworkPolicy(props.hostId,policy.id,{enabled:!policy.enabled});await loadNetworkPolicyPanel()}catch(err:any){toast.error(err?.message||String(err))}}
async function deleteNetworkPolicy(policy:any){if(!confirm(`确定删除策略「${policy.name}」？`))return;try{await api.hosts.opsDeleteNetworkPolicy(props.hostId,policy.id);await loadNetworkPolicyPanel()}catch(err:any){toast.error(err?.message||String(err))}}

watch(() => props.active, (active) => {
  if (active) void loadNetworkPolicyPanel()
})
</script>

<template>
  <div class="space-y-6">
    <div class="rounded-xl border p-4 space-y-4" :class="themeStore.isDark ? 'border-gray-800 bg-gray-900/40' : 'border-gray-200 bg-gray-50'">
      <div><h3 class="font-semibold text-themed">Agent 定时审查</h3><p class="text-xs text-themed-muted mt-1">Agent 分批采集原始数据，由面板统一套用审查规则；关闭时不会进行后台扫描。</p></div>
      <div class="grid gap-3 sm:grid-cols-3">
        <label class="flex items-center gap-2 text-sm"><input v-model="agentMonitoring.enabled" type="checkbox" />启用定时监测</label>
        <label class="text-xs text-themed-muted">扫描周期（秒）<input v-model.number="agentMonitoring.intervalSeconds" type="number" min="60" max="86400" class="input mt-1" /></label>
        <label class="text-xs text-themed-muted">每批实例数<input v-model.number="agentMonitoring.batchSize" type="number" min="1" max="32" class="input mt-1" /></label>
      </div>
      <button class="btn-primary btn-sm" :disabled="networkPolicyLoading" @click="saveAgentMonitoring">保存监测配置</button>
    </div>

    <div class="grid gap-6 xl:grid-cols-[minmax(360px,520px)_1fr]">
      <div class="rounded-xl border p-4 space-y-4" :class="themeStore.isDark ? 'border-gray-800' : 'border-gray-200'">
        <div><h3 class="font-semibold text-themed">新增网络策略</h3><p class="text-xs text-themed-muted mt-1">策略默认关闭；勾选启用后才会由 Agent 强制执行。</p></div>
        <input v-model="networkPolicyForm.name" class="input" placeholder="策略名称" />
        <select v-model="networkPolicyForm.policyType" class="input"><option value="ip_block">阻挡 IP / CIDR</option><option value="dns_lock">强制平台 DNS</option><option value="dns_override">域名劫持 / 屏蔽</option><option value="udp_block">{{ t('admin.hosts.ops.networkPolicyUdpBlock') }}</option><option value="ping_block">{{ t('admin.hosts.ops.networkPolicyPingBlock') }}</option></select>
        <select v-model="networkPolicyForm.targetMode" class="input"><option value="selected">选择实例</option><option value="all_current">当前全部实例</option><option value="all_dynamic">当前及今后全部实例</option></select>
        <div v-if="networkPolicyForm.targetMode === 'selected'" class="max-h-48 overflow-auto rounded-lg border p-2 space-y-1" :class="themeStore.isDark ? 'border-gray-800' : 'border-gray-200'">
          <label v-for="item in networkPolicyInstances" :key="item.id" class="flex items-center gap-2 rounded px-2 py-1 text-sm"><input type="checkbox" :checked="networkPolicyForm.targetInstanceIds.includes(item.id)" @change="toggleNetworkPolicyInstance(item.id)" />{{ item.name }} <span class="text-themed-muted">#{{ item.id }} · {{ item.status }}</span></label>
          <div v-if="!networkPolicyInstances.length" class="text-xs text-themed-muted">当前节点没有可选实例。</div>
        </div>
        <textarea v-if="networkPolicyForm.policyType === 'ip_block'" v-model="networkPolicyForm.cidrs" class="input min-h-24" placeholder="每行或逗号分隔，例如：203.0.113.10&#10;198.51.100.0/24&#10;2001:db8::/32"></textarea>
        <template v-else-if="networkPolicyForm.policyType === 'dns_lock' || networkPolicyForm.policyType === 'dns_override'">
          <input v-model="networkPolicyForm.upstreams" class="input" placeholder="平台 DNS 上游，例如 1.1.1.1, 8.8.8.8" />
          <label v-if="networkPolicyForm.policyType === 'dns_lock'" class="flex items-center gap-2 text-sm"><input v-model="networkPolicyForm.blockDot" type="checkbox" />同时阻挡 DoT（TCP 853）</label>
        </template>
        <template v-if="networkPolicyForm.policyType === 'dns_override'">
          <textarea v-model="networkPolicyForm.domains" class="input min-h-20" placeholder="域名，每行或逗号分隔"></textarea>
          <select v-model="networkPolicyForm.dnsAction" class="input"><option value="address">返回指定 IP</option><option value="nxdomain">返回 NXDOMAIN</option><option value="zero">返回 0.0.0.0 / ::</option></select>
          <input v-if="networkPolicyForm.dnsAction === 'address'" v-model="networkPolicyForm.addresses" class="input" placeholder="目标 IPv4 / IPv6" />
        </template>
        <label class="flex items-center gap-2 text-sm text-red-500"><input v-model="networkPolicyForm.enabled" type="checkbox" />建立后立即启用强制策略</label>
        <button class="btn-primary btn-sm w-full" :disabled="networkPolicyLoading" @click="createNetworkPolicy">建立策略</button>
      </div>

      <div class="rounded-xl border p-4 space-y-3" :class="themeStore.isDark ? 'border-gray-800' : 'border-gray-200'">
        <div class="flex justify-between"><h3 class="font-semibold text-themed">现有策略</h3><button class="btn-ghost btn-sm" @click="loadNetworkPolicyPanel">刷新</button></div>
        <div v-for="policy in networkPolicies" :key="policy.id" class="rounded-xl border p-3 space-y-2" :class="themeStore.isDark ? 'border-gray-800 bg-gray-900' : 'border-gray-200 bg-gray-50'">
          <div class="flex items-start justify-between gap-3"><div><div class="font-medium text-themed">{{ policy.name }}</div><div class="text-xs text-themed-muted">{{ networkPolicyTypeLabel(policy.policyType) }} · {{ policy.targetMode }} · revision {{ policy.revision }}</div></div><span class="badge" :class="policy.applyStatus === 'applied' ? 'badge-success' : policy.applyStatus === 'failed' ? 'badge-danger' : 'badge-warning'">{{ policy.applyStatus }}</span></div>
          <div v-if="policy.applyError" class="text-xs text-red-500 break-all">{{ policy.applyError }}</div>
          <div class="flex gap-2"><button class="btn-secondary btn-sm" @click="toggleNetworkPolicy(policy)">{{ policy.enabled ? '停用并撤销' : '启用' }}</button><button class="btn-danger btn-sm" @click="deleteNetworkPolicy(policy)">删除</button></div>
        </div>
        <div v-if="!networkPolicies.length" class="text-sm text-themed-muted">尚未建立网络策略。</div>
      </div>
    </div>
  </div>
</template>
