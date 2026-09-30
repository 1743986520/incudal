<script setup lang="ts">
// Host Ops 薄型容器:接收 hostId/hostName,展示一级分页(实例操作/实例审查/网络策略),
// 并持有跨面板共享的核心状态(盘点结果、实例选择、操作互斥锁、最近执行记录)。
// 各面板的数据加载与操作逻辑位于对应面板组件内。
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import api from '@/api'
import { useThemeStore } from '@/stores/theme'
import { useToast } from '@/stores/toast'
import HostOpsActionsPanel from '@/components/host/ops/HostOpsActionsPanel.vue'
import HostAuditPanel from '@/components/host/ops/HostAuditPanel.vue'
import HostNetworkPolicyPanel from '@/components/host/ops/HostNetworkPolicyPanel.vue'
import type {
  BaselineSyncResult,
  DiscoverResult,
  NetworkRepairResult,
  OpsActionKey
} from '@/components/host/ops/opsTypes'

defineOptions({
  name: 'HostOpsTab'
})

interface Props {
  hostId: number
  hostName?: string
}

const props = defineProps<Props>()

const { t } = useI18n()
const themeStore = useThemeStore()
const toast = useToast()

const activeOpsMenu = ref<'actions' | 'audit' | 'network'>('actions')

// 跨面板共享核心状态
const loadingAction = ref<OpsActionKey | ''>('')
const lastAction = ref<OpsActionKey | ''>('')
const lastRunAt = ref<string>('')
const discoverResult = ref<DiscoverResult | null>(null)
const baselineResult = ref<BaselineSyncResult | null>(null)
const networkResult = ref<NetworkRepairResult | null>(null)
const selectedManagedDbId = ref<number | null>(null)
let hostGeneration = 0

watch(() => props.hostId, () => {
  hostGeneration += 1
  lastAction.value = ''
  lastRunAt.value = ''
  discoverResult.value = null
  baselineResult.value = null
  networkResult.value = null
  selectedManagedDbId.value = null
}, { flush: 'sync' })

const selectedManaged = computed(() => {
  if (!discoverResult.value || selectedManagedDbId.value === null) return null
  return discoverResult.value.managed.find(item => item.dbId === selectedManagedDbId.value) || null
})

const actionsPanelRef = ref<InstanceType<typeof HostOpsActionsPanel> | null>(null)
const auditPanelRef = ref<InstanceType<typeof HostAuditPanel> | null>(null)

// 操作互斥锁:同一时间只允许一个操作进行中
function beginAction(key: OpsActionKey): boolean {
  if (loadingAction.value) return false
  loadingAction.value = key
  return true
}

function endAction(): void {
  loadingAction.value = ''
}

function touchLastRun(action: OpsActionKey) {
  lastAction.value = action
  lastRunAt.value = new Date().toLocaleString()
}

function selectManaged(dbId: number) {
  selectedManagedDbId.value = dbId
}

async function runDiscover() {
  if (!props.hostId || loadingAction.value) return
  if (!beginAction('discover')) return
  const hostId = props.hostId
  const generation = hostGeneration
  try {
    const result = await api.hosts.opsDiscover(hostId)
    if (hostId !== props.hostId || generation !== hostGeneration) return
    discoverResult.value = result
    if (!selectedManagedDbId.value && result.managed.length > 0) {
      selectedManagedDbId.value = result.managed[0].dbId
    }
    touchLastRun('discover')
    toast.success(t('admin.hosts.ops.runSuccess'))
  } catch (err: any) {
    if (hostId === props.hostId && generation === hostGeneration) {
      toast.error(t('admin.hosts.ops.runFailed') + ': ' + (err?.message || String(err)))
    }
  } finally {
    endAction()
  }
}

async function runBaselineSync() {
  if (!props.hostId || loadingAction.value) return
  if (!beginAction('baseline')) return
  const hostId = props.hostId
  const generation = hostGeneration
  try {
    const result = await api.hosts.opsBaselineSync(hostId)
    if (hostId !== props.hostId || generation !== hostGeneration) return
    baselineResult.value = result
    touchLastRun('baseline')
    toast.success(t('admin.hosts.ops.runSuccess'))
  } catch (err: any) {
    if (hostId === props.hostId && generation === hostGeneration) {
      toast.error(t('admin.hosts.ops.runFailed') + ': ' + (err?.message || String(err)))
    }
  } finally {
    endAction()
  }
}

async function runNetworkRepair() {
  if (!props.hostId || loadingAction.value) return
  if (!beginAction('network')) return
  const hostId = props.hostId
  const generation = hostGeneration
  try {
    const result = await api.hosts.opsNetworkRepair(hostId)
    if (hostId !== props.hostId || generation !== hostGeneration) return
    networkResult.value = result
    touchLastRun('network')
    toast.success(t('admin.hosts.ops.runSuccess'))
  } catch (err: any) {
    if (hostId === props.hostId && generation === hostGeneration) {
      toast.error(t('admin.hosts.ops.runFailed') + ': ' + (err?.message || String(err)))
    }
  } finally {
    endAction()
  }
}

async function refreshLastResult() {
  if (lastAction.value === 'discover') await runDiscover()
  else if (lastAction.value === 'baseline') await runBaselineSync()
  else if (lastAction.value === 'network') await runNetworkRepair()
  else if (lastAction.value === 'preview') await actionsPanelRef.value?.loadPreview()
  else if (lastAction.value === 'instanceSync' || lastAction.value === 'instanceRestart' || lastAction.value === 'instanceDanger') {
    await actionsPanelRef.value?.loadPreview(true)
  }
  else if (lastAction.value === 'auditScan') await auditPanelRef.value?.runAuditScan()
  else if (lastAction.value === 'auditKill') await auditPanelRef.value?.runAuditScan()
}
</script>

<template>
  <div class="space-y-6">
    <div class="card p-5 space-y-4">
      <div>
        <h3 class="text-lg font-semibold text-themed">{{ t('admin.hosts.ops.title') }}</h3>
        <p class="text-sm text-themed-muted mt-1">{{ t('admin.hosts.ops.description') }}</p>
      </div>

      <div class="inline-flex rounded-lg border p-1" :class="themeStore.isDark ? 'border-gray-800 bg-gray-900' : 'border-gray-200 bg-gray-50'">
        <button
          type="button"
          class="px-4 py-2 text-sm rounded-md transition"
          :class="activeOpsMenu === 'actions' ? 'bg-blue-600 text-white' : 'text-themed-muted hover:text-themed'"
          @click="activeOpsMenu = 'actions'"
        >
          {{ t('admin.hosts.ops.actionsTab') }}
        </button>
        <button
          type="button"
          class="px-4 py-2 text-sm rounded-md transition"
          :class="activeOpsMenu === 'audit' ? 'bg-blue-600 text-white' : 'text-themed-muted hover:text-themed'"
          @click="activeOpsMenu = 'audit'"
        >
          {{ t('admin.hosts.ops.auditTab') }}
        </button>
        <button type="button" class="px-4 py-2 text-sm rounded-md transition" :class="activeOpsMenu === 'network' ? 'bg-blue-600 text-white' : 'text-themed-muted hover:text-themed'" @click="activeOpsMenu = 'network'">
          {{ t('admin.hosts.ops.networkPolicyTab') }}
        </button>
      </div>

      <HostNetworkPolicyPanel
        v-show="activeOpsMenu === 'network'"
        :host-id="hostId"
        :active="activeOpsMenu === 'network'"
      />

      <div v-if="activeOpsMenu === 'actions'" class="grid gap-4 lg:grid-cols-3">
        <div class="rounded-xl border p-4 space-y-3" :class="themeStore.isDark ? 'border-gray-800 bg-gray-900/40' : 'border-gray-200 bg-gray-50'">
          <div class="flex items-start justify-between gap-3">
            <div>
              <div class="text-sm font-medium text-themed">{{ t('admin.hosts.ops.discover') }}</div>
              <div class="text-xs text-themed-muted mt-1">{{ t('admin.hosts.ops.discoverHint') }}</div>
            </div>
            <span class="badge badge-info">Incus</span>
          </div>
          <button class="btn-primary btn-sm w-full" :disabled="loadingAction !== ''" @click="runDiscover">
            <span>{{ loadingAction === 'discover' ? '...' : t('admin.hosts.ops.discover') }}</span>
          </button>
        </div>

        <div class="rounded-xl border p-4 space-y-3" :class="themeStore.isDark ? 'border-gray-800 bg-gray-900/40' : 'border-gray-200 bg-gray-50'">
          <div class="flex items-start justify-between gap-3">
            <div>
              <div class="text-sm font-medium text-themed">{{ t('admin.hosts.ops.baselineSync') }}</div>
              <div class="text-xs text-themed-muted mt-1">{{ t('admin.hosts.ops.baselineHint') }}</div>
            </div>
            <span class="badge badge-warning">Safe</span>
          </div>
          <button class="btn-secondary btn-sm w-full" :disabled="loadingAction !== ''" @click="runBaselineSync">
            <span>{{ loadingAction === 'baseline' ? '...' : t('admin.hosts.ops.baselineSync') }}</span>
          </button>
        </div>

        <div class="rounded-xl border p-4 space-y-3" :class="themeStore.isDark ? 'border-gray-800 bg-gray-900/40' : 'border-gray-200 bg-gray-50'">
          <div class="flex items-start justify-between gap-3">
            <div>
              <div class="text-sm font-medium text-themed">{{ t('admin.hosts.ops.networkRepair') }}</div>
              <div class="text-xs text-themed-muted mt-1">{{ t('admin.hosts.ops.networkHint') }}</div>
            </div>
            <span class="badge badge-success">IP</span>
          </div>
          <button class="btn-secondary btn-sm w-full" :disabled="loadingAction !== ''" @click="runNetworkRepair">
            <span>{{ loadingAction === 'network' ? '...' : t('admin.hosts.ops.networkRepair') }}</span>
          </button>
        </div>
      </div>
    </div>

    <HostOpsActionsPanel
      v-show="activeOpsMenu === 'actions'"
      ref="actionsPanelRef"
      :host-id="hostId"
      :active="activeOpsMenu === 'actions'"
      :discover-result="discoverResult"
      :selected-managed="selectedManaged"
      :selected-managed-db-id="selectedManagedDbId"
      :loading-action="loadingAction"
      :last-action="lastAction"
      :last-run-at="lastRunAt"
      :baseline-result="baselineResult"
      :network-result="networkResult"
      :begin-action="beginAction"
      :end-action="endAction"
      :touch-last-run="touchLastRun"
      :run-discover="runDiscover"
      @select-managed="selectManaged"
      @refresh-last-result="refreshLastResult"
    />

    <HostAuditPanel
      v-show="activeOpsMenu === 'audit'"
      ref="auditPanelRef"
      :host-id="hostId"
      :active="activeOpsMenu === 'audit'"
      :discover-result="discoverResult"
      :selected-managed="selectedManaged"
      :selected-managed-db-id="selectedManagedDbId"
      :loading-action="loadingAction"
      :begin-action="beginAction"
      :end-action="endAction"
      :touch-last-run="touchLastRun"
      :run-discover="runDiscover"
      @select-managed="selectManaged"
    />
  </div>
</template>
