<script setup lang="ts">
// 实例操作面板:盘点结果、实例同步/重启、重装/重建危险区、执行结果报告与二次确认弹窗。
// 面板自身负责数据加载与操作;盘点结果与实例选择来自容器,
// 操作互斥锁、最近执行记录与盘点刷新通过函数属性与容器交互。
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import api from '@/api'
import type { SshKey, SystemImage } from '@/types/api'
import { useThemeStore } from '@/stores/theme'
import { useToast } from '@/stores/toast'
import type {
  AvailableInitCommand,
  BaselineSyncResult,
  DiscoverResult,
  InstanceOpsActionResult,
  InstanceOpsPreview,
  NetworkRepairResult,
  OpsActionKey
} from '@/components/host/ops/opsTypes'
import { localizeStatus, localizeType } from '@/components/host/ops/opsDisplay'

defineOptions({
  name: 'HostOpsActionsPanel'
})

const props = defineProps<{
  hostId: number
  active: boolean
  discoverResult: DiscoverResult | null
  selectedManaged: DiscoverResult['managed'][number] | null
  selectedManagedDbId: number | null
  loadingAction: string
  lastAction: OpsActionKey | ''
  lastRunAt: string
  baselineResult: BaselineSyncResult | null
  networkResult: NetworkRepairResult | null
  beginAction: (key: OpsActionKey) => boolean
  endAction: () => void
  touchLastRun: (key: OpsActionKey) => void
  runDiscover: () => Promise<void>
}>()

const emit = defineEmits<{
  'select-managed': [dbId: number]
  'refresh-last-result': []
}>()

const { t } = useI18n()
const themeStore = useThemeStore()
const toast = useToast()

const previewResult = ref<InstanceOpsPreview | null>(null)
const latestInstanceActionResult = ref<InstanceOpsActionResult | null>(null)
let previewGeneration = 0

const currentPreview = computed(() => {
  const preview = previewResult.value
  return preview?.hostId === props.hostId
    && preview.instanceId === props.selectedManagedDbId
    && preview.instanceId === props.selectedManaged?.dbId
    ? preview
    : null
})

function isCurrentSelection(generation: number, hostId: number, dbId: number): boolean {
  return previewGeneration === generation && props.hostId === hostId && props.selectedManagedDbId === dbId
}

const dangerousAction = ref<'rebuild' | 'recreate'>('recreate')
const selectedImageId = ref<number | null>(null)
const selectedSshKeyId = ref<number | null>(null)
const selectedCustomInitCommandIds = ref<number[]>([])
const confirmationText = ref('')
const riskAccepted = ref(false)

// 镜像下拉数据
const availableImages = ref<SystemImage[]>([])
const loadingImages = ref(false)
const availableSshKeys = ref<SshKey[]>([])
const loadingSshKeys = ref(false)
const availableInitCommands = ref<AvailableInitCommand[]>([])
const loadingInitCommands = ref(false)

// 二次确认弹窗
const showDangerConfirmModal = ref(false)
const dangerConfirmStep = ref(1) // 1 = 第一次确认, 2 = 第二次确认

const hasResult = computed(() => {
  return !!props.discoverResult || !!props.baselineResult || !!props.networkResult || !!currentPreview.value || !!latestInstanceActionResult.value
})

const confirmationExpectedText = computed(() => currentPreview.value?.incusId || '')

// 当前选中镜像的 remoteAlias
const selectedImage = computed(() => {
  if (!selectedImageId.value) return null
  return availableImages.value.find(img => img.id === selectedImageId.value) || null
})

const selectedImageDistro = computed(() => {
  const alias = selectedImage.value?.remoteAlias || ''
  if (!alias) return ''
  return getImageDistroFromAlias(alias)
})

const selectedImageAlias = computed(() => {
  return selectedImage.value?.remoteAlias || ''
})

const isDangerFormValid = computed(() => {
  const preview = currentPreview.value
  if (!preview) return false
  if (dangerousAction.value === 'rebuild' ? !preview.canRebuild : !preview.canRecreate) return false
  if (!selectedImageId.value) return false
  if (!riskAccepted.value) return false
  return confirmationText.value.trim() === confirmationExpectedText.value
})

// 精简镜像名称展示：只显示系统名，不显示 remoteAlias
function simplifyImageLabel(image: SystemImage): string {
  // 优先使用 name 字段
  const raw = (image.name || image.remoteAlias || '').trim()
  if (!raw) return `Image #${image.id}`
  // 去除 remoteAlias 格式中的路径前缀（如 images:debian/12/cloud → Debian 12）
  return raw
    .replace(/\s*\(.*?\)\s*$/, '') // 去掉括号内容（如 "(images:debian/12/cloud)"）
    .trim()
}

// 建议动作中文映射
function localizeSuggestedAction(action: string): string {
  const map: Record<string, string> = {
    sync: '同步实例',
    restart: '重启实例',
    rebuild: '重装实例',
    recreate: '重建实例',
    none: '无需操作',
  }
  return map[action] || action
}

function resetDangerState() {
  dangerousAction.value = 'recreate'
  selectedImageId.value = null
  selectedSshKeyId.value = null
  selectedCustomInitCommandIds.value = []
  confirmationText.value = ''
  riskAccepted.value = false
  showDangerConfirmModal.value = false
  dangerConfirmStep.value = 1
}

watch([() => props.hostId, () => props.selectedManagedDbId], () => {
  // 切换目标后立即清除旧预览；未完成的请求也不能再写回新目标的面板。
  previewGeneration += 1
  previewResult.value = null
  latestInstanceActionResult.value = null
  availableImages.value = []
  availableSshKeys.value = []
  availableInitCommands.value = []
  loadingImages.value = false
  loadingSshKeys.value = false
  loadingInitCommands.value = false
  resetDangerState()
}, { flush: 'sync' })

function getImageDistroFromAlias(imageAlias: string): string {
  const alias = imageAlias.toLowerCase()

  if (alias.includes('ubuntu')) return 'ubuntu'
  if (alias.includes('debian') || alias.includes('kali')) return 'debian'
  if (alias.includes('alpine')) return 'alpine'
  if (alias.includes('arch')) return 'arch'
  if (alias.includes('opensuse') || alias.includes('suse') || alias.includes('tumbleweed') || alias.includes('leap')) return 'suse'
  if (alias.includes('alma') || alias.includes('rocky') || alias.includes('oracle') || alias.includes('centos') || alias.includes('rhel') || alias.includes('fedora')) return 'rhel'

  return 'other'
}

function toggleInitCommand(cmdId: number): void {
  const next = [...selectedCustomInitCommandIds.value]
  const index = next.indexOf(cmdId)
  if (index >= 0) next.splice(index, 1)
  else next.push(cmdId)
  selectedCustomInitCommandIds.value = next
}

function getDistroName(distro: string): string {
  const key = `extensions.initCommands.distroNames.${distro}`
  const translated = t(key)
  return translated !== key ? translated : distro
}

function formatValue(value: string | null | undefined) {
  return value || '-'
}

function resultTitle() {
  if (props.lastAction === 'discover') return t('admin.hosts.ops.resultInventory')
  if (props.lastAction === 'baseline') return t('admin.hosts.ops.resultBaseline')
  if (props.lastAction === 'network') return t('admin.hosts.ops.resultNetwork')
  if (props.lastAction === 'preview') return t('admin.hosts.ops.resultPreview')
  if (props.lastAction === 'instanceSync') return t('admin.hosts.ops.resultInstanceSync')
  if (props.lastAction === 'instanceRestart') return t('admin.hosts.ops.resultInstanceRestart')
  if (props.lastAction === 'instanceDanger') return t('admin.hosts.ops.resultDanger')
  if (props.lastAction === 'auditScan') return '实例审查结果'
  if (props.lastAction === 'auditKill') return '手动处置结果'
  return t('admin.hosts.ops.sectionReport')
}

async function loadImages(generation: number, hostId: number, dbId: number) {
  loadingImages.value = true
  try {
    const res = await api.images.getSystemImages(undefined, undefined, hostId)
    if (!isCurrentSelection(generation, hostId, dbId)) return
    availableImages.value = res.images.filter(img => !img.hidden)
    // 若已有 previewResult 的 imageAlias，尝试自动匹配
    if (currentPreview.value?.imageAlias && !selectedImageId.value) {
      const matched = availableImages.value.find(img => img.remoteAlias === currentPreview.value!.imageAlias)
      if (matched) selectedImageId.value = matched.id
    }
  } catch {
    // 静默处理，用户可手动选择
  } finally {
    if (isCurrentSelection(generation, hostId, dbId)) loadingImages.value = false
  }
}

async function loadOperationSshKeys(generation: number, hostId: number, dbId: number) {
  loadingSshKeys.value = true
  try {
    const res = await api.hosts.opsInstanceSshKeys(hostId, dbId)
    if (!isCurrentSelection(generation, hostId, dbId)) return
    availableSshKeys.value = res.keys || []
    if (selectedSshKeyId.value && !availableSshKeys.value.some(key => key.id === selectedSshKeyId.value)) {
      selectedSshKeyId.value = null
    }
  } catch {
    if (isCurrentSelection(generation, hostId, dbId)) availableSshKeys.value = []
  } finally {
    if (isCurrentSelection(generation, hostId, dbId)) loadingSshKeys.value = false
  }
}

async function loadOperationInitCommands(generation: number, hostId: number, dbId: number) {
  const distro = selectedImageDistro.value
  if (!distro) {
    availableInitCommands.value = []
    selectedCustomInitCommandIds.value = []
    loadingInitCommands.value = false
    return
  }
  loadingInitCommands.value = true
  try {
    const res = await api.hosts.opsInstanceInitCommands(hostId, dbId, distro)
    if (!isCurrentSelection(generation, hostId, dbId) || selectedImageDistro.value !== distro) return
    availableInitCommands.value = res.commands || []
    const availableIds = new Set(availableInitCommands.value.map(cmd => cmd.id))
    selectedCustomInitCommandIds.value = selectedCustomInitCommandIds.value.filter(id => availableIds.has(id))
  } catch {
    if (isCurrentSelection(generation, hostId, dbId) && selectedImageDistro.value === distro) {
      availableInitCommands.value = []
      selectedCustomInitCommandIds.value = []
    }
  } finally {
    if (isCurrentSelection(generation, hostId, dbId) && selectedImageDistro.value === distro) loadingInitCommands.value = false
  }
}

watch(selectedImageId, () => {
  if (!currentPreview.value || props.selectedManagedDbId === null) return
  void loadOperationInitCommands(previewGeneration, props.hostId, props.selectedManagedDbId)
})

async function loadPreview(preserveActionResult = false) {
  if (!props.hostId || !props.selectedManaged) return
  if (!props.beginAction('preview')) return
  const hostId = props.hostId
  const dbId = props.selectedManaged.dbId
  const generation = ++previewGeneration
  previewResult.value = null
  if (!preserveActionResult) latestInstanceActionResult.value = null
  availableImages.value = []
  availableSshKeys.value = []
  availableInitCommands.value = []
  loadingImages.value = false
  loadingSshKeys.value = false
  loadingInitCommands.value = false
  resetDangerState()
  try {
    const preview = await api.hosts.opsInstancePreview(hostId, dbId)
    if (!isCurrentSelection(generation, hostId, dbId) || preview.hostId !== hostId || preview.instanceId !== dbId) return
    previewResult.value = preview
    if (!preserveActionResult) props.touchLastRun('preview')
    // 加载当前节点可用镜像
    await loadImages(generation, hostId, dbId)
    if (!isCurrentSelection(generation, hostId, dbId)) return
    await Promise.all([
      loadOperationSshKeys(generation, hostId, dbId),
      loadOperationInitCommands(generation, hostId, dbId)
    ])
  } catch (err: any) {
    if (isCurrentSelection(generation, hostId, dbId)) {
      toast.error(t('admin.hosts.ops.runFailed') + ': ' + (err?.message || String(err)))
    }
  } finally {
    props.endAction()
  }
}

async function runInstanceSync() {
  if (!currentPreview.value?.canSync || !props.selectedManaged) return
  if (!props.beginAction('instanceSync')) return
  const hostId = props.hostId
  const dbId = props.selectedManaged.dbId
  const generation = previewGeneration
  try {
    const result = await api.hosts.opsInstanceSync(hostId, dbId)
    toast.success(t('admin.hosts.ops.runSuccess'))
    if (!isCurrentSelection(generation, hostId, dbId)) return
    latestInstanceActionResult.value = result
    props.touchLastRun('instanceSync')
    props.endAction()
    await loadPreview(true)
  } catch (err: any) {
    toast.error(t('admin.hosts.ops.runFailed') + ': ' + (err?.message || String(err)))
  } finally {
    props.endAction()
  }
}

async function runInstanceRestart(force: boolean) {
  const preview = currentPreview.value
  if (!preview || !props.selectedManaged || (force ? !preview.canForceRestart : !preview.canRestart)) return
  if (!props.beginAction('instanceRestart')) return
  const hostId = props.hostId
  const dbId = props.selectedManaged.dbId
  const generation = previewGeneration
  try {
    const result = await api.hosts.opsInstanceRestart(hostId, dbId, force)
    toast.success(t('admin.hosts.ops.runSuccess'))
    if (!isCurrentSelection(generation, hostId, dbId)) return
    latestInstanceActionResult.value = result
    props.touchLastRun('instanceRestart')
    props.endAction()
    await loadPreview(true)
  } catch (err: any) {
    toast.error(t('admin.hosts.ops.runFailed') + ': ' + (err?.message || String(err)))
  } finally {
    props.endAction()
  }
}

// 第一步：点击"执行高风险动作"弹出二次确认弹窗
function openDangerConfirm() {
  if (!isDangerFormValid.value) return
  dangerConfirmStep.value = 1
  showDangerConfirmModal.value = true
}

// 第二步：第一次确认后进入第二次确认
function advanceDangerConfirm() {
  dangerConfirmStep.value = 2
}

// 第三步：第二次确认后真正执行
async function executeDangerConfirmed() {
  showDangerConfirmModal.value = false
  dangerConfirmStep.value = 1
  await runDangerousAction()
}

function cancelDangerConfirm() {
  showDangerConfirmModal.value = false
  dangerConfirmStep.value = 1
}

async function runDangerousAction() {
  if (!props.selectedManaged || !isDangerFormValid.value) return
  if (!props.beginAction('instanceDanger')) return
  const hostId = props.hostId
  const dbId = props.selectedManaged.dbId
  const generation = previewGeneration
  try {
    const result = await api.hosts.opsInstanceDangerousAction(hostId, dbId, {
      action: dangerousAction.value,
      imageAlias: selectedImageAlias.value,
      sshKeyId: selectedSshKeyId.value || undefined,
      customInitCommandIds: selectedCustomInitCommandIds.value.length > 0 ? selectedCustomInitCommandIds.value : undefined,
      confirmationText: confirmationText.value.trim(),
      riskConfirmed: riskAccepted.value
    })
    toast.success(t('admin.hosts.ops.runSuccess'))
    if (!isCurrentSelection(generation, hostId, dbId)) return
    latestInstanceActionResult.value = result
    props.touchLastRun('instanceDanger')
    resetDangerState()
    props.endAction()
    await props.runDiscover()
    if (isCurrentSelection(generation, hostId, dbId)) await loadPreview(true)
    if (isCurrentSelection(generation, hostId, dbId)) props.touchLastRun('instanceDanger')
  } catch (err: any) {
    toast.error(t('admin.hosts.ops.runFailed') + ': ' + (err?.message || String(err)))
  } finally {
    props.endAction()
  }
}

defineExpose({
  loadPreview
})
</script>

<template>
  <div class="space-y-6">
    <div v-if="discoverResult" class="card p-5 space-y-4">
      <div class="flex items-center justify-between gap-3 flex-wrap">
        <div>
          <h3 class="text-base font-semibold text-themed">{{ t('admin.hosts.ops.sectionInventory') }}</h3>
          <p class="text-xs text-themed-muted mt-1">{{ t('admin.hosts.ops.selectInstanceHint') }}</p>
        </div>
      </div>

      <div class="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        <div class="rounded-xl p-4" :class="themeStore.isDark ? 'bg-gray-900' : 'bg-gray-50'">
          <div class="text-xs text-themed-muted">{{ t('admin.hosts.ops.totalIncus') }}</div>
          <div class="text-2xl font-semibold mt-1 text-themed">{{ discoverResult.summary.totalIncus }}</div>
        </div>
        <div class="rounded-xl p-4" :class="themeStore.isDark ? 'bg-gray-900' : 'bg-gray-50'">
          <div class="text-xs text-themed-muted">{{ t('admin.hosts.ops.totalDb') }}</div>
          <div class="text-2xl font-semibold mt-1 text-themed">{{ discoverResult.summary.totalDb }}</div>
        </div>
        <div class="rounded-xl p-4" :class="themeStore.isDark ? 'bg-gray-900' : 'bg-gray-50'">
          <div class="text-xs text-themed-muted">{{ t('admin.hosts.ops.managedCount') }}</div>
          <div class="text-2xl font-semibold mt-1 text-themed">{{ discoverResult.summary.managedCount }}</div>
        </div>
        <div class="rounded-xl p-4" :class="themeStore.isDark ? 'bg-gray-900' : 'bg-gray-50'">
          <div class="text-xs text-themed-muted">{{ t('admin.hosts.ops.orphanedCount') }}</div>
          <div class="text-2xl font-semibold mt-1 text-themed">{{ discoverResult.summary.orphanedCount }}</div>
        </div>
        <div class="rounded-xl p-4" :class="themeStore.isDark ? 'bg-gray-900' : 'bg-gray-50'">
          <div class="text-xs text-themed-muted">{{ t('admin.hosts.ops.missingCount') }}</div>
          <div class="text-2xl font-semibold mt-1 text-themed">{{ discoverResult.summary.missingCount }}</div>
        </div>
      </div>

      <div class="grid gap-4 xl:grid-cols-3">
        <div class="rounded-xl border p-4 space-y-3" :class="themeStore.isDark ? 'border-gray-800' : 'border-gray-200'">
          <div class="font-medium text-themed">{{ t('admin.hosts.ops.managed') }}</div>
          <div v-if="discoverResult.managed.length" class="space-y-2 max-h-96 overflow-auto">
            <button
              v-for="item in discoverResult.managed"
              :key="`${item.dbId}-${item.incusName}`"
              type="button"
              class="w-full rounded-lg px-3 py-2 text-left text-sm border transition"
              :class="selectedManagedDbId === item.dbId
                ? (themeStore.isDark ? 'border-blue-500 bg-blue-500/10' : 'border-blue-500 bg-blue-50')
                : (themeStore.isDark ? 'border-gray-800 bg-gray-900 hover:border-gray-700' : 'border-gray-200 bg-gray-50 hover:border-gray-300')"
              @click="emit('select-managed', item.dbId)"
            >
              <div class="font-medium text-themed">{{ item.incusName }}</div>
              <div class="text-xs text-themed-muted mt-1">
                {{ t('admin.hosts.ops.instanceType') }}: {{ localizeType(item.incusType) }} · {{ t('admin.hosts.ops.incusStatus') }}: {{ localizeStatus(item.incusStatus) }} · {{ t('admin.hosts.ops.dbStatus') }}: {{ localizeStatus(item.dbStatus) }} · 用户 ID: {{ item.userId }}
              </div>
            </button>
          </div>
          <div v-else class="text-sm text-themed-muted">{{ t('admin.hosts.ops.noManaged') }}</div>
        </div>

        <div class="rounded-xl border p-4" :class="themeStore.isDark ? 'border-gray-800' : 'border-gray-200'">
          <div class="font-medium text-themed mb-3">{{ t('admin.hosts.ops.orphaned') }}</div>
          <div v-if="discoverResult.orphaned.length" class="space-y-2 max-h-96 overflow-auto">
            <div v-for="item in discoverResult.orphaned" :key="item.incusName" class="rounded-lg px-3 py-2 text-sm" :class="themeStore.isDark ? 'bg-gray-900' : 'bg-gray-50'">
              <div class="font-medium text-themed">{{ item.incusName }}</div>
              <div class="text-xs text-themed-muted mt-1">{{ t('admin.hosts.ops.instanceType') }}: {{ localizeType(item.incusType) }} · {{ t('admin.hosts.ops.incusStatus') }}: {{ localizeStatus(item.incusStatus) }}</div>
            </div>
          </div>
          <div v-else class="text-sm text-themed-muted">{{ t('admin.hosts.ops.noOrphaned') }}</div>
        </div>

        <div class="rounded-xl border p-4" :class="themeStore.isDark ? 'border-gray-800' : 'border-gray-200'">
          <div class="font-medium text-themed mb-3">{{ t('admin.hosts.ops.missing') }}</div>
          <div v-if="discoverResult.missing.length" class="space-y-2 max-h-96 overflow-auto">
            <div v-for="item in discoverResult.missing" :key="`${item.dbId}-${item.incusId}`" class="rounded-lg px-3 py-2 text-sm" :class="themeStore.isDark ? 'bg-gray-900' : 'bg-gray-50'">
              <div class="font-medium text-themed">{{ item.dbName }}</div>
              <div class="text-xs text-themed-muted mt-1">ID #{{ item.dbId }} · Incus: {{ item.incusId }} · {{ t('admin.hosts.ops.dbStatus') }}: {{ item.dbStatus }}</div>
            </div>
          </div>
          <div v-else class="text-sm text-themed-muted">{{ t('admin.hosts.ops.noMissing') }}</div>
        </div>
      </div>
    </div>

    <div v-if="selectedManaged" class="grid gap-6 xl:grid-cols-2">
      <div class="card p-5 space-y-4">
        <div class="flex items-center justify-between gap-3 flex-wrap">
          <div>
            <h3 class="text-base font-semibold text-themed">{{ t('admin.hosts.ops.instancePanel') }}</h3>
            <p class="text-xs text-themed-muted mt-1">{{ selectedManaged.incusName }} · #{{ selectedManaged.dbId }}</p>
          </div>
          <button class="btn-ghost btn-sm" :disabled="loadingAction !== ''" @click="loadPreview()">{{ t('admin.hosts.ops.loadPreview') }}</button>
        </div>

        <div v-if="currentPreview" class="rounded-xl p-4 space-y-2" :class="themeStore.isDark ? 'bg-gray-900' : 'bg-gray-50'">
          <div class="text-sm text-themed"><strong>{{ t('admin.hosts.ops.dbStatus') }}:</strong> {{ localizeStatus(currentPreview.instanceStatus) }}</div>
          <div class="text-sm text-themed"><strong>{{ t('admin.hosts.ops.suggestedAction') }}:</strong> {{ localizeSuggestedAction(currentPreview.risk.suggestedAction) }}</div>
          <div class="text-sm text-themed"><strong>{{ t('admin.hosts.ops.activeTask') }}:</strong> {{ currentPreview.activeTask ? `${currentPreview.activeTask.taskType} #${currentPreview.activeTask.id}` : '-' }}</div>
          <ul class="text-xs text-themed-muted list-disc pl-5 space-y-1">
            <li v-for="note in currentPreview.risk.notes" :key="note">{{ note }}</li>
          </ul>
        </div>

        <div class="grid gap-3 sm:grid-cols-3">
          <button class="btn-secondary btn-sm" :disabled="loadingAction !== '' || !currentPreview?.canSync" @click="runInstanceSync">{{ t('admin.hosts.ops.syncInstance') }}</button>
          <button class="btn-secondary btn-sm" :disabled="loadingAction !== '' || !currentPreview?.canRestart" @click="runInstanceRestart(false)">{{ t('admin.hosts.ops.safeRestart') }}</button>
          <button class="btn-secondary btn-sm" :disabled="loadingAction !== '' || !currentPreview?.canForceRestart" @click="runInstanceRestart(true)">{{ t('admin.hosts.ops.forceRestart') }}</button>
        </div>
      </div>

      <div class="card p-5 space-y-4">
        <div>
          <h3 class="text-base font-semibold text-themed">{{ t('admin.hosts.ops.dangerZone') }}</h3>
          <p class="text-xs text-themed-muted mt-1">{{ t('admin.hosts.ops.dangerHint') }}</p>
        </div>

        <div v-if="currentPreview" class="space-y-4">
          <div class="grid gap-3 sm:grid-cols-2">
            <label class="rounded-xl border p-3 cursor-pointer" :class="themeStore.isDark ? 'border-gray-800 bg-gray-900' : 'border-gray-200 bg-gray-50'">
              <input v-model="dangerousAction" type="radio" class="mr-2" value="rebuild" :disabled="!currentPreview.canRebuild" />
              {{ t('admin.hosts.ops.rebuild') }}
            </label>
            <label class="rounded-xl border p-3 cursor-pointer" :class="themeStore.isDark ? 'border-gray-800 bg-gray-900' : 'border-gray-200 bg-gray-50'">
              <input v-model="dangerousAction" type="radio" class="mr-2" value="recreate" :disabled="!currentPreview.canRecreate" />
              {{ t('admin.hosts.ops.recreate') }}
            </label>
          </div>

          <!-- 镜像选择下拉 -->
          <div>
            <label class="block text-xs text-themed-muted mb-1.5">{{ t('admin.hosts.ops.selectImage') }}</label>
            <div v-if="loadingImages" class="text-xs text-themed-muted">{{ t('admin.hosts.ops.loadingImages') }}</div>
            <select
              v-else
              v-model="selectedImageId"
              class="input"
            >
              <option :value="null" disabled>{{ t('admin.hosts.ops.imagePlaceholder') }}</option>
              <option v-for="img in availableImages" :key="img.id" :value="img.id">
                {{ simplifyImageLabel(img) }}
              </option>
            </select>
            <div v-if="availableImages.length === 0 && !loadingImages" class="text-xs text-themed-muted mt-1">
              {{ t('admin.hosts.ops.noImagesAvailable') }}
            </div>
          </div>

          <!-- 可选恢复参数 -->
          <div>
            <label class="block text-xs text-themed-muted mb-1.5">{{ t('admin.hosts.ops.selectSshKey') }}</label>
            <div v-if="loadingSshKeys" class="text-xs text-themed-muted">{{ t('admin.hosts.ops.loadingSshKeys') }}</div>
            <select v-else v-model="selectedSshKeyId" class="input">
              <option :value="null">{{ t('admin.hosts.ops.sshKeyPlaceholder') }}</option>
              <option v-for="key in availableSshKeys" :key="key.id" :value="key.id">
                {{ key.name }}{{ key.fingerprint ? ` (${key.fingerprint})` : '' }}
              </option>
            </select>
            <div class="text-xs text-themed-muted mt-1">
              {{ availableSshKeys.length === 0 && !loadingSshKeys ? t('admin.hosts.ops.noSshKeysAvailable') : t('admin.hosts.ops.sshKeyOptionalHint') }}
            </div>
          </div>

          <div>
            <label class="block text-xs text-themed-muted mb-1.5">{{ t('admin.hosts.ops.selectInitCommands') }}</label>
            <div v-if="loadingInitCommands" class="text-xs text-themed-muted">{{ t('admin.hosts.ops.loadingInitCommands') }}</div>
            <div v-else-if="availableInitCommands.length > 0" class="space-y-2 max-h-48 overflow-auto rounded-xl border p-2" :class="themeStore.isDark ? 'border-gray-800' : 'border-gray-200'">
              <label
                v-for="cmd in availableInitCommands"
                :key="cmd.id"
                class="flex items-start gap-3 rounded-lg px-3 py-2 text-sm cursor-pointer transition"
                :class="selectedCustomInitCommandIds.includes(cmd.id)
                  ? (themeStore.isDark ? 'bg-blue-500/10' : 'bg-blue-50')
                  : (themeStore.isDark ? 'hover:bg-gray-800' : 'hover:bg-gray-50')"
              >
                <input
                  type="checkbox"
                  class="mt-0.5 rounded"
                  :checked="selectedCustomInitCommandIds.includes(cmd.id)"
                  @change="toggleInitCommand(cmd.id)"
                />
                <span class="min-w-0 flex-1">
                  <span class="block font-medium text-themed">{{ cmd.name }}</span>
                  <span class="block text-xs text-themed-muted mt-0.5">
                    {{ t('extensions.initCommands.lineCount', { count: cmd.commandLineCount }) }}
                    <span v-if="cmd.distros.length"> · {{ cmd.distros.map(getDistroName).join(', ') }}</span>
                  </span>
                  <span v-if="cmd.description" class="block text-xs text-themed-muted mt-0.5 truncate">{{ cmd.description }}</span>
                </span>
              </label>
            </div>
            <div v-else class="text-xs text-themed-muted">{{ t('admin.hosts.ops.noInitCommandsAvailable') }}</div>
            <div class="text-xs text-themed-muted mt-1">{{ t('admin.hosts.ops.optionalField') }}</div>
          </div>

          <div class="rounded-xl border p-4 space-y-3" :class="themeStore.isDark ? 'border-red-900 bg-red-950/20' : 'border-red-200 bg-red-50'">
            <div class="text-sm font-medium text-red-500">{{ t('admin.hosts.ops.confirmDangerTitle') }}</div>
            <label class="flex items-start gap-2 text-sm text-themed">
              <input v-model="riskAccepted" type="checkbox" class="mt-0.5" />
              <span>{{ t('admin.hosts.ops.riskCheckbox') }}</span>
            </label>
            <div>
              <label class="block text-xs text-themed-muted mb-1.5">{{ t('admin.hosts.ops.confirmTextHint') }}</label>
              <input v-model="confirmationText" type="text" class="input" :placeholder="confirmationExpectedText" />
            </div>
            <div class="flex justify-end">
              <button
                class="btn-danger btn-sm"
                type="button"
                :disabled="loadingAction !== '' || !isDangerFormValid"
                @click="openDangerConfirm"
              >
                {{ t('admin.hosts.ops.executeDangerAction') }}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="card p-5 space-y-4">
      <div class="flex items-center justify-between gap-3 flex-wrap">
        <div>
          <h3 class="text-base font-semibold text-themed">{{ resultTitle() }}</h3>
          <p v-if="lastRunAt" class="text-xs text-themed-muted mt-1">{{ t('admin.hosts.ops.lastRunAt') }}：{{ lastRunAt }}</p>
        </div>
        <button class="btn-ghost btn-sm" :disabled="!lastAction || loadingAction !== ''" @click="$emit('refresh-last-result')">{{ t('admin.hosts.ops.refresh') }}</button>
      </div>

      <template v-if="!hasResult">
        <div class="rounded-xl border border-dashed p-8 text-center text-sm text-themed-muted" :class="themeStore.isDark ? 'border-gray-800' : 'border-gray-200'">
          {{ t('admin.hosts.ops.empty') }}
        </div>
      </template>

      <template v-else>
        <div v-if="baselineResult" class="grid gap-3 md:grid-cols-2 xl:grid-cols-5">
          <div class="rounded-xl p-4" :class="themeStore.isDark ? 'bg-gray-900' : 'bg-gray-50'">
            <div class="text-xs text-themed-muted">已用 CPU</div>
            <div class="text-xl font-semibold mt-1 text-themed">{{ baselineResult.resources.cpuUsed }}</div>
          </div>
          <div class="rounded-xl p-4" :class="themeStore.isDark ? 'bg-gray-900' : 'bg-gray-50'">
            <div class="text-xs text-themed-muted">已用内存</div>
            <div class="text-xl font-semibold mt-1 text-themed">{{ baselineResult.resources.memoryUsed }}</div>
          </div>
          <div class="rounded-xl p-4" :class="themeStore.isDark ? 'bg-gray-900' : 'bg-gray-50'">
            <div class="text-xs text-themed-muted">已用磁盘</div>
            <div class="text-xl font-semibold mt-1 text-themed">{{ baselineResult.resources.diskUsed }}</div>
          </div>
          <div class="rounded-xl p-4" :class="themeStore.isDark ? 'bg-gray-900' : 'bg-gray-50'">
            <div class="text-xs text-themed-muted">{{ t('admin.hosts.ops.synced') }}</div>
            <div class="text-xl font-semibold mt-1 text-themed">{{ baselineResult.instanceSync.synced }} / {{ baselineResult.instanceSync.total }}</div>
          </div>
          <div class="rounded-xl p-4" :class="themeStore.isDark ? 'bg-gray-900' : 'bg-gray-50'">
            <div class="text-xs text-themed-muted">{{ t('admin.hosts.ops.changes') }}</div>
            <div class="text-xl font-semibold mt-1 text-themed">{{ baselineResult.instanceSync.ipChanged }}</div>
          </div>
        </div>

        <div v-if="networkResult" class="overflow-x-auto rounded-xl border" :class="themeStore.isDark ? 'border-gray-800' : 'border-gray-200'">
          <table class="min-w-full text-sm">
            <thead :class="themeStore.isDark ? 'bg-gray-900' : 'bg-gray-50'">
              <tr>
                <th class="px-4 py-3 text-left font-medium text-themed">ID</th>
                <th class="px-4 py-3 text-left font-medium text-themed">{{ t('admin.hosts.ops.instanceName') }}</th>
                <th class="px-4 py-3 text-left font-medium text-themed">{{ t('admin.hosts.ops.dbStatus') }}</th>
                <th class="px-4 py-3 text-left font-medium text-themed">{{ t('admin.hosts.ops.ipv4') }}</th>
                <th class="px-4 py-3 text-left font-medium text-themed">{{ t('admin.hosts.ops.ipv6') }}</th>
                <th class="px-4 py-3 text-left font-medium text-themed">{{ t('admin.hosts.ops.details') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in networkResult.results" :key="row.id" class="border-t" :class="themeStore.isDark ? 'border-gray-800' : 'border-gray-200'">
                <td class="px-4 py-3 text-themed">{{ row.id }}</td>
                <td class="px-4 py-3 text-themed">{{ row.name }}</td>
                <td class="px-4 py-3 text-themed">{{ row.newStatus || row.oldStatus || '-' }}</td>
                <td class="px-4 py-3 text-themed-muted">{{ row.ipv4Changed ? `${formatValue(row.oldIpv4)} → ${formatValue(row.newIpv4)}` : '-' }}</td>
                <td class="px-4 py-3 text-themed-muted">{{ row.ipv6Changed ? `${formatValue(row.oldIpv6)} → ${formatValue(row.newIpv6)}` : '-' }}</td>
                <td class="px-4 py-3">
                  <span v-if="row.success" class="text-xs text-themed-muted">{{ row.statusChanged ? `${formatValue(row.oldStatus)} → ${formatValue(row.newStatus)}` : '-' }}</span>
                  <span v-else class="text-xs text-red-500">{{ row.error }}</span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <div v-if="latestInstanceActionResult" class="rounded-xl border p-4 text-sm" :class="themeStore.isDark ? 'border-gray-800 bg-gray-900' : 'border-gray-200 bg-gray-50'">
          <div class="font-medium text-themed mb-2">{{ t('admin.hosts.ops.latestInstanceAction') }}</div>
          <div class="space-y-1 text-themed-muted">
            <div v-if="latestInstanceActionResult.message">{{ latestInstanceActionResult.message }}</div>
            <div v-if="latestInstanceActionResult.taskId">Task #{{ latestInstanceActionResult.taskId }}</div>
            <div v-if="latestInstanceActionResult.currentStatus">{{ t('admin.hosts.ops.dbStatus') }}: {{ latestInstanceActionResult.currentStatus }}</div>
            <div v-if="latestInstanceActionResult.from || latestInstanceActionResult.to">{{ formatValue(latestInstanceActionResult.from) }} → {{ formatValue(latestInstanceActionResult.to) }}</div>
          </div>
        </div>
      </template>
    </div>

    <!-- 二次确认弹窗 -->
    <div
      v-if="showDangerConfirmModal"
      class="fixed inset-0 z-50 flex items-center justify-center p-4"
    >
      <div class="absolute inset-0 bg-black/60 backdrop-blur-sm" @click="cancelDangerConfirm" />
      <div
        class="relative w-full max-w-md rounded-2xl p-6 space-y-5 shadow-2xl"
        :class="themeStore.isDark ? 'bg-gray-900 border border-gray-800' : 'bg-white border border-gray-200'"
      >
        <!-- 警告图标 -->
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-full bg-red-500/15 flex items-center justify-center flex-shrink-0">
            <svg class="w-5 h-5 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
            </svg>
          </div>
          <div>
            <div class="font-semibold text-themed">
              {{ dangerConfirmStep === 1 ? t('admin.hosts.ops.dangerConfirm1Title') : t('admin.hosts.ops.dangerConfirm2Title') }}
            </div>
            <div class="text-xs text-themed-muted mt-0.5">
              {{ dangerConfirmStep === 1 ? t('admin.hosts.ops.dangerConfirm1Hint') : t('admin.hosts.ops.dangerConfirm2Hint') }}
            </div>
          </div>
        </div>

        <!-- 操作摘要 -->
        <div class="rounded-xl p-4 space-y-1.5 text-sm" :class="themeStore.isDark ? 'bg-gray-800' : 'bg-gray-50'">
          <div class="flex items-center justify-between">
            <span class="text-themed-muted">{{ t('admin.hosts.ops.instanceName') }}</span>
            <span class="font-mono font-medium text-themed">{{ currentPreview?.instanceName }}</span>
          </div>
          <div class="flex items-center justify-between">
            <span class="text-themed-muted">{{ t('admin.hosts.ops.dangerActionType') }}</span>
            <span class="font-medium text-red-500">{{ dangerousAction === 'rebuild' ? t('admin.hosts.ops.rebuild') : t('admin.hosts.ops.recreate') }}</span>
          </div>
          <div class="flex items-center justify-between">
            <span class="text-themed-muted">{{ t('admin.hosts.ops.selectImage') }}</span>
            <span class="text-themed text-xs font-mono">{{ selectedImageAlias }}</span>
          </div>
        </div>

        <!-- 步骤指示 -->
        <div class="flex items-center gap-2">
          <div class="flex-1 h-1.5 rounded-full" :class="dangerConfirmStep >= 1 ? 'bg-red-500' : (themeStore.isDark ? 'bg-gray-700' : 'bg-gray-200')" />
          <div class="flex-1 h-1.5 rounded-full" :class="dangerConfirmStep >= 2 ? 'bg-red-500' : (themeStore.isDark ? 'bg-gray-700' : 'bg-gray-200')" />
        </div>
        <div class="text-xs text-themed-muted text-center">
          {{ t('admin.hosts.ops.dangerConfirmStep', { step: dangerConfirmStep, total: 2 }) }}
        </div>

        <!-- 操作按钮 -->
        <div class="flex gap-3 justify-end">
          <button class="btn-ghost btn-sm" @click="cancelDangerConfirm">{{ t('common.cancel') }}</button>
          <button
            v-if="dangerConfirmStep === 1"
            class="btn-danger btn-sm"
            @click="advanceDangerConfirm"
          >
            {{ t('admin.hosts.ops.dangerConfirm1Btn') }}
          </button>
          <button
            v-else
            class="btn-danger btn-sm"
            :disabled="loadingAction !== ''"
            @click="executeDangerConfirmed"
          >
            {{ loadingAction === 'instanceDanger' ? '...' : t('admin.hosts.ops.dangerConfirm2Btn') }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>
