<script setup lang="ts">
import { ref, onMounted, onUnmounted, onActivated, onDeactivated, watch, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import api from '@/api'
import { useAuthStore } from '@/stores/auth'
import { useConfigStore } from '@/stores/config'
import { useThemeStore } from '@/stores/theme'
import { usePollingWhenVisible } from '@/composables/usePollingWhenVisible'
import SkeletonLoader from '@/components/SkeletonLoader.vue'
import { useToast } from '@/stores/toast'
import { translateError } from '@/utils/errorHandler'
import type { Instance, UserBalance } from '@/types/api'
import InstanceListToolbar from '@/components/instance/InstanceListToolbar.vue'
import InstanceBatchActionBar from '@/components/instance/InstanceBatchActionBar.vue'
import InstanceTable from '@/components/instance/InstanceTable.vue'
import InstanceCardList from '@/components/instance/InstanceCardList.vue'
import BatchRenewModal from '@/components/instance/BatchRenewModal.vue'
import BatchDestroyModal from '@/components/instance/BatchDestroyModal.vue'
import {
  type InstanceLayoutMode,
  type InstanceRowAction,
  type BatchSimpleAction,
  type InstanceOrderAction,
  type BatchRenewPreviewItem,
  type BatchDestroyPreviewItem
} from '@/components/instance/instanceListShared'
import { freeSiteCopy } from '@/utils/freeSiteFun'

// 为 KeepAlive include 匹配定义组件名称（必须在所有 import 之后）
defineOptions({ name: 'InstancesView' })

const INSTANCE_LAYOUT_STORAGE_KEY = 'incudal.instances.layout'

const route = useRoute()
const router = useRouter()
const { t } = useI18n()
const authStore = useAuthStore()
const configStore = useConfigStore()
const themeStore = useThemeStore()
const toast = useToast()
void configStore.loadPublicConfig()

const instances = ref<Instance[]>([])
const loading = ref<boolean>(true)
const actionLoading = ref<Record<number, string>>({})
const orderLoading = ref<boolean>(false)
const recentlyOrderedInstanceId = ref<number | null>(null)
const batchActionLoading = ref<string>('')

// 搜索和分页
const search = ref<string>('')
const page = ref<number>(1)
const pageSize = ref<number>(30)
const total = ref<number>(0)
const totalPages = ref<number>(0)
const countryFilter = ref<string | null>(null)
const availableCountries = ref<string[]>([])
const userSelectedLayout = ref<InstanceLayoutMode | null>(null)
const isDesktopViewport = ref<boolean>(true)

// 批量选择
const selectedIds = ref<Set<number>>(new Set())

// 批量续费
const showBatchRenewModal = ref(false)
const batchRenewLoading = ref(false)
const batchRenewSubmitting = ref(false)
const batchRenewMonths = ref<number>(1)
const batchRenewBalance = ref<UserBalance>({ balance: 0, frozen: 0, totalRecharge: 0, totalConsume: 0 })
const batchRenewPreview = ref<BatchRenewPreviewItem[]>([])

// 批量销毁
const showBatchDestroyModal = ref(false)
const batchDestroyLoading = ref(false)
const batchDestroySubmitting = ref(false)
const batchDestroyConfirm = ref('')
const batchDestroyPreview = ref<BatchDestroyPreviewItem[]>([])

// 筛选条件（从 URL 获取）
const filterUserId = ref<number | null>(null)
const filterUserName = ref<string>('')

const isAllSelected = computed(() => instances.value.length > 0 && selectedIds.value.size === instances.value.length)
const selectedCount = computed(() => selectedIds.value.size)
const selectedInstances = computed(() => instances.value.filter(instance => selectedIds.value.has(instance.id)))
const selectedRunningCount = computed(() => selectedInstances.value.filter(instance => instance.status?.toLowerCase() === 'running').length)
const selectedStoppedCount = computed(() => selectedInstances.value.filter(instance => instance.status?.toLowerCase() === 'stopped').length)
const selectedPaidCount = computed(() => selectedInstances.value.filter(instance => !!instance.packagePlanId).length)
const hasSelectedInstances = computed(() => selectedCount.value > 0)
const isViewingAnotherUsersInstances = computed(() => (
  isAdmin.value &&
  filterUserId.value !== null &&
  filterUserId.value !== (authStore.user?.id || null)
))
const countryFilterOptions = computed(() => availableCountries.value.map(code => code.toLowerCase()))
const instanceLayoutMode = computed<InstanceLayoutMode>(() => (
  isDesktopViewport.value
    ? (userSelectedLayout.value || 'list')
    : 'card'
))
const isCardLayout = computed<boolean>(() => instanceLayoutMode.value === 'card')

const batchRenewMonthOptions = computed(() => {
  const options = new Set<number>()
  for (const item of batchRenewPreview.value) {
    if (!item.canRenew) continue
    for (const option of item.options) {
      options.add(option.months)
    }
  }
  return Array.from(options).sort((a, b) => a - b)
})

const batchRenewEligibleItems = computed(() => {
  return batchRenewPreview.value
    .map(item => ({
      ...item,
      selectedOption: item.options.find(option => option.months === batchRenewMonths.value) || null
    }))
    .filter(item => item.selectedOption !== null)
})

const batchRenewIneligibleItems = computed(() => {
  return batchRenewPreview.value.filter(item => !item.canRenew || !item.options.some(option => option.months === batchRenewMonths.value))
})

const batchRenewTotal = computed(() => {
  return batchRenewEligibleItems.value.reduce((sum, item) => sum + Number(item.selectedOption?.discountedPrice || 0), 0)
})

const batchRenewInsufficientBalance = computed(() => batchRenewBalance.value.balance < batchRenewTotal.value)
const batchRenewBalanceAfter = computed(() => batchRenewBalance.value.balance - batchRenewTotal.value)
const batchRenewCanSubmit = computed(() => (
  batchRenewEligibleItems.value.length > 0 &&
  batchRenewMonthOptions.value.length > 0 &&
  !batchRenewInsufficientBalance.value &&
  !batchRenewSubmitting.value
))

const batchDestroyEligibleItems = computed(() => batchDestroyPreview.value.filter(item => item.canDestroy))
const batchDestroyIneligibleItems = computed(() => batchDestroyPreview.value.filter(item => !item.canDestroy))
const batchDestroyTotalRefund = computed(() => batchDestroyEligibleItems.value.reduce((sum, item) => sum + item.refund.refundAmount, 0))
const batchDestroyTotalFee = computed(() => batchDestroyEligibleItems.value.reduce((sum, item) => sum + item.refund.feeAmount, 0))
const batchDestroyCanSubmit = computed(() => batchDestroyEligibleItems.value.length > 0 && batchDestroyConfirm.value === 'DESTROY' && !batchDestroySubmitting.value)
const isInstanceOrderView = computed(() => search.value.trim() === '' && countryFilter.value === null)
const canReorderInstances = computed(() => (
  isInstanceOrderView.value &&
  (
    !isAdmin.value ||
    filterUserId.value === (authStore.user?.id || null)
  )
))

const polling = usePollingWhenVisible()
let orderFeedbackTimer: ReturnType<typeof setTimeout> | null = null
let instancesRequestGeneration = 0

// 监听搜索变化（防抖）
let searchTimer: ReturnType<typeof setTimeout> | null = null
watch(search, () => {
  if (searchTimer) clearTimeout(searchTimer)
  searchTimer = setTimeout(() => {
    page.value = 1
    loadInstances()
  }, 300)
})

// 监听路由参数变化（管理员切换查看不同用户的实例）
watch(
  () => route.query.userId,
  async (newUserId, oldUserId) => {
    if (newUserId === oldUserId) return

    // 更新筛选条件
    if (newUserId) {
      filterUserId.value = parseInt(newUserId as string)
      // 获取用户名
      try {
        const res = await api.users.get(filterUserId.value)
        filterUserName.value = (res as { user?: { username?: string } }).user?.username || ''
      } catch {
        filterUserName.value = ''
      }
    } else {
      filterUserId.value = null
      filterUserName.value = ''
    }

    // 重置分页并重新加载
    page.value = 1
    loading.value = true
    await loadInstances()
  },
  { immediate: false }
)

// 判断是否为管理员
const isAdmin = computed<boolean>(() => authStore.user?.role === 'admin')

function updateViewportState(): void {
  if (typeof window === 'undefined') return
  isDesktopViewport.value = window.innerWidth >= 1024
}

function loadInstanceLayoutPreference(): void {
  if (typeof window === 'undefined') return
  try {
    const stored = localStorage.getItem(INSTANCE_LAYOUT_STORAGE_KEY)
    userSelectedLayout.value = stored === 'list' || stored === 'card' ? stored : null
  } catch {
    userSelectedLayout.value = null
  }
}

function setInstanceLayoutMode(mode: InstanceLayoutMode): void {
  userSelectedLayout.value = mode
  if (typeof window === 'undefined') return
  try {
    localStorage.setItem(INSTANCE_LAYOUT_STORAGE_KEY, mode)
  } catch {
    // ignore storage errors
  }
}

onMounted(async (): Promise<void> => {
  updateViewportState()
  loadInstanceLayoutPreference()
  if (typeof window !== 'undefined') {
    window.addEventListener('resize', updateViewportState)
  }

  // 从 URL 获取 userId 参数（首次加载）
  if (route.query.userId) {
    filterUserId.value = parseInt(route.query.userId as string)
    // 获取用户名
    try {
      const res = await api.users.get(filterUserId.value)
      filterUserName.value = (res as { user?: { username?: string } }).user?.username || ''
    } catch {
      // 忽略错误
    }
  } else {
    // 确保没有 userId 时清空筛选
    filterUserId.value = null
    filterUserName.value = ''
  }

  await loadInstances()
  // 每 15 秒自动刷新（可见性感知）
  polling.start('instances', loadInstances, 15000)
})

onUnmounted(() => {
  if (typeof window !== 'undefined') {
    window.removeEventListener('resize', updateViewportState)
  }
  polling.stopAll()
  if (searchTimer) {
    clearTimeout(searchTimer)
    searchTimer = null
  }
  clearInstanceOrderFeedback()
})

// 当组件被 KeepAlive 停用时，暂停所有轮询
onDeactivated(() => {
  polling.stopAll()
  if (searchTimer) {
    clearTimeout(searchTimer)
    searchTimer = null
  }
  clearInstanceOrderFeedback()
})

// 当组件从 KeepAlive 缓存中激活时，重新加载数据
onActivated(async () => {
  updateViewportState()
  // 恢复定时刷新（可见性感知）
  polling.start('instances', loadInstances, 15000)

  // 检查路由参数是否与当前筛选一致
  const currentUserId = route.query.userId ? parseInt(route.query.userId as string) : null

  if (currentUserId !== filterUserId.value) {
    // 路由参数已变化，更新筛选并重新加载
    if (currentUserId) {
      filterUserId.value = currentUserId
      try {
        const res = await api.users.get(filterUserId.value)
        filterUserName.value = (res as { user?: { username?: string } }).user?.username || ''
      } catch {
        filterUserName.value = ''
      }
    } else {
      filterUserId.value = null
      filterUserName.value = ''
    }
    page.value = 1
  }

  // 总是重新加载数据以确保最新
  await loadInstances()
})

async function loadInstances(force = false): Promise<void> {
  // 如果有操作进行中，跳过刷新
  if (
    !force &&
    loading.value === false &&
    (
      Object.keys(actionLoading.value).length > 0 ||
      orderLoading.value ||
      batchActionLoading.value ||
      batchRenewSubmitting.value ||
      batchDestroySubmitting.value
    )
  ) return

  const generation = ++instancesRequestGeneration

  try {
    const params: { page: number; pageSize: number; search: string; userId?: number } = {
      page: page.value,
      pageSize: pageSize.value,
      search: search.value
    }

    if (filterUserId.value) {
      params.userId = filterUserId.value
    }

    if (countryFilter.value) {
      ;(params as typeof params & { countryCode?: string }).countryCode = countryFilter.value
    }

    const response = await api.instances.list(params)
    if (generation !== instancesRequestGeneration) return
    const data = response as { instances?: Instance[]; total?: number; totalPages?: number; availableCountries?: string[] }
    const nextInstances = data.instances || []
    instances.value = nextInstances
    total.value = data.total || 0
    totalPages.value = Math.max(1, data.totalPages || 1)
    availableCountries.value = (data.availableCountries || []).map(code => code.toLowerCase())

    if (page.value > totalPages.value) {
      page.value = totalPages.value
      return loadInstances(force)
    }

    const visibleIds = new Set(nextInstances.map(instance => instance.id))
    selectedIds.value = new Set([...selectedIds.value].filter(id => visibleIds.has(id)))
  } catch (error) {
    if (generation === instancesRequestGeneration) console.error('Failed to load instances:', error)
  } finally {
    if (generation === instancesRequestGeneration) loading.value = false
  }
}

function toggleSelectAll(): void {
  if (isAllSelected.value) {
    selectedIds.value = new Set()
  } else {
    selectedIds.value = new Set(instances.value.map(instance => instance.id))
  }
}

function toggleSelect(id: number): void {
  const next = new Set(selectedIds.value)
  if (next.has(id)) {
    next.delete(id)
  } else {
    next.add(id)
  }
  selectedIds.value = next
}

function clearSelection(): void {
  selectedIds.value = new Set()
}

function setCountryFilter(code: string | null): void {
  if (countryFilter.value === code) return
  countryFilter.value = code
  page.value = 1
  clearSelection()
  void loadInstances()
}

function handlePageSizeChange(): void {
  page.value = 1
  clearSelection()
  void loadInstances()
}

function goToPage(nextPage: number): void {
  if (nextPage < 1 || nextPage > totalPages.value || nextPage === page.value) return
  page.value = nextPage
  clearSelection()
  void loadInstances()
}

function clearUserFilter(): void {
  clearSelection()
  page.value = 1
  filterUserId.value = null
  filterUserName.value = ''
  router.replace({ query: {} })
  void loadInstances()
}

const instanceOrderLabels = computed<Record<InstanceOrderAction, string>>(() => ({
  top: t('instance.order.top'),
  up: t('instance.order.up'),
  down: t('instance.order.down'),
  bottom: t('instance.order.bottom')
}))

function getInstanceIndex(instanceId: number): number {
  return instances.value.findIndex(instance => instance.id === instanceId)
}

function canMoveInstance(instanceId: number, action: InstanceOrderAction): boolean {
  if (orderLoading.value || !canReorderInstances.value || total.value <= 1) return false
  const index = getInstanceIndex(instanceId)
  if (index < 0) return false
  const globalIndex = (page.value - 1) * pageSize.value + index
  if (action === 'top' || action === 'up') return globalIndex > 0
  return globalIndex < total.value - 1
}

function getInstanceOrderDisabledActions(instanceId: number): Record<InstanceOrderAction, boolean> {
  return {
    top: !canMoveInstance(instanceId, 'top'),
    up: !canMoveInstance(instanceId, 'up'),
    down: !canMoveInstance(instanceId, 'down'),
    bottom: !canMoveInstance(instanceId, 'bottom')
  }
}

function clearInstanceOrderFeedback(): void {
  if (orderFeedbackTimer) {
    clearTimeout(orderFeedbackTimer)
    orderFeedbackTimer = null
  }
  recentlyOrderedInstanceId.value = null
}

function markInstanceOrderFeedback(instanceId: number): void {
  clearInstanceOrderFeedback()
  recentlyOrderedInstanceId.value = instanceId
  orderFeedbackTimer = setTimeout(() => {
    recentlyOrderedInstanceId.value = null
    orderFeedbackTimer = null
  }, 1100)
}

function getVisibleReorderTargetIndex(currentIndex: number, action: InstanceOrderAction): number | null {
  const pageStartIndex = (page.value - 1) * pageSize.value
  const globalIndex = pageStartIndex + currentIndex
  let targetGlobalIndex = globalIndex
  if (action === 'top') targetGlobalIndex = 0
  else if (action === 'up') targetGlobalIndex = globalIndex - 1
  else if (action === 'down') targetGlobalIndex = globalIndex + 1
  else targetGlobalIndex = total.value - 1

  const targetIndex = targetGlobalIndex - pageStartIndex
  if (targetIndex < 0 || targetIndex >= instances.value.length) {
    return null
  }
  return targetIndex
}

async function reorderInstance(instance: Instance, action: InstanceOrderAction): Promise<void> {
  if (!canMoveInstance(instance.id, action)) return

  const currentIndex = getInstanceIndex(instance.id)
  if (currentIndex < 0) return

  const nextInstances = [...instances.value]
  const targetIndex = getVisibleReorderTargetIndex(currentIndex, action)
  if (targetIndex !== null) {
    const [moved] = nextInstances.splice(currentIndex, 1)
    if (!moved) return
    nextInstances.splice(targetIndex, 0, moved)
  }

  try {
    orderLoading.value = true
    if (targetIndex !== null) {
      instances.value = nextInstances
      markInstanceOrderFeedback(instance.id)
    }
    await api.instances.updateOrder(instance.id, action)
    await loadInstances(true)
    toast.success(t('instance.order.updateSuccess'))
  } catch (error: any) {
    clearInstanceOrderFeedback()
    toast.error(t('instance.order.updateFailed') + ': ' + translateError(error))
    await loadInstances(true)
  } finally {
    orderLoading.value = false
  }
}

async function handleAction(instance: Instance, action: InstanceRowAction): Promise<void> {
  actionLoading.value[instance.id] = action

  try {
    if (action === 'start') {
      await api.instances.start(instance.id)
      toast.success(t('instance.startingInstance', { name: instance.name }))
      // 更新本地状态为启动中
      const idx = instances.value.findIndex(i => i.id === instance.id)
      if (idx !== -1) {
        (instances.value[idx] as any).status = 'starting'
      }
    }
    else if (action === 'stop') {
      await api.instances.stop(instance.id)
      toast.success(t('instance.stoppedInstance', { name: instance.name }))
      // 更新本地状态为已停止
      const idx = instances.value.findIndex(i => i.id === instance.id)
      if (idx !== -1) {
        instances.value[idx] = { ...instances.value[idx], status: 'stopped' }
      }
    }
    else if (action === 'restart') {
      await api.instances.restart(instance.id)
      toast.success(t('instance.restartingInstance', { name: instance.name }))
      // 更新本地状态为重启中
      const idx = instances.value.findIndex(i => i.id === instance.id)
      if (idx !== -1) {
        (instances.value[idx] as any).status = 'restarting'
      }
    }
    else if (action === 'retry') {
      await api.instances.retryProvision(instance.id)
      const idx = instances.value.findIndex(i => i.id === instance.id)
      if (idx !== -1) instances.value[idx] = { ...instances.value[idx], status: 'creating' }
      toast.success(t('instance.retryCreateStarted', { name: instance.name }))
    }
    else if (action === 'delete') {
      if (!confirm(t('instance.confirmDelete', { name: instance.name }))) {
        delete actionLoading.value[instance.id]
        return
      }
      await api.instances.delete(instance.id)
      // 立即从本地列表移除，提供即时反馈
      instances.value = instances.value.filter(i => i.id !== instance.id)
      total.value = Math.max(0, total.value - 1)
      toast.success(t('instance.deletedInstance', { name: instance.name }))
    }
  } catch (error: any) {
    toast.error(`${t('instance.actionFailed')}: ${translateError(error)}`)
    // 操作失败时重新加载以恢复正确状态
    await loadInstances(true)
  } finally {
    delete actionLoading.value[instance.id]
  }
}

function openInstanceDetail(instanceId: number): void {
  router.push(`/instances/${instanceId}`)
}

function getBatchTargets(action: BatchSimpleAction): Instance[] {
  if (action === 'start') {
    return selectedInstances.value.filter(instance => instance.status?.toLowerCase() === 'stopped')
  }
  if (action === 'stop' || action === 'restart') {
    return selectedInstances.value.filter(instance => instance.status?.toLowerCase() === 'running')
  }
  return selectedInstances.value
}

async function runWithConcurrency<T, R>(
  items: T[],
  concurrency: number,
  handler: (item: T) => Promise<R>
): Promise<PromiseSettledResult<R>[]> {
  const results: PromiseSettledResult<R>[] = new Array(items.length)
  let currentIndex = 0

  async function worker(): Promise<void> {
    while (true) {
      const index = currentIndex
      currentIndex += 1
      if (index >= items.length) break
      try {
        const value = await handler(items[index])
        results[index] = { status: 'fulfilled', value }
      } catch (error) {
        results[index] = { status: 'rejected', reason: error }
      }
    }
  }

  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, () => worker()))
  return results
}

const SIMPLE_BATCH_CONCURRENCY = 5

async function handleBatchSimpleAction(action: BatchSimpleAction): Promise<void> {
  const targets = getBatchTargets(action)
  if (targets.length === 0) {
    toast.warning(t('instance.batch.noEligibleAction'))
    return
  }

  batchActionLoading.value = action
  try {
    const settled = await runWithConcurrency(
      targets,
      SIMPLE_BATCH_CONCURRENCY,
      async (instance) => {
        if (action === 'start') return api.instances.start(instance.id)
        if (action === 'stop') return api.instances.stop(instance.id)
        if (action === 'restart') return api.instances.restart(instance.id)
        return api.instances.syncStatus(instance.id)
      }
    )

    const successCount = settled.filter(item => item.status === 'fulfilled').length
    const failedCount = settled.length - successCount
    const skippedCount = selectedCount.value - targets.length

    if (failedCount > 0) {
      toast.warning(t('instance.batch.partialResult', { success: successCount, failed: failedCount, skipped: skippedCount }))
    } else {
      toast.success(t('instance.batch.successResult', { count: successCount }))
    }

    clearSelection()
    await loadInstances(true)
  } catch (error: any) {
    toast.error(t('instance.batch.actionFailed') + ': ' + translateError(error))
  } finally {
    batchActionLoading.value = ''
  }
}

async function handleBatchAutoRenew(autoRenew: boolean): Promise<void> {
  if (selectedCount.value === 0 || isViewingAnotherUsersInstances.value) return

  batchActionLoading.value = autoRenew ? 'autoRenewOn' : 'autoRenewOff'
  try {
    const result = await api.billing.setAutoRenewBatch(Array.from(selectedIds.value), autoRenew)
    if (result.failedCount > 0) {
      toast.warning(t('instance.batch.partialResult', {
        success: result.successCount,
        failed: result.failedCount,
        skipped: result.skippedCount
      }))
    } else {
      toast.success(t(autoRenew ? 'billing.autoRenewEnabled' : 'billing.autoRenewDisabled'))
    }
    clearSelection()
    await loadInstances(true)
  } catch (error: any) {
    toast.error(t('instance.batch.actionFailed') + ': ' + translateError(error))
  } finally {
    batchActionLoading.value = ''
  }
}

async function openBatchRenewModal(): Promise<void> {
  if (selectedCount.value === 0 || isViewingAnotherUsersInstances.value) return

  showBatchRenewModal.value = true
  batchRenewLoading.value = true
  batchRenewPreview.value = []
  batchRenewMonths.value = 1

  try {
    const [previewRes, balanceRes] = await Promise.all([
      api.billing.previewBatchRenew(Array.from(selectedIds.value)),
      api.billing.getUserBalance()
    ])
    batchRenewPreview.value = previewRes.items
    batchRenewBalance.value = balanceRes.balance
    batchRenewMonths.value = batchRenewMonthOptions.value.includes(1)
      ? 1
      : (batchRenewMonthOptions.value[0] || 1)
  } catch (error: any) {
    toast.error(t('instance.batch.previewFailed') + ': ' + translateError(error))
    showBatchRenewModal.value = false
  } finally {
    batchRenewLoading.value = false
  }
}

function closeBatchRenewModal(force = false): void {
  if (batchRenewSubmitting.value && !force) return
  showBatchRenewModal.value = false
  batchRenewPreview.value = []
  batchRenewMonths.value = 1
}

async function confirmBatchRenew(): Promise<void> {
  if (!batchRenewCanSubmit.value) return

  batchRenewSubmitting.value = true
  try {
    const result = await api.billing.renewInstancesBatch(Array.from(selectedIds.value), batchRenewMonths.value)
    if (result.failedCount > 0) {
      toast.warning(t('instance.batch.partialResult', {
        success: result.successCount,
        failed: result.failedCount,
        skipped: result.skippedCount
      }))
    } else {
      toast.success(t('instance.batch.successResult', { count: result.successCount }))
    }
    closeBatchRenewModal(true)
    clearSelection()
    await loadInstances(true)
  } catch (error: any) {
    toast.error(t('instance.batch.actionFailed') + ': ' + translateError(error))
  } finally {
    batchRenewSubmitting.value = false
  }
}

async function openBatchDestroyModal(): Promise<void> {
  if (selectedCount.value === 0 || isViewingAnotherUsersInstances.value) return

  showBatchDestroyModal.value = true
  batchDestroyLoading.value = true
  batchDestroyConfirm.value = ''
  batchDestroyPreview.value = []

  try {
    const result = await api.billing.getBatchDestroyInfo(Array.from(selectedIds.value))
    batchDestroyPreview.value = result.items
  } catch (error: any) {
    toast.error(t('instance.batch.previewFailed') + ': ' + translateError(error))
    showBatchDestroyModal.value = false
  } finally {
    batchDestroyLoading.value = false
  }
}

function closeBatchDestroyModal(force = false): void {
  if (batchDestroySubmitting.value && !force) return
  showBatchDestroyModal.value = false
  batchDestroyConfirm.value = ''
  batchDestroyPreview.value = []
}

async function confirmBatchDestroy(): Promise<void> {
  if (!batchDestroyCanSubmit.value) return

  batchDestroySubmitting.value = true
  try {
    const result = await api.billing.destroyInstancesBatch(Array.from(selectedIds.value))
    if (result.failedCount > 0) {
      toast.warning(t('instance.batch.partialResult', {
        success: result.successCount,
        failed: result.failedCount,
        skipped: result.skippedCount
      }))
    } else {
      toast.success(t('instance.batch.successResult', { count: result.successCount }))
    }
    closeBatchDestroyModal(true)
    clearSelection()
    await loadInstances(true)
  } catch (error: any) {
    toast.error(t('instance.batch.actionFailed') + ': ' + translateError(error))
  } finally {
    batchDestroySubmitting.value = false
  }
}

</script>

<template>
  <div class="space-y-6 animate-fade-in">
    <!-- 页面头部 -->
    <div class="page-header flex-col sm:flex-row gap-4 sm:gap-0">
      <div>
        <h1 class="page-title text-lg sm:text-xl">{{ $t('instance.title') }}</h1>
        <p class="page-description">
          <template v-if="filterUserId && filterUserName">
            {{ $t('instance.userInstances', { name: filterUserName }) }}
            <button class="text-blue-500 hover:text-blue-400 ml-2 text-sm" @click="clearUserFilter">
              {{ $t('instance.clearFilter') }}
            </button>
          </template>
          <template v-else>
            {{ $t('instance.manageDesc') }}
          </template>
        </p>
      </div>
      <div class="flex w-full flex-col gap-2 sm:w-auto sm:flex-row">
        <RouterLink to="/instances/create" class="btn-primary w-full justify-center sm:w-auto">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
          </svg>
          {{ configStore.freeSiteMode ? freeSiteCopy.instanceCreate : $t('instance.create') }}
        </RouterLink>
      </div>
    </div>

    <!-- 搜索和筛选 -->
    <InstanceListToolbar
      v-model:search="search"
      v-model:page-size="pageSize"
      :country-filter="countryFilter"
      :country-options="countryFilterOptions"
      :layout-mode="instanceLayoutMode"
      :total="total"
      @change-country="setCountryFilter"
      @set-layout="setInstanceLayoutMode"
      @page-size-change="handlePageSizeChange"
    />

    <!-- 批量操作条 -->
    <InstanceBatchActionBar
      v-if="hasSelectedInstances && !loading && instances.length > 0"
      :selected-count="selectedCount"
      :selected-stopped-count="selectedStoppedCount"
      :selected-running-count="selectedRunningCount"
      :selected-paid-count="selectedPaidCount"
      :batch-action-loading="batchActionLoading"
      :batch-renew-submitting="batchRenewSubmitting"
      :batch-destroy-submitting="batchDestroySubmitting"
      :disabled-by-admin-context="isViewingAnotherUsersInstances"
      @clear="clearSelection"
      @simple-action="handleBatchSimpleAction"
      @auto-renew="handleBatchAutoRenew"
      @open-renew="openBatchRenewModal"
      @open-destroy="openBatchDestroyModal"
    />

    <!-- 加载骨架屏 -->
    <SkeletonLoader
      v-if="loading"
      :type="isCardLayout ? 'grid' : 'table'"
      :rows="isCardLayout ? 3 : 8"
      :cols="isDesktopViewport ? 3 : 1"
    />

    <!-- 空状态 -->
    <div v-else-if="instances.length === 0" class="card p-12 text-center">
      <svg
        class="w-16 h-16 mx-auto mb-4"
        :class="themeStore.isDark ? 'text-gray-700' : 'text-gray-300'"
        fill="none" stroke="currentColor" viewBox="0 0 24 24"
      >
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2" />
      </svg>
      <h3
        class="text-lg font-medium mb-2"
        :class="themeStore.isDark ? 'text-gray-300' : 'text-gray-700'"
      >
        {{ search ? $t('instance.noMatchingInstances') : $t('instance.noInstances') }}
      </h3>
      <p class="text-themed-muted mb-4">{{ search ? $t('instance.tryOtherKeywords') : $t('instance.createFirstInstance') }}</p>
      <RouterLink v-if="!search" to="/instances/create" class="btn-primary">{{ configStore.freeSiteMode ? freeSiteCopy.instanceCreateFirst : $t('instance.create') }}</RouterLink>
    </div>

    <!-- 实例列表 -->
    <template v-else>
      <InstanceTable
        v-if="instanceLayoutMode === 'list'"
        :instances="instances"
        :selected-ids="selectedIds"
        :is-admin="isAdmin"
        :action-loading="actionLoading"
        :order-loading="orderLoading"
        :recently-ordered-instance-id="recentlyOrderedInstanceId"
        :can-reorder-instances="canReorderInstances"
        :order-labels="instanceOrderLabels"
        :get-order-disabled-actions="getInstanceOrderDisabledActions"
        @toggle-select-all="toggleSelectAll"
        @toggle-select="toggleSelect"
        @open-detail="openInstanceDetail"
        @row-action="handleAction"
        @reorder="reorderInstance"
      />

      <InstanceCardList
        v-else
        :instances="instances"
        :selected-ids="selectedIds"
        :is-admin="isAdmin"
        :action-loading="actionLoading"
        :order-loading="orderLoading"
        :recently-ordered-instance-id="recentlyOrderedInstanceId"
        :can-reorder-instances="canReorderInstances"
        :order-labels="instanceOrderLabels"
        :get-order-disabled-actions="getInstanceOrderDisabledActions"
        @toggle-select="toggleSelect"
        @open-detail="openInstanceDetail"
        @row-action="handleAction"
        @reorder="reorderInstance"
      />
    </template>

    <div v-if="!loading && instances.length > 0" class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between text-sm text-themed-muted">
      <span>{{ $t('instance.totalRecords', { count: total }) }} · {{ page }} / {{ totalPages }}</span>
      <div class="flex items-center gap-2">
        <button
          :disabled="page <= 1"
          class="btn-ghost btn-sm"
          @click="goToPage(page - 1)"
        >
          {{ $t('common.prevPage') }}
        </button>
        <span class="min-w-[84px] text-center">{{ page }} / {{ totalPages }}</span>
        <button
          :disabled="page >= totalPages"
          class="btn-ghost btn-sm"
          @click="goToPage(page + 1)"
        >
          {{ $t('common.nextPage') }}
        </button>
      </div>
    </div>

    <Teleport to="body">
      <BatchRenewModal
        v-if="showBatchRenewModal"
        v-model:months="batchRenewMonths"
        :loading="batchRenewLoading"
        :submitting="batchRenewSubmitting"
        :selected-count="selectedCount"
        :month-options="batchRenewMonthOptions"
        :eligible-items="batchRenewEligibleItems"
        :ineligible-items="batchRenewIneligibleItems"
        :total="batchRenewTotal"
        :balance="batchRenewBalance"
        :balance-after="batchRenewBalanceAfter"
        :insufficient-balance="batchRenewInsufficientBalance"
        :can-submit="batchRenewCanSubmit"
        @close="closeBatchRenewModal()"
        @confirm="confirmBatchRenew"
      />
    </Teleport>

    <Teleport to="body">
      <BatchDestroyModal
        v-if="showBatchDestroyModal"
        v-model:confirm-text="batchDestroyConfirm"
        :loading="batchDestroyLoading"
        :submitting="batchDestroySubmitting"
        :selected-count="selectedCount"
        :eligible-items="batchDestroyEligibleItems"
        :ineligible-items="batchDestroyIneligibleItems"
        :total-refund="batchDestroyTotalRefund"
        :total-fee="batchDestroyTotalFee"
        :can-submit="batchDestroyCanSubmit"
        @close="closeBatchDestroyModal()"
        @confirm="confirmBatchDestroy"
      />
    </Teleport>
  </div>
</template>
