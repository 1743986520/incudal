<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { useThemeStore } from '@/stores/theme'
import { useToast } from '@/stores/toast'
import { translateError } from '@/utils/errorHandler'
import api from '@/api'
import { formatTrafficUnitPrice } from '@/utils/trafficBilling'

const props = defineProps<{
  instanceId: number
  trafficData: TrafficData | null
  loading: boolean
}>()

const emit = defineEmits<{
  (e: 'need-refresh'): void
}>()

const { t } = useI18n()
const themeStore = useThemeStore()
const toast = useToast()

// 流量数据
interface TrafficData {
  monthlyUsed: string
  monthlyUsedFormatted: string
  monthlyLimit: string | null
  monthlyLimitFormatted: string | null
  trafficStatus: 'NORMAL' | 'WARNING' | 'LIMITED'
  percentage: number
  trafficResetDay: number
  periodStart: string
  periodEnd: string
  resetAllowed: boolean
  resetPrice: number
  resetPriceFormatted: string | null
  resetDisabledReason: string | null
  trafficBillingMode: 'package' | 'usage'
  trafficUnitPrice: number
  includedTraffic: string | null
  overageTraffic: string
  settledTraffic: string
  settledTrafficCost: number
  pendingTraffic: string
  nextTrafficBillingAt: string | null
}

function formatTrafficBytes(value: string | null): string {
  const bytes = Number(value || 0)
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(2)} MB`
  return `${(bytes / 1024 ** 3).toFixed(2)} GB`
}

interface TrafficHistoryItem {
  date: string
  rxTotal: string
  txTotal: string
  rxFormatted: string
  txFormatted: string
  total: string
  totalFormatted: string
}

const trafficHistory = ref<TrafficHistoryItem[]>([])
const periodInfo = ref<{ periodStart: string; periodEnd: string } | null>(null)
const historyLoading = ref(true)
const showResetConfirm = ref(false)
const resetting = ref(false)

onMounted(async () => {
  // 流量摘要数据由父组件 InstanceDetailView 统一加载和轮询，这里仅加载历史数据
  await loadTrafficHistory()
})

async function loadTrafficHistory() {
  historyLoading.value = true
  try {
    const response = await api.traffic.getInstanceTrafficHistory(props.instanceId)
    trafficHistory.value = response.data
    periodInfo.value = {
      periodStart: response.periodStart,
      periodEnd: response.periodEnd
    }
  } catch (error) {
    console.error('Failed to load traffic history:', error)
  } finally {
    historyLoading.value = false
  }
}

// 格式化周期日期显示 (MM-DD ~ MM-DD)
const periodDateRange = computed(() => {
  if (!props.trafficData) return ''
  const start = props.trafficData.periodStart.slice(5) // MM-DD
  const end = props.trafficData.periodEnd.slice(5)
  return `${start} ~ ${end}`
})

// 状态标签样式
const statusBadgeClass = computed(() => {
  if (!props.trafficData) return ''
  switch (props.trafficData.trafficStatus) {
    case 'LIMITED':
      return 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400'
    case 'WARNING':
      return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400'
    default:
      return 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400'
  }
})

const statusLabel = computed(() => {
  if (!props.trafficData) return ''
  switch (props.trafficData.trafficStatus) {
    case 'LIMITED':
      return t('traffic.status.limited')
    case 'WARNING':
      return t('traffic.status.warning')
    default:
      return t('traffic.status.normal')
  }
})

const canResetTraffic = computed(() => {
  if (!props.trafficData) return false
  return props.trafficData.resetAllowed && BigInt(props.trafficData.monthlyUsed || '0') > 0n
})

function openResetConfirm() {
  if (!canResetTraffic.value || resetting.value) return
  showResetConfirm.value = true
}

async function confirmResetTraffic() {
  if (!props.trafficData || resetting.value) return

  resetting.value = true
  try {
    await api.traffic.resetInstanceTraffic(props.instanceId)
    // 通知父组件重新加载流量数据（父组件的 loadTrafficData 会获取最新数据）
    emit('need-refresh')
    showResetConfirm.value = false
    toast.success(t('traffic.resetSuccess'))
  } catch (error) {
    toast.error(translateError(error) || t('traffic.resetFailed'))
  } finally {
    resetting.value = false
  }
}

// 进度条颜色
const progressBarClass = computed(() => {
  if (!props.trafficData) return 'bg-blue-500'
  if (props.trafficData.percentage >= 100) return 'bg-red-500'
  if (props.trafficData.percentage >= 80) return 'bg-yellow-500'
  return 'bg-blue-500'
})

// 计算图表最大值
const chartMaxValue = computed(() => {
  if (trafficHistory.value.length === 0) return 1
  const max = Math.max(...trafficHistory.value.map(h => Number(h.total)))
  return max || 1
})

// 格式化字节数为可读字符串
const formatBytes = (bytes: number) => {
  if (bytes === 0) return '0'
  if (bytes < 1024) return bytes + 'B'
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + 'K'
  if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + 'M'
  return (bytes / 1073741824).toFixed(1) + 'G'
}

// Y 轴刻度标签
const yAxisLabels = computed(() => {
  const max = chartMaxValue.value
  return {
    top: formatBytes(max),
    mid: formatBytes(max / 2),
    bottom: '0'
  }
})

// 格式化日期显示 (MM-DD)
const formatDate = (dateStr: string) => {
  return dateStr.slice(5) // 去掉年份，只保留 MM-DD
}

// X 轴标签（显示 5-7 个日期点）
const xAxisLabels = computed(() => {
  const len = trafficHistory.value.length
  if (len === 0) return []
  if (len <= 7) return trafficHistory.value.map(h => ({ date: formatDate(h.date), index: trafficHistory.value.indexOf(h) }))
  
  // 显示首、尾和中间均匀分布的点
  const step = Math.floor(len / 5)
  const labels = []
  for (let i = 0; i < len; i += step) {
    labels.push({ date: formatDate(trafficHistory.value[i].date), index: i })
  }
  // 确保最后一个日期显示
  if (labels[labels.length - 1].index !== len - 1) {
    labels.push({ date: formatDate(trafficHistory.value[len - 1].date), index: len - 1 })
  }
  return labels
})
</script>

<template>
  <div class="space-y-6">
    <!-- Current Month Usage -->
    <div class="card p-6">
      <div class="flex items-center justify-between mb-4">
        <h3 
          class="text-lg font-medium"
          :class="themeStore.isDark ? 'text-gray-100' : 'text-gray-900'"
        >
          {{ $t('traffic.monthlyUsage') }}
          <span v-if="trafficData" class="text-sm font-normal ml-2" :class="themeStore.isDark ? 'text-gray-500' : 'text-gray-400'">
            ({{ periodDateRange }})
          </span>
        </h3>
        <span 
          v-if="trafficData"
          :class="['px-2.5 py-0.5 rounded-full text-xs font-medium', statusBadgeClass]"
        >
          {{ statusLabel }}
        </span>
      </div>

      <div v-if="loading" class="animate-pulse space-y-4">
        <div class="h-4 bg-gray-200 dark:bg-gray-700 rounded w-1/3"></div>
        <div class="h-2 bg-gray-200 dark:bg-gray-700 rounded"></div>
        <div class="h-4 bg-gray-200 dark:bg-gray-700 rounded w-1/4"></div>
      </div>

      <template v-else-if="trafficData">
        <div class="space-y-3">
          <div class="flex justify-between text-sm">
            <span :class="themeStore.isDark ? 'text-gray-400' : 'text-gray-600'">
              {{ $t('traffic.used') }}
            </span>
            <span :class="themeStore.isDark ? 'text-gray-200' : 'text-gray-900'" class="font-medium">
              {{ trafficData.monthlyUsedFormatted }}
              <template v-if="trafficData.monthlyLimitFormatted">
                / {{ trafficData.monthlyLimitFormatted }}
              </template>
              <template v-else>
                / {{ $t('traffic.unlimited') }}
              </template>
            </span>
          </div>

          <div v-if="trafficData.trafficBillingMode === 'usage'" class="grid gap-2 rounded-lg border p-3 text-sm sm:grid-cols-2" :class="themeStore.isDark ? 'border-gray-800 bg-gray-900/40' : 'border-gray-100 bg-gray-50'">
            <div><span class="text-themed-muted">{{ $t('resources.plans.includedTraffic') }}:</span> <span class="font-medium text-themed">{{ formatTrafficBytes(trafficData.includedTraffic) }}</span></div>
            <div><span class="text-themed-muted">{{ $t('resources.plans.overageTraffic') }}:</span> <span class="font-medium text-themed">{{ formatTrafficBytes(trafficData.overageTraffic) }}</span></div>
            <div><span class="text-themed-muted">{{ $t('resources.plans.settledTrafficCost') }}:</span> <span class="font-medium text-themed">¥{{ trafficData.settledTrafficCost.toFixed(2) }}</span></div>
            <div><span class="text-themed-muted">{{ $t('resources.plans.pendingTraffic') }}:</span> <span class="font-medium text-themed">{{ formatTrafficBytes(trafficData.pendingTraffic) }}</span></div>
            <div><span class="text-themed-muted">{{ $t('resources.plans.trafficUnitPrice') }}:</span> <span class="font-medium text-themed">¥{{ formatTrafficUnitPrice(trafficData.trafficUnitPrice) }} / GB</span></div>
            <div><span class="text-themed-muted">{{ $t('resources.plans.nextSettlement') }}:</span> <span class="font-medium text-themed">{{ trafficData.nextTrafficBillingAt ? new Date(trafficData.nextTrafficBillingAt).toLocaleString() : '-' }}</span></div>
          </div>

          <!-- Progress Bar -->
          <div 
            class="h-2 rounded-full overflow-hidden"
            :class="themeStore.isDark ? 'bg-gray-700' : 'bg-gray-200'"
          >
            <div 
              :class="['h-full rounded-full transition-all duration-300', progressBarClass]"
              :style="{ width: `${Math.min(trafficData.percentage, 100)}%` }"
            ></div>
          </div>

          <div class="flex justify-between text-xs">
            <span :class="themeStore.isDark ? 'text-gray-500' : 'text-gray-500'">
              {{ trafficData.percentage.toFixed(1) }}%
            </span>
            <span :class="themeStore.isDark ? 'text-gray-500' : 'text-gray-400'">
              <span 
                v-if="trafficData.trafficStatus === 'LIMITED'"
                class="text-red-500"
              >
                {{ $t('traffic.throttledHint') }}
                <span class="mx-1">·</span>
              </span>
              {{ $t('traffic.periodResetHint', { date: trafficData.trafficResetDay }) }}
            </span>
          </div>

          <div
            v-if="trafficData.resetAllowed"
            class="mt-4 border-t pt-4"
            :class="themeStore.isDark ? 'border-gray-800' : 'border-gray-100'"
          >
            <div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div class="min-w-0">
                <div class="text-sm font-medium" :class="themeStore.isDark ? 'text-gray-100' : 'text-gray-900'">
                  {{ $t('traffic.resetTitle') }}
                </div>
                <div class="mt-1 text-xs leading-5 text-themed-muted">
                  {{ $t('traffic.resetPriceInfo', { price: trafficData.resetPriceFormatted || '¥0.00' }) }}
                </div>
              </div>
              <button
                type="button"
                class="btn-secondary h-9 w-full sm:w-auto"
                :disabled="!canResetTraffic || resetting"
                @click="openResetConfirm"
              >
                <span v-if="resetting" class="loading-spinner w-4 h-4"></span>
                <template v-else>{{ $t('traffic.resetAction') }}</template>
              </button>
            </div>
            <p v-if="!canResetTraffic" class="mt-2 text-xs text-themed-muted">
              {{ $t('traffic.resetNoUsage') }}
            </p>
          </div>
        </div>
      </template>

      <div v-else class="text-center py-4">
        <span :class="themeStore.isDark ? 'text-gray-500' : 'text-gray-400'">
          {{ $t('traffic.noData') }}
        </span>
      </div>
    </div>

    <!-- Traffic History Chart -->
    <div class="card p-6">
      <h3 
        class="text-lg font-medium mb-4"
        :class="themeStore.isDark ? 'text-gray-100' : 'text-gray-900'"
      >
        {{ $t('traffic.historyPeriod') }}
        <span v-if="periodInfo" class="text-sm font-normal ml-2" :class="themeStore.isDark ? 'text-gray-500' : 'text-gray-400'">
          ({{ periodInfo.periodStart.slice(5) }} ~ {{ periodInfo.periodEnd.slice(5) }})
        </span>
      </h3>

      <div v-if="historyLoading" class="animate-pulse">
        <div class="flex items-end gap-1 h-32">
          <div 
            v-for="i in 30" 
            :key="i" 
            class="flex-1 bg-gray-200 dark:bg-gray-700 rounded-t"
            :style="{ height: `${Math.random() * 100}%` }"
          ></div>
        </div>
      </div>

      <template v-else-if="trafficHistory.length > 0">
        <!-- Bar Chart with Y-axis -->
        <div class="flex">
          <!-- Y 轴刻度 -->
          <div class="flex flex-col justify-between h-40 pr-2 text-xs w-10" :class="themeStore.isDark ? 'text-gray-500' : 'text-gray-400'">
            <span class="text-right">{{ yAxisLabels.top }}</span>
            <span class="text-right">{{ yAxisLabels.mid }}</span>
            <span class="text-right">{{ yAxisLabels.bottom }}</span>
          </div>
          
          <!-- 图表区域 -->
          <div class="flex-1">
            <!-- 背景网格线 -->
            <div class="relative h-40">
              <div 
                class="absolute inset-0 flex flex-col justify-between pointer-events-none"
              >
                <div class="border-b" :class="themeStore.isDark ? 'border-gray-800' : 'border-gray-100'"></div>
                <div class="border-b" :class="themeStore.isDark ? 'border-gray-800' : 'border-gray-100'"></div>
                <div class="border-b" :class="themeStore.isDark ? 'border-gray-800' : 'border-gray-100'"></div>
              </div>
              
              <!-- 柱状图 -->
              <div class="absolute inset-0 flex items-end gap-0.5 px-1">
                <div 
                  v-for="(item, index) in trafficHistory" 
                  :key="item.date"
                  class="flex-1 min-w-1 rounded-t transition-all duration-200 cursor-pointer group relative"
                  :class="[
                    themeStore.isDark 
                      ? 'bg-gradient-to-t from-blue-600 to-blue-400 hover:from-blue-500 hover:to-blue-300' 
                      : 'bg-gradient-to-t from-blue-500 to-blue-400 hover:from-blue-400 hover:to-blue-300'
                  ]"
                  :style="{ height: `${Math.max((Number(item.total) / chartMaxValue) * 100, 1)}%` }"
                >
                  <!-- Tooltip -->
                  <div 
                    class="absolute bottom-full mb-2 px-2.5 py-1.5 text-xs rounded-lg shadow-lg opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none whitespace-nowrap z-10"
                    :class="[
                      themeStore.isDark ? 'bg-gray-800 text-gray-200 border border-gray-700' : 'bg-white text-gray-900 border border-gray-200 shadow-md',
                      index < 5 ? 'left-0' : index > trafficHistory.length - 5 ? 'right-0' : 'left-1/2 -translate-x-1/2'
                    ]"
                  >
                    <div class="font-medium mb-1">{{ item.date }}</div>
                    <div class="flex items-center gap-1.5">
                      <span class="w-2 h-2 rounded-full bg-green-500"></span>
                      <span>{{ $t('traffic.download') }}: {{ item.rxFormatted }}</span>
                    </div>
                    <div class="flex items-center gap-1.5">
                      <span class="w-2 h-2 rounded-full bg-orange-500"></span>
                      <span>{{ $t('traffic.upload') }}: {{ item.txFormatted }}</span>
                    </div>
                    <div 
                      class="mt-1 pt-1 font-medium"
                      :class="themeStore.isDark ? 'border-t border-gray-700' : 'border-t border-gray-200'"
                    >
                      {{ $t('traffic.total') }}: {{ item.totalFormatted }}
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <!-- X-axis labels -->
            <div class="relative h-5 mt-1">
              <div 
                v-for="label in xAxisLabels" 
                :key="label.index"
                class="absolute text-xs transform -translate-x-1/2"
                :class="themeStore.isDark ? 'text-gray-500' : 'text-gray-400'"
                :style="{ left: `${(label.index / (trafficHistory.length - 1)) * 100}%` }"
              >
                {{ label.date }}
              </div>
            </div>
          </div>
        </div>
      </template>

      <div v-else class="text-center py-8">
        <span :class="themeStore.isDark ? 'text-gray-500' : 'text-gray-400'">
          {{ $t('traffic.noHistoryData') }}
        </span>
      </div>
    </div>

    <Teleport to="body">
      <Transition name="modal">
        <div v-if="showResetConfirm && trafficData" class="modal-overlay">
          <div class="modal-backdrop" @click="showResetConfirm = false"></div>
          <div class="modal-content max-w-md">
            <div class="modal-header">
              <div>
                <h3 class="modal-title">{{ $t('traffic.resetConfirmTitle') }}</h3>
                <p class="mt-1 text-xs text-themed-muted">{{ $t('traffic.resetConfirmSubtitle') }}</p>
              </div>
              <button
                class="p-1.5 rounded-lg transition-colors"
                :class="themeStore.isDark ? 'hover:bg-gray-700' : 'hover:bg-gray-100'"
                @click="showResetConfirm = false"
              >
                <svg class="w-5 h-5 text-themed-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <div class="modal-body space-y-4">
              <div
                class="rounded-lg border p-4"
                :class="themeStore.isDark ? 'border-gray-700 bg-gray-800/50' : 'border-gray-200 bg-gray-50'"
              >
                <div class="flex items-center justify-between gap-3 text-sm">
                  <span class="text-themed-muted">{{ $t('traffic.resetCurrentUsage') }}</span>
                  <span class="font-medium" :class="themeStore.isDark ? 'text-gray-100' : 'text-gray-900'">
                    {{ trafficData.monthlyUsedFormatted }}
                  </span>
                </div>
                <div class="mt-3 flex items-center justify-between gap-3 text-sm">
                  <span class="text-themed-muted">{{ $t('traffic.resetCost') }}</span>
                  <span class="font-medium" :class="themeStore.isDark ? 'text-cyan-300' : 'text-cyan-700'">
                    {{ trafficData.resetPriceFormatted || '¥0.00' }}
                  </span>
                </div>
              </div>
              <p class="text-sm leading-6 text-themed-secondary">
                {{ $t('traffic.resetConfirmBody') }}
              </p>
            </div>
            <div class="modal-footer">
              <button class="btn-secondary" :disabled="resetting" @click="showResetConfirm = false">
                {{ $t('common.cancel') }}
              </button>
              <button class="btn-primary" :disabled="resetting" @click="confirmResetTraffic">
                <span v-if="resetting" class="loading-spinner w-4 h-4"></span>
                <template v-else>{{ $t('traffic.resetConfirmAction') }}</template>
              </button>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>
  </div>
</template>
