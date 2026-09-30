<script setup lang="ts">
// 批量续费确认弹窗。
// 纯呈现组件:预览数据与提交/关闭由父页面控制,这里只负责展示与交互上抛。
import { useThemeStore } from '@/stores/theme'
import { useConfigStore } from '@/stores/config'
import { freeSiteCopy } from '@/utils/freeSiteFun'
import { useInstanceDisplay } from '@/composables/useInstanceDisplay'
import type { UserBalance } from '@/types/api'
import type {
  BatchRenewEligibleItem,
  BatchRenewPreviewItem
} from '@/components/instance/instanceListShared'

defineProps<{
  loading: boolean
  submitting: boolean
  selectedCount: number
  monthOptions: number[]
  months: number
  eligibleItems: BatchRenewEligibleItem[]
  ineligibleItems: BatchRenewPreviewItem[]
  total: number
  balance: UserBalance
  balanceAfter: number
  insufficientBalance: boolean
  canSubmit: boolean
}>()

const emit = defineEmits<{
  close: []
  confirm: []
  'update:months': [months: number]
}>()

const themeStore = useThemeStore()
const configStore = useConfigStore()
const { formatCurrency, getBatchRenewMonthsLabel, formatDate, translateBatchReason } = useInstanceDisplay()
</script>

<template>
  <div
    class="fixed inset-0 z-50 flex items-center justify-center p-4"
    @click.self="emit('close')"
  >
    <div class="absolute inset-0 bg-black/60" @click="emit('close')"></div>
    <div
      class="relative w-full max-w-4xl max-h-[90vh] overflow-hidden rounded-2xl shadow-2xl flex flex-col"
      :class="themeStore.isDark ? 'bg-gray-900 border border-gray-800' : 'bg-white border border-gray-200'"
    >
      <div class="flex items-center justify-between px-5 py-4 border-b" :class="themeStore.isDark ? 'border-gray-800' : 'border-gray-200'">
        <div>
          <h3 class="text-lg font-semibold" :class="themeStore.isDark ? 'text-gray-100' : 'text-gray-900'">
            {{ configStore.freeSiteMode ? freeSiteCopy.instanceBatchRenewTitle : $t('instance.batch.renewTitle') }}
          </h3>
          <p class="text-sm text-themed-muted mt-1">{{ configStore.freeSiteMode ? freeSiteCopy.instanceBatchRenewDescription : $t('instance.batch.renewDescription') }}</p>
        </div>
        <button class="p-1 rounded hover:bg-gray-500/20" @click="emit('close')">
          <svg class="w-5 h-5" :class="themeStore.isDark ? 'text-gray-400' : 'text-gray-500'" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>

      <div class="flex-1 overflow-y-auto p-5 space-y-4">
        <div v-if="loading" class="flex items-center justify-center py-12">
          <svg class="w-8 h-8 animate-spin text-blue-500" fill="none" viewBox="0 0 24 24">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
          </svg>
        </div>

        <template v-else>
          <div class="grid gap-3 md:grid-cols-4">
            <div class="rounded-xl border p-4" :class="themeStore.isDark ? 'border-gray-800 bg-gray-950/60' : 'border-gray-200 bg-gray-50'">
              <div class="text-xs uppercase tracking-wide text-themed-muted">{{ $t('instance.batch.selectedCount', { count: selectedCount }) }}</div>
              <div class="mt-2 text-2xl font-semibold" :class="themeStore.isDark ? 'text-gray-100' : 'text-gray-900'">{{ selectedCount }}</div>
            </div>
            <div class="rounded-xl border p-4" :class="themeStore.isDark ? 'border-gray-800 bg-gray-950/60' : 'border-gray-200 bg-gray-50'">
              <div class="text-xs uppercase tracking-wide text-themed-muted">{{ $t('instance.batch.eligibleCount') }}</div>
              <div class="mt-2 text-2xl font-semibold text-emerald-500">{{ eligibleItems.length }}</div>
            </div>
            <div class="rounded-xl border p-4" :class="themeStore.isDark ? 'border-gray-800 bg-gray-950/60' : 'border-gray-200 bg-gray-50'">
              <div class="text-xs uppercase tracking-wide text-themed-muted">{{ configStore.freeSiteMode ? freeSiteCopy.instanceBatchTotalAmount : $t('instance.batch.totalAmount') }}</div>
              <div class="mt-2 text-2xl font-semibold" :class="themeStore.isDark ? 'text-gray-100' : 'text-gray-900'">{{ formatCurrency(total) }}</div>
            </div>
            <div class="rounded-xl border p-4" :class="themeStore.isDark ? 'border-gray-800 bg-gray-950/60' : 'border-gray-200 bg-gray-50'">
              <div class="text-xs uppercase tracking-wide text-themed-muted">{{ configStore.freeSiteMode ? freeSiteCopy.instanceBatchBalanceAfter : $t('billing.balanceAfterRenew') }}</div>
              <div class="mt-2 text-2xl font-semibold" :class="insufficientBalance ? 'text-red-500' : 'text-blue-500'">{{ formatCurrency(balanceAfter) }}</div>
            </div>
          </div>

          <div v-if="monthOptions.length > 0" class="rounded-xl border p-4" :class="themeStore.isDark ? 'border-gray-800 bg-gray-950/50' : 'border-gray-200 bg-gray-50/80'">
            <div class="text-sm font-medium" :class="themeStore.isDark ? 'text-gray-100' : 'text-gray-900'">{{ $t('instance.batch.selectedMonths') }}</div>
            <div class="mt-3 flex flex-wrap gap-2">
              <button
                v-for="option in monthOptions"
                :key="option"
                class="px-3 py-2 rounded-lg border text-sm transition-colors"
                :class="option === months
                  ? 'border-blue-500 bg-blue-500/10 text-blue-500'
                  : themeStore.isDark
                    ? 'border-gray-700 text-gray-300 hover:border-gray-600'
                    : 'border-gray-200 text-gray-700 hover:border-gray-300'"
                @click="emit('update:months', option)"
              >
                {{ getBatchRenewMonthsLabel(option) }}
              </button>
            </div>
          </div>

          <div
            v-else
            class="rounded-xl border p-4 text-sm"
            :class="themeStore.isDark ? 'border-yellow-500/20 bg-yellow-500/10 text-yellow-300' : 'border-yellow-200 bg-yellow-50 text-yellow-700'"
          >
            {{ $t('instance.batch.renewEmpty') }}
          </div>

          <div
            v-if="insufficientBalance"
            class="rounded-xl border p-4 text-sm"
            :class="themeStore.isDark ? 'border-red-500/20 bg-red-500/10 text-red-300' : 'border-red-200 bg-red-50 text-red-700'"
          >
            {{ $t('billing.insufficientBalance') }}
            <RouterLink to="/wallet" class="underline ml-1">{{ $t('billing.goRecharge') }}</RouterLink>
          </div>

          <div class="rounded-xl border p-4" :class="themeStore.isDark ? 'border-gray-800 bg-gray-950/50' : 'border-gray-200 bg-white'">
            <div class="flex items-center justify-between gap-3 mb-3">
              <h4 class="text-sm font-medium" :class="themeStore.isDark ? 'text-gray-100' : 'text-gray-900'">
                {{ $t('instance.batch.eligibleList', { count: eligibleItems.length }) }}
              </h4>
              <span class="text-xs text-themed-muted">{{ configStore.freeSiteMode ? freeSiteCopy.instanceBatchCurrentBalance : $t('billing.currentBalance') }}: {{ formatCurrency(balance.balance) }}</span>
            </div>
            <div v-if="eligibleItems.length > 0" class="space-y-3 max-h-64 overflow-y-auto pr-1">
              <div
                v-for="item in eligibleItems"
                :key="item.id"
                class="rounded-xl border px-3 py-3"
                :class="themeStore.isDark ? 'border-gray-800 bg-black/20' : 'border-gray-200 bg-gray-50/80'"
              >
                <div class="flex items-start justify-between gap-3">
                  <div class="min-w-0">
                    <div class="text-sm font-medium truncate" :class="themeStore.isDark ? 'text-gray-100' : 'text-gray-900'">{{ item.name }}</div>
                    <div class="mt-1 flex flex-wrap gap-2 text-xs">
                      <span class="inline-flex items-center rounded-full px-2 py-0.5" :class="themeStore.isDark ? 'bg-gray-800 text-gray-300' : 'bg-gray-100 text-gray-700'">
                        {{ item.autoRenew ? $t('billing.autoRenewEnabled') : $t('billing.autoRenewDisabled') }}
                      </span>
                      <span
                        v-if="item.isHostedInstance"
                        class="inline-flex items-center rounded-full px-2 py-0.5"
                        :class="themeStore.isDark ? 'bg-blue-500/10 text-blue-300' : 'bg-blue-50 text-blue-700'"
                      >
                        {{ $t('instance.batch.hosted') }}
                      </span>
                    </div>
                  </div>
                  <div class="text-right shrink-0">
                    <div class="text-sm font-semibold text-emerald-500">{{ formatCurrency(item.selectedOption?.discountedPrice) }}</div>
                    <div class="text-xs text-themed-muted">{{ formatDate(item.selectedOption?.expiresAt) }}</div>
                  </div>
                </div>
              </div>
            </div>
            <div v-else class="text-sm text-themed-muted">{{ $t('instance.batch.renewEmpty') }}</div>
          </div>

          <div
            v-if="ineligibleItems.length > 0"
            class="rounded-xl border p-4"
            :class="themeStore.isDark ? 'border-gray-800 bg-gray-950/50' : 'border-gray-200 bg-white'"
          >
            <h4 class="text-sm font-medium mb-3" :class="themeStore.isDark ? 'text-gray-100' : 'text-gray-900'">
              {{ $t('instance.batch.skippedList', { count: ineligibleItems.length }) }}
            </h4>
            <div class="space-y-2 max-h-56 overflow-y-auto pr-1">
              <div
                v-for="item in ineligibleItems"
                :key="`renew-skip-${item.id}`"
                class="rounded-lg border px-3 py-2"
                :class="themeStore.isDark ? 'border-gray-800 bg-black/20' : 'border-gray-200 bg-gray-50/80'"
              >
                <div class="text-sm font-medium" :class="themeStore.isDark ? 'text-gray-100' : 'text-gray-900'">{{ item.name }}</div>
                <div class="mt-1 text-xs" :class="themeStore.isDark ? 'text-red-300' : 'text-red-600'">
                  {{ translateBatchReason(item.reason || (item.canRenew ? '该实例不支持当前续费时长' : undefined)) }}
                </div>
              </div>
            </div>
          </div>
        </template>
      </div>

      <div class="flex items-center justify-between gap-3 px-5 py-4 border-t" :class="themeStore.isDark ? 'border-gray-800' : 'border-gray-200'">
        <span class="text-xs text-themed-muted">{{ $t('instance.batch.currentPageOnly') }}</span>
        <div class="flex items-center gap-2">
          <button class="btn-ghost btn-sm" :disabled="submitting" @click="emit('close')">
            {{ $t('common.cancel') }}
          </button>
          <button class="btn-primary btn-sm" :disabled="!canSubmit" @click="emit('confirm')">
            <svg v-if="submitting" class="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
              <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
            </svg>
            {{ configStore.freeSiteMode ? freeSiteCopy.instanceBatchRenewAction : $t('instance.batch.renew') }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>
