<script setup lang="ts">
// 批量销毁确认弹窗。
// 纯呈现组件:预览数据、输入 DESTROY 确认与提交/关闭由父页面控制,这里只负责展示与交互上抛。
import { useThemeStore } from '@/stores/theme'
import { useInstanceDisplay } from '@/composables/useInstanceDisplay'
import type {
  BatchDestroyPreviewItem
} from '@/components/instance/instanceListShared'

defineProps<{
  loading: boolean
  submitting: boolean
  selectedCount: number
  eligibleItems: BatchDestroyPreviewItem[]
  ineligibleItems: BatchDestroyPreviewItem[]
  totalRefund: number
  totalFee: number
  confirmText: string
  canSubmit: boolean
}>()

const emit = defineEmits<{
  close: []
  confirm: []
  'update:confirmText': [value: string]
}>()

const themeStore = useThemeStore()
const { formatCurrency, translateBatchReason } = useInstanceDisplay()

function onConfirmInput(event: Event): void {
  emit('update:confirmText', (event.target as HTMLInputElement).value)
}
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
            {{ $t('instance.batch.destroyTitle') }}
          </h3>
          <p class="text-sm text-themed-muted mt-1">{{ $t('instance.batch.destroyDescription') }}</p>
        </div>
        <button class="p-1 rounded hover:bg-gray-500/20" @click="emit('close')">
          <svg class="w-5 h-5" :class="themeStore.isDark ? 'text-gray-400' : 'text-gray-500'" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>

      <div class="flex-1 overflow-y-auto p-5 space-y-4">
        <div v-if="loading" class="flex items-center justify-center py-12">
          <svg class="w-8 h-8 animate-spin text-red-500" fill="none" viewBox="0 0 24 24">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
          </svg>
        </div>

        <template v-else>
          <div class="rounded-xl border p-4" :class="themeStore.isDark ? 'border-red-500/20 bg-red-500/10' : 'border-red-200 bg-red-50'">
            <div class="flex items-start gap-3">
              <svg class="w-5 h-5 text-red-500 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
              <p class="text-sm font-medium" :class="themeStore.isDark ? 'text-red-200' : 'text-red-700'">
                {{ $t('instance.destroy.warning') }}
              </p>
            </div>
          </div>

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
              <div class="text-xs uppercase tracking-wide text-themed-muted">{{ $t('instance.batch.refundTotal') }}</div>
              <div class="mt-2 text-2xl font-semibold text-emerald-500">{{ formatCurrency(totalRefund) }}</div>
            </div>
            <div class="rounded-xl border p-4" :class="themeStore.isDark ? 'border-gray-800 bg-gray-950/60' : 'border-gray-200 bg-gray-50'">
              <div class="text-xs uppercase tracking-wide text-themed-muted">{{ $t('instance.batch.feeTotal') }}</div>
              <div class="mt-2 text-2xl font-semibold" :class="themeStore.isDark ? 'text-gray-100' : 'text-gray-900'">{{ formatCurrency(totalFee) }}</div>
            </div>
          </div>

          <div
            v-if="eligibleItems.length === 0"
            class="rounded-xl border p-4 text-sm"
            :class="themeStore.isDark ? 'border-yellow-500/20 bg-yellow-500/10 text-yellow-300' : 'border-yellow-200 bg-yellow-50 text-yellow-700'"
          >
            {{ $t('instance.batch.destroyEmpty') }}
          </div>

          <div class="rounded-xl border p-4" :class="themeStore.isDark ? 'border-gray-800 bg-gray-950/50' : 'border-gray-200 bg-white'">
            <h4 class="text-sm font-medium mb-3" :class="themeStore.isDark ? 'text-gray-100' : 'text-gray-900'">
              {{ $t('instance.batch.eligibleList', { count: eligibleItems.length }) }}
            </h4>
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
                    <div class="mt-1 text-xs text-themed-muted">
                      {{ item.instance.hostName }} · {{ item.instance.planName || $t('billing.freeInstance') }}
                    </div>
                    <div class="mt-2 flex flex-wrap gap-2 text-xs">
                      <span class="inline-flex items-center rounded-full px-2 py-0.5" :class="themeStore.isDark ? 'bg-gray-800 text-gray-300' : 'bg-gray-100 text-gray-700'">
                        {{ item.isFreeInstance ? $t('billing.freeInstance') : $t('billing.paidInstance') }}
                      </span>
                      <span
                        v-if="!item.isFreeInstance && item.isFirstTime"
                        class="inline-flex items-center rounded-full px-2 py-0.5"
                        :class="themeStore.isDark ? 'bg-emerald-500/10 text-emerald-300' : 'bg-emerald-50 text-emerald-700'"
                      >
                        {{ $t('instance.destroy.firstTimeFree') }}
                      </span>
                      <span
                        v-else-if="!item.isFreeInstance && item.feeWaiverEligible"
                        class="inline-flex items-center rounded-full px-2 py-0.5"
                        :class="themeStore.isDark ? 'bg-emerald-500/10 text-emerald-300' : 'bg-emerald-50 text-emerald-700'"
                      >
                        {{ $t('instance.batch.feeWaived') }}
                      </span>
                    </div>
                  </div>
                  <div class="text-right shrink-0">
                    <div class="text-sm font-semibold text-emerald-500">{{ formatCurrency(item.refund.refundAmount) }}</div>
                    <div class="text-xs text-themed-muted">{{ $t('instance.destroy.feeAmount') }} {{ formatCurrency(item.refund.feeAmount) }}</div>
                  </div>
                </div>
              </div>
            </div>
            <div v-else class="text-sm text-themed-muted">{{ $t('instance.batch.destroyEmpty') }}</div>
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
                :key="`destroy-skip-${item.id}`"
                class="rounded-lg border px-3 py-2"
                :class="themeStore.isDark ? 'border-gray-800 bg-black/20' : 'border-gray-200 bg-gray-50/80'"
              >
                <div class="text-sm font-medium" :class="themeStore.isDark ? 'text-gray-100' : 'text-gray-900'">{{ item.name }}</div>
                <div class="mt-1 text-xs" :class="themeStore.isDark ? 'text-red-300' : 'text-red-600'">
                  {{ item.cannotDestroyReason ? translateBatchReason(item.cannotDestroyReason) : $t('instance.destroy.cannotDestroy') }}
                </div>
              </div>
            </div>
          </div>

          <div class="rounded-xl border p-4" :class="themeStore.isDark ? 'border-gray-800 bg-gray-950/50' : 'border-gray-200 bg-gray-50/80'">
            <label class="block text-sm font-medium mb-2" :class="themeStore.isDark ? 'text-gray-100' : 'text-gray-900'">
              {{ $t('instance.batch.confirmHint') }}
            </label>
            <input
              :value="confirmText"
              type="text"
              class="input w-full"
              :placeholder="$t('instance.batch.confirmPlaceholder')"
              @input="onConfirmInput"
            />
          </div>
        </template>
      </div>

      <div class="flex items-center justify-between gap-3 px-5 py-4 border-t" :class="themeStore.isDark ? 'border-gray-800' : 'border-gray-200'">
        <span class="text-xs text-themed-muted">{{ $t('instance.batch.currentPageOnly') }}</span>
        <div class="flex items-center gap-2">
          <button class="btn-ghost btn-sm" :disabled="submitting" @click="emit('close')">
            {{ $t('common.cancel') }}
          </button>
          <button
            class="btn-sm text-white"
            :class="themeStore.isDark ? 'bg-red-500/80 hover:bg-red-500 disabled:bg-red-500/40' : 'bg-red-500 hover:bg-red-600 disabled:bg-red-300'"
            :disabled="!canSubmit"
            @click="emit('confirm')"
          >
            <svg v-if="submitting" class="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
              <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
            </svg>
            {{ $t('instance.batch.destroy') }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>
