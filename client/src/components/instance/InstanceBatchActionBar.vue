<script setup lang="ts">
// 批量操作条:展示已选数量与批量动作入口。
// 常用启停/重启/同步直接展示,低频的自动续费与续费收进"更多"菜单;
// 销毁保持独立按钮,沿用父页面的确认与预览流程。
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useThemeStore } from '@/stores/theme'
import { useConfigStore } from '@/stores/config'
import { freeSiteCopy } from '@/utils/freeSiteFun'
import type { BatchSimpleAction } from '@/components/instance/instanceListShared'

const props = defineProps<{
  selectedCount: number
  selectedStoppedCount: number
  selectedRunningCount: number
  selectedPaidCount: number
  batchActionLoading: string
  batchRenewSubmitting: boolean
  batchDestroySubmitting: boolean
  disabledByAdminContext: boolean
}>()

const emit = defineEmits<{
  clear: []
  'simple-action': [action: BatchSimpleAction]
  'auto-renew': [autoRenew: boolean]
  'open-renew': []
  'open-destroy': []
}>()

const { t } = useI18n()
const themeStore = useThemeStore()
const configStore = useConfigStore()

const hasSelectedInstances = computed(() => props.selectedCount > 0)

const busy = computed(() =>
  !!props.batchActionLoading || props.batchRenewSubmitting || props.batchDestroySubmitting
)

const moreRootRef = ref<HTMLElement | null>(null)
const isMoreOpen = ref(false)

const autoRenewDisabled = computed(() =>
  props.selectedPaidCount === 0 || props.disabledByAdminContext || busy.value
)

function toggleMore(): void {
  isMoreOpen.value = !isMoreOpen.value
}

function closeMore(): void {
  isMoreOpen.value = false
}

function handleOutsidePointerDown(event: PointerEvent): void {
  if (!moreRootRef.value || moreRootRef.value.contains(event.target as Node)) return
  closeMore()
}

onMounted(() => {
  document.addEventListener('pointerdown', handleOutsidePointerDown, true)
})

onBeforeUnmount(() => {
  document.removeEventListener('pointerdown', handleOutsidePointerDown, true)
})

function getSpinner(action: string): boolean {
  return props.batchActionLoading === action
}
</script>

<template>
  <div class="card p-4 space-y-4">
    <div class="flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
      <div class="flex flex-wrap items-center gap-3">
        <div
          class="inline-flex items-center gap-2 rounded-full px-3 py-1 text-sm font-medium"
          :class="themeStore.isDark ? 'bg-blue-500/15 text-blue-300' : 'bg-blue-50 text-blue-700'"
        >
          <span class="inline-flex h-2 w-2 rounded-full bg-current"></span>
          {{ $t('instance.batch.selectedCount', { count: selectedCount }) }}
        </div>
        <span class="text-sm text-themed-muted">{{ $t('instance.batch.currentPageOnly') }}</span>
        <button class="btn-ghost btn-sm" @click="emit('clear')">
          {{ $t('instance.batch.clear') }}
        </button>
      </div>

      <div class="flex flex-wrap items-center gap-2">
        <button
          class="btn-ghost btn-sm"
          :disabled="selectedStoppedCount === 0 || busy"
          @click="emit('simple-action', 'start')"
        >
          <svg v-if="getSpinner('start')" class="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
          </svg>
          {{ $t('instance.batch.start') }}
        </button>
        <button
          class="btn-ghost btn-sm"
          :disabled="selectedRunningCount === 0 || busy"
          @click="emit('simple-action', 'stop')"
        >
          <svg v-if="getSpinner('stop')" class="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
          </svg>
          {{ $t('instance.batch.stop') }}
        </button>
        <button
          class="btn-ghost btn-sm"
          :disabled="selectedRunningCount === 0 || busy"
          @click="emit('simple-action', 'restart')"
        >
          <svg v-if="getSpinner('restart')" class="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
          </svg>
          {{ $t('instance.batch.restart') }}
        </button>
        <button
          class="btn-ghost btn-sm"
          :disabled="!hasSelectedInstances || busy"
          @click="emit('simple-action', 'sync')"
        >
          <svg v-if="getSpinner('sync')" class="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
          </svg>
          {{ $t('instance.batch.sync') }}
        </button>

        <div
          ref="moreRootRef"
          class="relative"
          @keydown.esc.stop="closeMore"
        >
          <button
            type="button"
            class="btn-ghost btn-sm inline-flex items-center gap-1"
            :aria-label="$t('common.more')"
            aria-haspopup="menu"
            :aria-expanded="isMoreOpen"
            @click="toggleMore"
          >
            {{ $t('common.more') }}
            <svg
              class="h-3.5 w-3.5 transition-transform"
              :class="isMoreOpen ? 'rotate-180' : ''"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
            </svg>
          </button>

          <div
            v-if="isMoreOpen"
            class="absolute right-0 top-full z-30 mt-1.5 w-52 overflow-hidden rounded-xl border shadow-lg"
            :class="themeStore.isDark ? 'border-gray-700 bg-gray-900' : 'border-gray-200 bg-white'"
            role="menu"
          >
            <div class="p-1.5">
              <button
                type="button"
                class="flex h-9 w-full items-center rounded-lg px-3 text-sm transition-colors disabled:cursor-not-allowed disabled:opacity-40"
                :class="themeStore.isDark ? 'text-gray-300 hover:bg-gray-800' : 'text-gray-700 hover:bg-gray-100'"
                :disabled="autoRenewDisabled"
                role="menuitem"
                @click="closeMore(); emit('auto-renew', true)"
              >
                {{ $t('instance.batch.autoRenewOn') }}
              </button>
              <button
                type="button"
                class="flex h-9 w-full items-center rounded-lg px-3 text-sm transition-colors disabled:cursor-not-allowed disabled:opacity-40"
                :class="themeStore.isDark ? 'text-gray-300 hover:bg-gray-800' : 'text-gray-700 hover:bg-gray-100'"
                :disabled="autoRenewDisabled"
                role="menuitem"
                @click="closeMore(); emit('auto-renew', false)"
              >
                {{ $t('instance.batch.autoRenewOff') }}
              </button>
              <button
                type="button"
                class="flex h-9 w-full items-center rounded-lg px-3 text-sm transition-colors disabled:cursor-not-allowed disabled:opacity-40"
                :class="themeStore.isDark ? 'text-gray-300 hover:bg-gray-800' : 'text-gray-700 hover:bg-gray-100'"
                :disabled="selectedPaidCount === 0 || disabledByAdminContext || busy"
                role="menuitem"
                @click="closeMore(); emit('open-renew')"
              >
                {{ configStore.freeSiteMode ? freeSiteCopy.instanceBatchRenewAction : t('instance.batch.renew') }}
              </button>
            </div>
          </div>
        </div>

        <button
          class="btn-danger btn-sm"
          :disabled="!hasSelectedInstances || disabledByAdminContext || busy"
          @click="emit('open-destroy')"
        >
          {{ $t('instance.batch.destroy') }}
        </button>
      </div>
    </div>
  </div>
</template>
