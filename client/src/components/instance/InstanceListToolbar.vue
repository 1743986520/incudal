<script setup lang="ts">
// 实例列表工具栏:搜索(主控制)、国家筛选下拉、版型切换、总数与每页数量。
// 纯呈现组件,不自行调用 API;筛选/版型/分页的实际处理由父页面完成。
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useThemeStore } from '@/stores/theme'
import FlagIcon from '@/components/FlagIcon.vue'
import { useInstanceDisplay } from '@/composables/useInstanceDisplay'
import type { InstanceLayoutMode } from '@/components/instance/instanceListShared'

const props = defineProps<{
  search: string
  countryFilter: string | null
  countryOptions: string[]
  layoutMode: InstanceLayoutMode
  total: number
  pageSize: number
}>()

const emit = defineEmits<{
  'update:search': [value: string]
  'change-country': [code: string | null]
  'set-layout': [mode: InstanceLayoutMode]
  'update:pageSize': [value: number]
  'page-size-change': []
}>()

const { t } = useI18n()
const themeStore = useThemeStore()
const { getCountryLabel } = useInstanceDisplay()

const pageSizeOptions = [10, 20, 30, 50, 100]

const countryRootRef = ref<HTMLElement | null>(null)
const isCountryOpen = ref(false)

const selectedCountryLabel = computed(() => (
  props.countryFilter ? getCountryLabel(props.countryFilter) : t('common.all')
))

function toggleCountryOpen(): void {
  isCountryOpen.value = !isCountryOpen.value
}

function closeCountryDropdown(): void {
  isCountryOpen.value = false
}

function selectCountry(code: string | null): void {
  emit('change-country', code)
  closeCountryDropdown()
}

function handleOutsidePointerDown(event: PointerEvent): void {
  if (!countryRootRef.value || countryRootRef.value.contains(event.target as Node)) return
  closeCountryDropdown()
}

function handleEscape(): void {
  closeCountryDropdown()
}

onMounted(() => {
  document.addEventListener('pointerdown', handleOutsidePointerDown, true)
})

onBeforeUnmount(() => {
  document.removeEventListener('pointerdown', handleOutsidePointerDown, true)
})

function onSearchInput(event: Event): void {
  emit('update:search', (event.target as HTMLInputElement).value)
}

function onPageSizeChange(event: Event): void {
  emit('update:pageSize', Number((event.target as HTMLSelectElement).value))
  emit('page-size-change')
}

function getLayoutButtonClass(mode: InstanceLayoutMode): string {
  const active = props.layoutMode === mode
  if (active) {
    return themeStore.isDark
      ? 'bg-white text-gray-900 shadow-sm'
      : 'bg-gray-900 text-white shadow-sm'
  }
  return themeStore.isDark
    ? 'text-gray-400 hover:text-gray-100'
    : 'text-gray-500 hover:text-gray-900'
}

function getCountryOptionClass(code: string | null): string {
  if (props.countryFilter === code) {
    return themeStore.isDark ? 'bg-blue-500/10 text-blue-300' : 'bg-blue-50 text-blue-700'
  }
  return themeStore.isDark ? 'text-gray-300 hover:bg-gray-800' : 'text-gray-700 hover:bg-gray-100'
}
</script>

<template>
  <div class="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
    <div class="flex flex-col gap-2 min-w-0 sm:flex-row sm:items-center">
      <div class="relative w-full sm:max-w-sm">
        <input
          :value="search"
          type="text"
          :placeholder="$t('instance.searchPlaceholder')"
          class="input pl-9 w-full"
          @input="onSearchInput"
        />
        <svg class="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 icon-themed" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
        </svg>
      </div>

      <div
        v-if="countryOptions.length > 0 || countryFilter !== null"
        ref="countryRootRef"
        class="relative self-start sm:self-auto"
        @keydown.esc.stop="handleEscape"
      >
        <button
          type="button"
          class="inline-flex h-10 max-w-[13rem] items-center gap-2 rounded-xl border px-3 text-sm font-medium transition-colors"
          :class="countryFilter !== null
            ? (themeStore.isDark ? 'border-blue-400 bg-blue-500/15 text-blue-300' : 'border-blue-500 bg-blue-50 text-blue-700')
            : (themeStore.isDark ? 'border-gray-700 bg-gray-900 text-gray-300 hover:border-gray-600' : 'border-gray-200 bg-white text-gray-600 hover:border-gray-300')"
          :aria-label="$t('instance.filterByCountry')"
          aria-haspopup="listbox"
          :aria-expanded="isCountryOpen"
          @click="toggleCountryOpen"
        >
          <FlagIcon
            v-if="countryFilter"
            :code="countryFilter"
            size="sm"
            class="shrink-0"
          />
          <svg v-else class="h-4 w-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <span class="truncate">{{ selectedCountryLabel }}</span>
          <svg
            class="h-4 w-4 shrink-0 transition-transform"
            :class="isCountryOpen ? 'rotate-180' : ''"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
          </svg>
        </button>

        <div
          v-if="isCountryOpen"
          class="absolute left-0 top-full z-30 mt-1.5 w-60 overflow-hidden rounded-xl border shadow-lg"
          :class="themeStore.isDark ? 'border-gray-700 bg-gray-900' : 'border-gray-200 bg-white'"
          role="listbox"
        >
          <div class="max-h-64 overflow-y-auto p-1.5 scrollbar-thin">
            <button
              type="button"
              class="flex h-9 w-full items-center gap-2 rounded-lg px-2.5 text-sm transition-colors"
              :class="getCountryOptionClass(null)"
              role="option"
              :aria-selected="countryFilter === null"
              @click="selectCountry(null)"
            >
              <svg class="h-4 w-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <span class="truncate font-medium">{{ $t('common.all') }}</span>
            </button>
            <button
              v-for="code in countryOptions"
              :key="code"
              type="button"
              class="flex h-9 w-full items-center gap-2 rounded-lg px-2.5 text-sm transition-colors"
              :class="getCountryOptionClass(code)"
              role="option"
              :aria-selected="countryFilter === code"
              @click="selectCountry(code)"
            >
              <FlagIcon :code="code" size="sm" class="shrink-0" />
              <span class="truncate">{{ getCountryLabel(code) }}</span>
            </button>
          </div>
        </div>
      </div>
    </div>

    <div class="flex flex-wrap items-center gap-3 lg:justify-end">
      <div
        class="hidden lg:inline-flex items-center rounded-xl border p-0.5"
        :class="themeStore.isDark ? 'border-gray-800 bg-gray-950/70' : 'border-gray-200 bg-gray-50/80'"
      >
        <button
          type="button"
          class="inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-medium transition-colors"
          :class="getLayoutButtonClass('list')"
          :title="$t('instance.listLayout')"
          :aria-label="$t('instance.listLayout')"
          @click="emit('set-layout', 'list')"
        >
          <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M4 6h16M4 12h16M4 18h16" />
          </svg>
          <span class="hidden sm:inline">{{ $t('instance.listLayout') }}</span>
        </button>
        <button
          type="button"
          class="inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-medium transition-colors"
          :class="getLayoutButtonClass('card')"
          :title="$t('instance.cardLayout')"
          :aria-label="$t('instance.cardLayout')"
          @click="emit('set-layout', 'card')"
        >
          <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M5 5h6v6H5V5zm8 0h6v6h-6V5zM5 13h6v6H5v-6zm8 0h6v6h-6v-6z" />
          </svg>
          <span class="hidden sm:inline">{{ $t('instance.cardLayout') }}</span>
        </button>
      </div>
      <span class="text-sm text-themed-muted whitespace-nowrap">{{ $t('instance.totalCount', { count: total }) }}</span>
      <div class="inline-flex items-center gap-2 shrink-0">
        <span class="text-sm text-themed-muted whitespace-nowrap">{{ $t('common.perPage') }}</span>
        <div class="relative">
          <select
            :value="pageSize"
            class="input h-10 min-w-[90px] appearance-none rounded-xl py-2 pl-3 pr-9 text-sm leading-none"
            @change="onPageSizeChange"
          >
            <option v-for="size in pageSizeOptions" :key="size" :value="size">
              {{ size }}
            </option>
          </select>
          <svg
            class="pointer-events-none absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 text-themed-muted"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
          </svg>
        </div>
      </div>
    </div>
  </div>
</template>
