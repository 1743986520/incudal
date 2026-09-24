<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { useThemeStore } from '@/stores/theme'
import { formatBytes, formatDisk, formatMemory } from '@/utils/formatters'
import type { PackagePlan } from '@/types/api'
import { formatTrafficUnitPrice } from '@/utils/trafficBilling'

type PlanStatus = 'active' | 'soldOut' | 'inactive'

const props = defineProps<{
  plan: PackagePlan
  instanceType?: 'container' | 'vm'
  updatingStatus?: boolean
}>()

const emit = defineEmits<{
  (e: 'edit', plan: PackagePlan): void
  (e: 'delete', plan: PackagePlan): void
  (e: 'status-change', plan: PackagePlan, status: PlanStatus): void
}>()

const { t } = useI18n()
const themeStore = useThemeStore()

const currentStatus = computed<PlanStatus>(() => {
  if (!props.plan.isActive) return 'inactive'
  if (props.plan.isSoldOut) return 'soldOut'
  return 'active'
})

const statusOptions = computed(() => [
  { value: 'active' as PlanStatus, label: t('resources.plans.statusActive') },
  { value: 'soldOut' as PlanStatus, label: t('resources.plans.statusSoldOut') },
  { value: 'inactive' as PlanStatus, label: t('resources.plans.statusInactive') }
])

function formatPrice(cents: number | null | undefined): string {
  return ((cents || 0) / 100).toFixed(2)
}

function formatTraffic(bytes: string | null | undefined): string {
  if (!bytes || bytes === '0') return props.plan.trafficBillingMode === 'usage' ? '0 GB' : '-'
  const value = Number(bytes)
  if (!Number.isFinite(value) || value <= 0) return '-'
  return formatBytes(value)
}

function formatSpeed(bytes: string | null | undefined): string {
  if (!bytes || bytes === '0') return '-'
  const value = Number(bytes)
  if (!Number.isFinite(value) || value <= 0) return '-'
  return `${Math.round(value / (1024 * 1024))} Mbps`
}

function getBillingCycleLabel(months: number): string {
  const labels: Record<number, string> = {
    1: t('resources.plans.monthly'),
    3: t('resources.plans.quarterly'),
    6: t('resources.plans.semiAnnual'),
    12: t('resources.plans.yearly')
  }
  return labels[months] || `${months} ${t('resources.plans.months')}`
}

function getStatusButtonClass(status: PlanStatus): string {
  const selected = currentStatus.value === status
  if (!selected) {
    return themeStore.isDark
      ? 'text-gray-500 hover:bg-gray-800 hover:text-gray-200'
      : 'text-gray-500 hover:bg-gray-100 hover:text-gray-900'
  }
  if (status === 'active') {
    return themeStore.isDark
      ? 'bg-emerald-500/15 text-emerald-300 ring-1 ring-emerald-500/25'
      : 'bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200'
  }
  if (status === 'soldOut') {
    return themeStore.isDark
      ? 'bg-amber-500/15 text-amber-300 ring-1 ring-amber-500/25'
      : 'bg-amber-50 text-amber-700 ring-1 ring-amber-200'
  }
  return themeStore.isDark
    ? 'bg-gray-800 text-gray-200 ring-1 ring-gray-700'
    : 'bg-gray-100 text-gray-700 ring-1 ring-gray-200'
}

function emitStatus(status: PlanStatus): void {
  if (status === currentStatus.value || props.updatingStatus) return
  emit('status-change', props.plan, status)
}
</script>

<template>
  <article
    class="rounded-lg border p-5 transition-colors"
    :class="themeStore.isDark ? 'border-gray-800 bg-gray-950/40 hover:border-gray-700' : 'border-gray-200 bg-white hover:border-gray-300'"
  >
    <div class="grid gap-5 lg:grid-cols-[1fr_auto] lg:items-start">
      <div class="min-w-0 flex-1">
        <div class="flex flex-wrap items-center gap-2">
          <h3 class="truncate text-base font-semibold text-themed">{{ plan.name }}</h3>
          <span
            class="rounded-full px-2 py-0.5 text-xs font-medium"
            :class="currentStatus === 'active'
              ? 'bg-emerald-50 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300'
              : currentStatus === 'soldOut'
                ? 'bg-amber-50 text-amber-700 dark:bg-amber-500/15 dark:text-amber-300'
                : 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-300'"
          >
            {{ statusOptions.find(option => option.value === currentStatus)?.label }}
          </span>
          <span
            class="rounded-full px-2 py-0.5 text-xs font-medium"
            :class="plan.billingMode === 'hourly'
              ? 'bg-blue-50 text-blue-700 dark:bg-blue-500/15 dark:text-blue-300'
              : 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-300'"
          >
            {{ t(plan.billingMode === 'hourly' ? 'resources.plans.hourlyBilling' : 'resources.plans.packageBilling') }}
          </span>
        </div>
        <p v-if="plan.description" class="mt-1 max-w-3xl text-sm text-themed-muted">{{ plan.description }}</p>
      </div>

      <div class="flex flex-col gap-3 lg:items-end">
        <div class="text-left lg:text-right">
          <template v-if="plan.billingMode === 'hourly'">
            <div class="text-lg font-semibold tracking-normal text-themed">{{ t('resources.plans.hourlyBilling') }}</div>
            <div class="text-xs text-themed-muted">{{ t('resources.plans.hourlyBillingPriceHint') }}</div>
          </template>
          <template v-else>
            <div class="text-2xl font-semibold tracking-normal text-themed">¥{{ formatPrice(plan.price) }}</div>
            <div class="text-xs text-themed-muted">{{ getBillingCycleLabel(plan.billingCycle) }}</div>
          </template>
        </div>
      </div>
    </div>

    <div class="mt-5 grid gap-x-8 gap-y-4 border-t pt-5 sm:grid-cols-2 xl:grid-cols-4" :class="themeStore.isDark ? 'border-gray-800' : 'border-gray-100'">
      <div>
        <div class="text-xs text-themed-muted">{{ t('resources.plans.resourceConfig') }}</div>
        <div class="mt-1 text-sm font-medium text-themed">{{ plan.cpu }}% CPU</div>
        <div class="text-xs text-themed-muted">{{ formatMemory(plan.memory) }} / {{ formatDisk(plan.disk) }}</div>
      </div>
      <div>
        <div class="text-xs text-themed-muted">{{ t(plan.trafficBillingMode === 'usage' ? 'resources.plans.includedTraffic' : 'resources.plans.trafficLimit') }}</div>
        <div class="mt-1 text-sm font-medium text-themed">{{ formatTraffic(plan.trafficLimit) }}</div>
        <div v-if="plan.trafficBillingMode === 'usage'" class="text-xs text-themed-muted">¥{{ formatTrafficUnitPrice(plan.trafficUnitPrice) }} / GB · {{ t('resources.plans.settlementHourly') }}</div>
        <div v-else class="text-xs text-themed-muted">{{ formatSpeed(plan.trafficLimitSpeed) }}</div>
      </div>
      <div>
        <div class="text-xs text-themed-muted">{{ t('resources.plans.quota') }}</div>
        <div class="mt-1 text-sm font-medium text-themed">{{ t('resources.plans.portLimit') }} {{ plan.portLimit }} · {{ t('resources.plans.snapshotLimit') }} {{ plan.snapshotLimit }}</div>
        <div class="text-xs text-themed-muted">{{ t('resources.plans.siteLimit') }} {{ plan.siteLimit }}</div>
      </div>
      <div>
        <div class="text-xs text-themed-muted">{{ t('resources.plans.trafficReset') }}</div>
        <div class="mt-1 text-sm font-medium text-themed">
          <template v-if="plan.trafficBillingMode === 'usage'">{{ t('resources.plans.usageTraffic') }}</template>
          <template v-else-if="plan.trafficResetEnabled">¥{{ formatPrice(plan.trafficResetPrice || 0) }}/{{ t('resources.plans.perReset') }}</template>
          <template v-else>{{ t('resources.plans.trafficResetDisabled') }}</template>
        </div>
        <div class="text-xs text-themed-muted">
          {{ t('resources.plans.slaGuarantee') }} {{ plan.slaGuarantee ?? '-' }}%
        </div>
      </div>
    </div>

    <div class="mt-4 flex flex-wrap gap-x-5 gap-y-1 text-xs text-themed-muted">
      <span v-if="instanceType !== 'vm'">{{ t('resources.plans.swapSize') }} {{ plan.swapSize || 0 }} MB</span>
      <span>{{ t('resources.plans.sortOrder') }} {{ plan.sortOrder }}</span>
    </div>

    <div class="mt-4 flex flex-wrap items-center justify-between gap-3 border-t pt-4" :class="themeStore.isDark ? 'border-gray-800' : 'border-gray-100'">
      <div class="inline-grid grid-cols-3 rounded-lg border p-0.5 text-xs" :class="themeStore.isDark ? 'border-gray-800 bg-gray-950' : 'border-gray-200 bg-white'">
        <button
          v-for="option in statusOptions"
          :key="option.value"
          type="button"
          class="rounded-md px-3 py-1.5 font-medium transition-colors disabled:cursor-wait disabled:opacity-70"
          :class="getStatusButtonClass(option.value)"
          :disabled="updatingStatus"
          @click="emitStatus(option.value)"
        >
          {{ option.label }}
        </button>
      </div>

      <div class="flex shrink-0 items-center gap-2">
        <button
          type="button"
          class="btn-secondary btn-sm"
          @click="emit('edit', plan)"
        >
          {{ t('common.edit') }}
        </button>
        <button
          type="button"
          class="btn-ghost btn-sm text-error"
          @click="emit('delete', plan)"
        >
          {{ t('common.delete') }}
        </button>
      </div>
    </div>
  </article>
</template>
