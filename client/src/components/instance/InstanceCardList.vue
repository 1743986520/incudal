<script setup lang="ts">
// 实例列表卡片布局:手机端卡片堆叠(sm 以下)与桌面端卡片网格。
// 纯呈现组件:选择、启停、排序等操作通过事件上抛,由父页面处理。
import { useI18n } from 'vue-i18n'
import { useAuthStore } from '@/stores/auth'
import { useThemeStore } from '@/stores/theme'
import { formatMemory, formatDisk, formatBytes, getStatusInfo } from '@/utils/formatters'
import FlagIcon from '@/components/FlagIcon.vue'
import DistroIcon from '@/components/icons/DistroIcon.vue'
import InstanceDisplayIcon from '@/components/InstanceDisplayIcon.vue'
import InstanceOrderMenu from '@/components/instance/InstanceOrderMenu.vue'
import { useInstanceDisplay } from '@/composables/useInstanceDisplay'
import {
  INSTANCE_ORDER_ACTIONS,
  type InstanceOrderAction,
  type InstanceRowAction
} from '@/components/instance/instanceListShared'
import type { Instance } from '@/types/api'

const props = defineProps<{
  instances: Instance[]
  selectedIds: Set<number>
  isAdmin: boolean
  actionLoading: Record<number, string>
  orderLoading: boolean
  recentlyOrderedInstanceId: number | null
  canReorderInstances: boolean
  orderLabels: Record<InstanceOrderAction, string>
  getOrderDisabledActions: (instanceId: number) => Record<InstanceOrderAction, boolean>
}>()

const emit = defineEmits<{
  'toggle-select': [id: number]
  'open-detail': [id: number]
  'row-action': [instance: Instance, action: InstanceRowAction]
  reorder: [instance: Instance, action: InstanceOrderAction]
}>()

const { t } = useI18n()
const themeStore = useThemeStore()
const authStore = useAuthStore()
const {
  getIps,
  isHourlyInstance,
  getDistroFromName,
  getPaidIconType,
  formatImageName,
  getInstanceExpiryInfo,
  getInstanceHostName,
  getInstancePackageName,
  getInstanceTypeBadgeClass,
  getInstanceTypeDisplayLabel,
  getInstanceNetworkMode,
  getInstanceNetworkModeClass,
  getCardActionButtonClass
} = useInstanceDisplay()

function canRetryProvision(instance: Instance): boolean {
  return instance.status?.toLowerCase() === 'error'
    && (props.isAdmin || instance.userId === undefined || instance.userId === authStore.user?.id)
}

function canDeleteInstance(instance: Instance): boolean {
  return (instance.status?.toLowerCase() === 'error' || isHourlyInstance(instance) || !instance.packagePlanId)
    && (instance as any).allow_instance_deletion !== false
}
</script>

<template>
  <div>
    <TransitionGroup name="instance-stack-order" tag="div" class="space-y-3 sm:hidden">
      <div
        v-for="instance in instances"
        :key="instance.id"
        class="card overflow-hidden transition-all"
        :class="[
          instance.status?.toLowerCase() === 'creating' ? 'creating-card' : '',
          recentlyOrderedInstanceId === instance.id ? (themeStore.isDark ? 'is-order-feedback-dark' : 'is-order-feedback-light') : '',
          selectedIds.has(instance.id) ? (themeStore.isDark ? 'ring-1 ring-blue-500/40' : 'ring-1 ring-blue-500/30') : ''
        ]"
      >
        <div class="block p-4">
          <div class="flex items-start gap-3 mb-3">
            <div class="pt-1 shrink-0" @click.stop>
              <input
                type="checkbox"
                class="w-5 h-5 rounded border-gray-300 text-primary focus:ring-primary cursor-pointer touch-manipulation"
                :checked="selectedIds.has(instance.id)"
                @click.stop
                @change.stop="emit('toggle-select', instance.id)"
              />
            </div>
            <div
              class="w-11 h-11 rounded-lg flex items-center justify-center flex-shrink-0 overflow-hidden"
              :class="themeStore.isDark ? 'bg-gray-800' : 'bg-gray-100'"
            >
              <InstanceDisplayIcon
                v-if="instance.iconBadgeId || getPaidIconType(instance)"
                :badge-id="instance.iconBadgeId"
                :fallback-icon="getPaidIconType(instance)"
                :alt="instance.name"
                :size="44"
              />
              <DistroIcon
                v-else
                :distro="getDistroFromName(instance.image)"
                :size="40"
              />
            </div>
            <div class="flex-1 min-w-0 cursor-pointer" @click="emit('open-detail', instance.id)">
                  <div class="flex items-center gap-2 mb-1">
                    <div
                    class="font-semibold truncate"
                    :class="themeStore.isDark ? 'text-gray-100' : 'text-gray-900'"
                  >
                    {{ instance.name }}
                  </div>
                  <span :class="['badge badge-sm inline-flex items-center gap-1 flex-shrink-0', getStatusInfo(instance.status, t).class]">
                    <span :class="['w-1 h-1 rounded-full', getStatusInfo(instance.status, t).dot]"></span>
                    <span class="text-[10px]">{{ getStatusInfo(instance.status, t).label }}</span>
                  </span>
                  <span v-if="isHourlyInstance(instance)" class="badge badge-sm flex-shrink-0 bg-blue-500/10 text-blue-500">{{ $t('hourlyBilling.badge') }}</span>
                </div>
                <div
                  class="text-xs truncate"
                  :class="themeStore.isDark ? 'text-gray-500' : 'text-gray-500'"
                >
                  {{ formatImageName(instance.image, (instance as any).imageName) }}
                </div>
              </div>
              <div class="flex flex-col items-end gap-1 shrink-0">
                <span
                  v-if="(instance as any).packageName"
                  class="text-xs px-2 py-1 rounded truncate max-w-[130px]"
                  :class="themeStore.isDark ? 'bg-blue-500/10 text-blue-400' : 'bg-blue-50 text-blue-600'"
                  :title="(instance as any).packageName"
                  @click="emit('open-detail', instance.id)"
                >
                  {{ (instance as any).packageName }}
                </span>
                <span
                  class="inline-flex max-w-[140px] items-center gap-1.5 px-2 py-1 rounded text-xs"
                  :class="themeStore.isDark ? 'bg-gray-900 text-gray-300' : 'bg-gray-100 text-gray-600'"
                  :title="getInstanceHostName(instance)"
                  @click="emit('open-detail', instance.id)"
                >
                  <FlagIcon :code="(instance as any).host?.country_code || (instance as any).hostCountryCode || 'us'" size="xs" class="shrink-0" />
                  <span class="uppercase truncate font-medium">{{ getInstanceHostName(instance) }}</span>
                </span>
              </div>
            </div>

            <div class="space-y-2 text-sm cursor-pointer" @click="emit('open-detail', instance.id)">
              <div class="flex items-start justify-between">
                <span class="text-themed-muted text-xs mt-0.5">{{ $t('instance.mobileCard.ipAddress') }}</span>
                <div class="flex flex-col items-end gap-1">
                  <template v-if="getIps(instance).length > 0">
                    <span
                      v-for="(ipObj, idx) in getIps(instance)"
                      :key="idx"
                      class="font-mono text-xs max-w-[200px] truncate"
                      :class="[themeStore.isDark ? 'text-gray-300' : 'text-gray-700', ipObj.type === 'ipv6' ? 'opacity-75' : '']"
                      :title="ipObj.ip"
                    >
                      {{ ipObj.type === 'ipv6' ? (ipObj.ip.length > 18 ? ipObj.ip.substring(0, 18) + '...' : ipObj.ip) : ipObj.ip }}
                    </span>
                  </template>
                  <span v-else class="text-themed-muted text-xs">-</span>
                </div>
              </div>
              <div class="flex items-center justify-between">
                <span class="text-themed-muted text-xs">{{ $t('instance.mobileCard.config') }}</span>
                <span
                  class="text-xs"
                  :class="themeStore.isDark ? 'text-gray-300' : 'text-gray-700'"
                >
                  {{ instance.cpu }}{{ $t('instance.mobileCard.cpuCore') }} / {{ formatMemory(instance.memory) }} / {{ formatDisk(instance.disk) }}
                </span>
              </div>
              <div class="flex items-center justify-between">
                <span class="text-themed-muted text-xs">{{ $t('instance.mobileCard.traffic') }}</span>
                <span
                  class="text-xs"
                  :class="themeStore.isDark ? 'text-gray-300' : 'text-gray-700'"
                >
                  <template v-if="(instance as any).monthlyTrafficLimit">
                    {{ formatBytes(Number((instance as any).monthlyTrafficUsed || 0)) }} / {{ formatBytes(Number((instance as any).monthlyTrafficLimit)) }}
                  </template>
                  <template v-else>
                    {{ formatBytes(Number((instance as any).monthlyTrafficUsed || 0)) }} / {{ $t('instance.mobileCard.unlimited') }}
                  </template>
                </span>
              </div>
              <div class="flex items-center justify-between">
                <span class="text-themed-muted text-xs">{{ $t('instance.expireAt') }}</span>
                <span class="text-xs text-right" :title="getInstanceExpiryInfo(instance).title || ''">
                  <template v-if="getInstanceExpiryInfo(instance).dateText">
                    <span class="text-themed-muted">{{ getInstanceExpiryInfo(instance).dateText }}</span>
                    <span class="mx-1 text-themed-muted">|</span>
                  </template>
                  <span class="font-medium" :class="getInstanceExpiryInfo(instance).className">
                    {{ getInstanceExpiryInfo(instance).remainingText }}
                  </span>
                </span>
              </div>
              <div class="flex items-center justify-between">
                <span class="text-themed-muted text-xs">{{ $t('instance.mobileCard.quota') }}</span>
                <span
                  class="text-xs"
                  :class="themeStore.isDark ? 'text-gray-300' : 'text-gray-700'"
                >
                  {{ (instance as any).portLimit ?? '-' }} {{ $t('instance.mobileCard.ports') }} / {{ (instance as any).snapshotLimit ?? '-' }} {{ $t('instance.mobileCard.snapshots') }} / {{ (instance as any).siteLimit ?? '-' }} {{ $t('instance.mobileCard.sites') }}
                </span>
              </div>
              <div v-if="isAdmin" class="flex items-center justify-between">
                <span class="text-themed-muted text-xs">{{ $t('instance.mobileCard.user') }}</span>
                <span
                  class="text-xs"
                  :class="themeStore.isDark ? 'text-gray-300' : 'text-gray-700'"
                >
                  {{ (instance as any).username || '-' }}
                </span>
              </div>
            </div>
          </div>

          <div
            class="flex items-center justify-center gap-2 px-4 py-3 border-t"
            :class="themeStore.isDark ? 'border-gray-800 bg-gray-900/30' : 'border-gray-100 bg-gray-50'"
          >
            <InstanceOrderMenu
              v-if="canReorderInstances"
              :actions="INSTANCE_ORDER_ACTIONS"
              :labels="orderLabels"
              :label="$t('instance.order.label')"
              :disabled-actions="getOrderDisabledActions(instance.id)"
              :loading="orderLoading"
              :dark="themeStore.isDark"
              align="left"
              @reorder="emit('reorder', instance, $event)"
            />
            <button
              v-if="instance.status?.toLowerCase() === 'stopped'"
              :disabled="!!actionLoading[instance.id]"
              class="btn-ghost btn-sm flex-1"
              @click.stop="emit('row-action', instance, 'start')"
            >
              <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <span class="text-xs">{{ actionLoading[instance.id] === 'start' ? '...' : $t('instance.actions.start') }}</span>
            </button>
            <button
              v-if="canRetryProvision(instance)"
              :disabled="!!actionLoading[instance.id]"
              class="btn-ghost btn-sm flex-1 text-blue-500"
              @click.stop="emit('row-action', instance, 'retry')"
            >
              <svg :class="['w-3.5 h-3.5', actionLoading[instance.id] === 'retry' ? 'animate-spin' : '']" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8 8 0 104.582 9M20 4v5h-5" />
              </svg>
              <span class="text-xs">{{ $t('instance.actions.retry') }}</span>
            </button>
            <button
              v-if="instance.status?.toLowerCase() === 'running'"
              :disabled="!!actionLoading[instance.id]"
              class="btn-ghost btn-sm flex-1"
              @click.stop="emit('row-action', instance, 'stop')"
            >
              <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 10a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1h-4a1 1 0 01-1-1v-4z" />
              </svg>
              <span class="text-xs">{{ actionLoading[instance.id] === 'stop' ? '...' : $t('instance.actions.stop') }}</span>
            </button>
            <button
              v-if="instance.status?.toLowerCase() === 'running'"
              :disabled="!!actionLoading[instance.id]"
              class="btn-ghost btn-sm flex-1"
              @click.stop="emit('row-action', instance, 'restart')"
            >
              <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
              <span class="text-xs">{{ actionLoading[instance.id] === 'restart' ? '...' : $t('instance.actions.restart') }}</span>
            </button>
            <button
              v-if="canDeleteInstance(instance)"
              :disabled="!!actionLoading[instance.id]"
              class="btn-ghost btn-sm flex-1 text-red-500 hover:text-red-400"
              @click.stop="emit('row-action', instance, 'delete')"
            >
              <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
              </svg>
              <span class="text-xs">{{ actionLoading[instance.id] === 'delete' ? '...' : $t('instance.actions.delete') }}</span>
            </button>
          </div>
        </div>
      </TransitionGroup>

    <TransitionGroup
      name="instance-card-order"
      tag="div"
      class="hidden sm:grid grid-cols-1 gap-3 xl:grid-cols-2 2xl:grid-cols-3"
    >
      <article
        v-for="instance in instances"
        :key="instance.id"
        class="group relative overflow-hidden rounded-2xl border transition-colors duration-200"
        :class="[
          instance.status?.toLowerCase() === 'creating' ? 'creating-card' : '',
          recentlyOrderedInstanceId === instance.id ? (themeStore.isDark ? 'is-order-feedback-dark' : 'is-order-feedback-light') : '',
          selectedIds.has(instance.id) ? (themeStore.isDark ? 'ring-1 ring-blue-500/40' : 'ring-1 ring-blue-500/30') : '',
          themeStore.isDark
            ? 'border-gray-800 bg-gray-950 hover:border-gray-700'
            : 'border-gray-200 bg-white hover:border-gray-300 hover:shadow-sm'
        ]"
      >
        <div class="flex h-full flex-col p-3.5">
          <div class="flex items-start gap-2.5">
            <button
              type="button"
              class="group/avatar relative flex h-11 w-11 shrink-0 items-center justify-center overflow-hidden rounded-xl border transition-all duration-150"
              :class="themeStore.isDark
                ? 'border-gray-800 bg-gray-900 hover:border-gray-700'
                : 'border-gray-200 bg-gray-50 hover:border-gray-300'"
              :aria-pressed="selectedIds.has(instance.id)"
              @click.stop="emit('toggle-select', instance.id)"
            >
              <span
                class="absolute inset-0 flex items-center justify-center transition-opacity duration-150"
                :class="selectedIds.has(instance.id) ? 'opacity-0' : 'opacity-100 group-hover/avatar:opacity-0'"
              >
                <InstanceDisplayIcon
                  v-if="instance.iconBadgeId || getPaidIconType(instance)"
                  :badge-id="instance.iconBadgeId"
                  :fallback-icon="getPaidIconType(instance)"
                  :alt="instance.name"
                  :size="40"
                />
                <DistroIcon
                  v-else
                  :distro="getDistroFromName(instance.image)"
                  :size="34"
                />
              </span>
              <span
                class="pointer-events-none absolute inset-0 flex items-center justify-center transition-opacity duration-150"
                :class="selectedIds.has(instance.id) ? 'opacity-100' : 'opacity-0 group-hover/avatar:opacity-100'"
              >
                <span
                  class="flex h-5 w-5 items-center justify-center rounded-md border shadow-sm"
                  :class="selectedIds.has(instance.id)
                    ? 'border-blue-500 bg-blue-500 text-white'
                    : (themeStore.isDark ? 'border-gray-600 bg-gray-950 text-transparent' : 'border-gray-300 bg-white text-transparent')"
                >
                  <svg class="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M5 13l4 4L19 7" />
                  </svg>
                </span>
              </span>
            </button>

            <div class="min-w-0 flex-1 cursor-pointer" @click="emit('open-detail', instance.id)">
              <div class="flex items-start justify-between gap-3">
                <div class="min-w-0">
                  <div
                    class="truncate text-[14px] font-semibold leading-5"
                    :class="themeStore.isDark ? 'text-gray-100' : 'text-gray-900'"
                  >
                    {{ instance.name }}
                  </div>
                  <div
                    class="mt-0.5 truncate text-xs"
                    :class="themeStore.isDark ? 'text-gray-500' : 'text-gray-500'"
                  >
                    {{ formatImageName(instance.image, (instance as any).imageName) }}
                  </div>
                </div>
                <span :class="['badge badge-sm inline-flex items-center gap-1.5 shrink-0', getStatusInfo(instance.status, t).class]">
                  <span :class="['w-1 h-1 rounded-full', getStatusInfo(instance.status, t).dot]"></span>
                  <span class="text-[10px]">{{ getStatusInfo(instance.status, t).label }}</span>
                </span>
              </div>

              <div class="mt-1.5 flex flex-wrap items-center gap-1">
                <span
                  class="inline-flex max-w-[9.5rem] items-center gap-1 rounded-full px-2 py-0.5 text-[10px] sm:max-w-[11rem] sm:gap-1.5 sm:text-[11px]"
                  :class="themeStore.isDark ? 'bg-gray-900 text-gray-300 ring-1 ring-white/5' : 'bg-gray-50 text-gray-700 ring-1 ring-black/5'"
                >
                  <FlagIcon :code="(instance as any).host?.country_code || (instance as any).hostCountryCode || 'us'" size="xs" />
                  <span class="truncate">{{ getInstanceHostName(instance) }}</span>
                </span>
                <span
                  v-if="getInstancePackageName(instance)"
                  class="max-w-[9.5rem] truncate rounded-full px-2 py-0.5 text-[10px] sm:max-w-[11rem] sm:text-[11px]"
                  :class="themeStore.isDark ? 'bg-blue-500/10 text-blue-300' : 'bg-blue-50 text-blue-700'"
                  :title="getInstancePackageName(instance) || ''"
                >
                  {{ getInstancePackageName(instance) }}
                </span>
                <span
                  class="shrink-0 rounded-full px-2 py-0.5 text-[10px] sm:text-[11px] whitespace-nowrap"
                  :class="getInstanceTypeBadgeClass(instance)"
                >
                  {{ getInstanceTypeDisplayLabel(instance) }}
                </span>
                <span
                  class="max-w-[9rem] truncate rounded-full px-2 py-0.5 text-[10px] sm:max-w-[10rem] sm:text-[11px]"
                  :class="getInstanceNetworkModeClass(instance)"
                >
                  {{ $t('common.networkMode.' + getInstanceNetworkMode(instance)) }}
                </span>
                <span
                  v-if="isAdmin"
                  class="max-w-[8rem] truncate rounded-full px-2 py-0.5 text-[10px] sm:text-[11px]"
                  :class="themeStore.isDark ? 'bg-gray-900 text-gray-300 ring-1 ring-white/5' : 'bg-gray-50 text-gray-700 ring-1 ring-black/5'"
                >
                  {{ (instance as any).username || '-' }}
                </span>
              </div>
            </div>
          </div>

          <div class="mt-auto">
            <div
              class="mt-2 grid grid-cols-2 gap-x-3 gap-y-2 border-t pt-2"
              :class="themeStore.isDark ? 'border-gray-800' : 'border-gray-200'"
              @click="emit('open-detail', instance.id)"
            >
              <div class="min-w-0">
                <div class="text-[11px] text-themed-muted">{{ $t('instance.mobileCard.config') }}</div>
                <div class="mt-1 truncate text-[13px] font-medium sm:text-sm" :class="themeStore.isDark ? 'text-gray-100' : 'text-gray-900'">
                  {{ instance.cpu }}% / {{ formatMemory(instance.memory) }} / {{ formatDisk(instance.disk) }}
                </div>
              </div>
              <div class="min-w-0">
                <div class="text-[11px] text-themed-muted">{{ $t('instance.mobileCard.quota') }}</div>
                <div class="mt-1 truncate text-[13px] font-medium sm:text-sm" :class="themeStore.isDark ? 'text-gray-100' : 'text-gray-900'">
                  {{ (instance as any).portLimit ?? '-' }} / {{ (instance as any).snapshotLimit ?? '-' }} / {{ (instance as any).siteLimit ?? '-' }}
                </div>
              </div>
              <div class="min-w-0">
                <div class="text-[11px] text-themed-muted">{{ $t('instance.mobileCard.traffic') }}</div>
                <div class="mt-1 truncate text-[13px] font-medium sm:text-sm" :class="themeStore.isDark ? 'text-gray-100' : 'text-gray-900'">
                  <template v-if="(instance as any).monthlyTrafficLimit">
                    {{ formatBytes(Number((instance as any).monthlyTrafficUsed || 0)) }} / {{ formatBytes(Number((instance as any).monthlyTrafficLimit)) }}
                  </template>
                  <template v-else>
                    {{ formatBytes(Number((instance as any).monthlyTrafficUsed || 0)) }} / {{ $t('instance.mobileCard.unlimited') }}
                  </template>
                </div>
              </div>
              <div class="min-w-0">
                <div class="text-[11px] text-themed-muted">{{ $t('instance.expireAt') }}</div>
                <div class="mt-1 truncate text-[13px] font-medium sm:text-sm" :class="themeStore.isDark ? 'text-gray-100' : 'text-gray-900'">
                  <span>{{ getInstanceExpiryInfo(instance).dateText || '-' }}</span>
                  <span class="mx-1 text-themed-muted">·</span>
                  <span :class="getInstanceExpiryInfo(instance).className" :title="getInstanceExpiryInfo(instance).title || ''">
                    {{ getInstanceExpiryInfo(instance).remainingText }}
                  </span>
                </div>
              </div>
            </div>

            <div
              class="mt-2 grid grid-cols-1 gap-2 border-t pt-2 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-end"
              :class="themeStore.isDark ? 'border-gray-800' : 'border-gray-200'"
            >
              <div class="min-h-[36px] min-w-0 cursor-pointer" @click="emit('open-detail', instance.id)">
                <div class="mb-1 text-[11px] text-themed-muted">{{ $t('instance.mobileCard.ipAddress') }}</div>
                <div class="space-y-1">
                  <template v-if="getIps(instance).length > 0">
                    <div
                      v-for="(ipObj, idx) in getIps(instance)"
                      :key="idx"
                      class="truncate font-mono text-xs"
                      :class="[themeStore.isDark ? 'text-gray-300' : 'text-gray-700', ipObj.type === 'ipv6' ? 'opacity-80' : '']"
                      :title="ipObj.ip"
                    >
                      {{ ipObj.ip }}
                    </div>
                  </template>
                  <span v-else class="text-themed-muted text-xs">-</span>
                </div>
              </div>

              <div class="flex min-w-[9.5rem] flex-wrap items-center justify-end gap-1.5 sm:max-w-[18rem] sm:justify-self-end">
                <InstanceOrderMenu
                  v-if="canReorderInstances"
                  :actions="INSTANCE_ORDER_ACTIONS"
                  :labels="orderLabels"
                  :label="$t('instance.order.label')"
                  :disabled-actions="getOrderDisabledActions(instance.id)"
                  :loading="orderLoading"
                  :dark="themeStore.isDark"
                  align="right"
                  @reorder="emit('reorder', instance, $event)"
                />
                <button
                  v-if="instance.status?.toLowerCase() === 'stopped'"
                  :disabled="!!actionLoading[instance.id]"
                  class="inline-flex h-8 w-8 items-center justify-center rounded-lg border transition-colors"
                  :class="getCardActionButtonClass()"
                  :title="$t('instance.actions.start')"
                  :aria-label="$t('instance.actions.start')"
                  @click.stop="emit('row-action', instance, 'start')"
                >
                  <svg v-if="actionLoading[instance.id] === 'start'" class="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
                    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
                  </svg>
                  <svg v-else class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                  </svg>
                </button>
                <button
                  v-if="instance.status?.toLowerCase() === 'running'"
                  :disabled="!!actionLoading[instance.id]"
                  class="inline-flex h-8 w-8 items-center justify-center rounded-lg border transition-colors"
                  :class="getCardActionButtonClass()"
                  :title="$t('instance.actions.stop')"
                  :aria-label="$t('instance.actions.stop')"
                  @click.stop="emit('row-action', instance, 'stop')"
                >
                  <svg v-if="actionLoading[instance.id] === 'stop'" class="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
                    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
                  </svg>
                  <svg v-else class="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                    <rect x="5" y="5" width="10" height="10" rx="1.8" />
                  </svg>
                </button>

                <button
                  v-if="canRetryProvision(instance)"
                  :disabled="!!actionLoading[instance.id]"
                  class="inline-flex h-8 w-8 items-center justify-center rounded-lg border transition-colors"
                  :class="getCardActionButtonClass()"
                  :title="$t('instance.actions.retry')"
                  :aria-label="$t('instance.actions.retry')"
                  @click.stop="emit('row-action', instance, 'retry')"
                >
                  <svg :class="['w-3.5 h-3.5', actionLoading[instance.id] === 'retry' ? 'animate-spin' : '']" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8 8 0 104.582 9M20 4v5h-5" />
                  </svg>
                </button>

                <button
                  v-if="instance.status?.toLowerCase() === 'running'"
                  :disabled="!!actionLoading[instance.id]"
                  class="inline-flex h-8 w-8 items-center justify-center rounded-lg border transition-colors"
                  :class="getCardActionButtonClass()"
                  :title="$t('instance.actions.restart')"
                  :aria-label="$t('instance.actions.restart')"
                  @click.stop="emit('row-action', instance, 'restart')"
                >
                  <svg v-if="actionLoading[instance.id] === 'restart'" class="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
                    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
                  </svg>
                  <svg v-else class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                  </svg>
                </button>

                <button
                  v-if="canDeleteInstance(instance)"
                  :disabled="!!actionLoading[instance.id]"
                  class="inline-flex h-8 w-8 items-center justify-center rounded-lg border transition-colors"
                  :class="getCardActionButtonClass('danger')"
                  :title="$t('instance.actions.delete')"
                  :aria-label="$t('instance.actions.delete')"
                  @click.stop="emit('row-action', instance, 'delete')"
                >
                  <svg v-if="actionLoading[instance.id] === 'delete'" class="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
                    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
                  </svg>
                  <svg v-else class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                  </svg>
                </button>

                <button
                  type="button"
                  class="inline-flex h-8 w-8 items-center justify-center rounded-lg border transition-colors"
                  :class="getCardActionButtonClass()"
                  :title="$t('instance.details')"
                  :aria-label="$t('instance.details')"
                  @click.stop="emit('open-detail', instance.id)"
                >
                  <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7" />
                  </svg>
                </button>
              </div>
            </div>
          </div>
        </div>
      </article>
    </TransitionGroup>
  </div>
</template>

<style scoped>
.instance-stack-order-move,
.instance-card-order-move {
  transition:
    transform 520ms cubic-bezier(0.2, 0.8, 0.2, 1),
    box-shadow 520ms cubic-bezier(0.2, 0.8, 0.2, 1),
    background-color 520ms ease,
    border-color 520ms ease;
}

.is-order-feedback-light {
  background-color: rgb(249 250 251);
  box-shadow: 0 10px 28px rgb(15 23 42 / 0.08);
}

.is-order-feedback-dark {
  background-color: rgb(17 24 39 / 0.82);
  box-shadow: 0 10px 28px rgb(0 0 0 / 0.22);
}

@media (prefers-reduced-motion: reduce) {
  .instance-stack-order-move,
  .instance-card-order-move {
    transition-duration: 1ms;
  }
}
</style>
