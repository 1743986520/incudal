<script setup lang="ts">
// 实例列表桌面表格(≥sm 视口)。
// 纯呈现组件:排序、启停等操作通过事件上抛,数据加载与 API 由父页面持有。
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
  'toggle-select-all': []
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
  getInstanceNetworkModeClass
} = useInstanceDisplay()

function canRetryProvision(instance: Instance): boolean {
  return instance.status?.toLowerCase() === 'error'
    && (props.isAdmin || instance.userId === undefined || instance.userId === authStore.user?.id)
}

function truncateIpv6(ip: string): string {
  return ip.length > 18 ? ip.substring(0, 18) + '...' : ip
}
</script>

<template>
  <div class="hidden sm:block card overflow-x-auto">
    <table class="w-full min-w-[1100px]">
      <thead
        class="border-b"
        :class="themeStore.isDark ? 'bg-gray-900/50 border-gray-800' : 'bg-gray-50 border-gray-200'"
      >
        <tr>
          <th class="px-4 py-3 w-12">
            <div class="flex items-center justify-center">
              <button
                type="button"
                class="relative flex h-4 w-4 items-center justify-center rounded border transition-colors"
                :class="themeStore.isDark ? 'border-gray-600 bg-gray-950 text-blue-400' : 'border-gray-300 bg-white text-blue-600'"
                @click="emit('toggle-select-all')"
              >
                <span v-if="selectedIds.size === instances.length && instances.length > 0" class="h-2 w-2 rounded-sm bg-current"></span>
                <span v-else-if="selectedIds.size > 0 && selectedIds.size < instances.length" class="h-0.5 w-2 rounded-full bg-current"></span>
              </button>
            </div>
          </th>
          <th class="text-left text-xs font-medium text-themed-muted uppercase tracking-wider px-4 py-3">{{ $t('instance.name') }}</th>
          <th class="text-left text-xs font-medium text-themed-muted uppercase tracking-wider px-3 py-3">{{ $t('instance.statusLabel') }}</th>
          <th class="text-left text-xs font-medium text-themed-muted uppercase tracking-wider px-3 py-3">{{ $t('instance.ip') }}</th>
          <th class="text-left text-xs font-medium text-themed-muted uppercase tracking-wider px-3 py-3">{{ $t('instance.config') }}</th>
          <th class="text-left text-xs font-medium text-themed-muted uppercase tracking-wider px-3 py-3">{{ $t('instance.quotaLabel') }}</th>
          <th v-if="isAdmin" class="text-left text-xs font-medium text-themed-muted uppercase tracking-wider px-3 py-3">{{ $t('instance.user') }}</th>
          <th class="text-right text-xs font-medium text-themed-muted uppercase tracking-wider px-4 py-3">{{ $t('common.actions') }}</th>
        </tr>
      </thead>
      <TransitionGroup
        tag="tbody"
        name="instance-table-order"
        :class="themeStore.isDark ? 'divide-y divide-gray-800' : 'divide-y divide-gray-100'"
      >
        <tr
          v-for="instance in instances"
          :key="instance.id"
          class="cursor-pointer"
          :class="[
            themeStore.isDark ? 'hover:bg-gray-900/30' : 'hover:bg-gray-50',
            selectedIds.has(instance.id) ? (themeStore.isDark ? 'bg-blue-500/10' : 'bg-blue-50/80') : '',
            recentlyOrderedInstanceId === instance.id ? (themeStore.isDark ? 'is-order-feedback-dark' : 'is-order-feedback-light') : '',
            instance.status?.toLowerCase() === 'creating' ? 'creating-row' : ''
          ]"
          @click="emit('open-detail', instance.id)"
        >
          <td class="px-4 py-3" @click.stop>
            <div class="flex items-center justify-center">
              <input
                type="checkbox"
                class="w-4 h-4 rounded border-gray-300 text-primary focus:ring-primary cursor-pointer"
                :checked="selectedIds.has(instance.id)"
                @change="emit('toggle-select', instance.id)"
              />
            </div>
          </td>
          <td class="px-4 py-3">
            <div class="flex items-center gap-2.5">
              <div
                class="w-9 h-9 rounded flex items-center justify-center transition-colors flex-shrink-0 overflow-hidden"
                :class="themeStore.isDark ? 'bg-gray-800' : 'bg-gray-100'"
              >
                <InstanceDisplayIcon
                  v-if="instance.iconBadgeId || getPaidIconType(instance)"
                  :badge-id="instance.iconBadgeId"
                  :fallback-icon="getPaidIconType(instance)"
                  :alt="instance.name"
                  :size="36"
                />
                <DistroIcon
                  v-else
                  :distro="getDistroFromName(instance.image)"
                  :size="32"
                />
              </div>
              <div class="min-w-0">
                <div
                  class="font-medium text-sm truncate"
                  :class="themeStore.isDark ? 'text-gray-100' : 'text-gray-900'"
                >
                  <span>{{ instance.name }}</span>
                  <span v-if="isHourlyInstance(instance)" class="ml-1.5 rounded-full bg-blue-500/10 px-1.5 py-0.5 text-[10px] font-medium text-blue-500">{{ $t('hourlyBilling.badge') }}</span>
                </div>
                <div
                  class="text-xs truncate"
                  :class="themeStore.isDark ? 'text-gray-600' : 'text-gray-400'"
                >
                  {{ formatImageName(instance.image, (instance as any).imageName) }}
                </div>
                <div class="mt-1 flex flex-wrap items-center gap-1">
                  <span
                    class="rounded-full px-2 py-0.5 text-[10px] whitespace-nowrap"
                    :class="getInstanceTypeBadgeClass(instance)"
                  >
                    {{ getInstanceTypeDisplayLabel(instance) }}
                  </span>
                  <span
                    class="max-w-[8rem] truncate rounded-full px-2 py-0.5 text-[10px]"
                    :class="getInstanceNetworkModeClass(instance)"
                  >
                    {{ $t('common.networkMode.' + getInstanceNetworkMode(instance)) }}
                  </span>
                  <span
                    v-if="getInstancePackageName(instance)"
                    class="max-w-[9rem] truncate rounded-full px-2 py-0.5 text-[10px]"
                    :class="themeStore.isDark ? 'bg-blue-500/10 text-blue-300' : 'bg-blue-50 text-blue-700'"
                    :title="getInstancePackageName(instance) || ''"
                  >
                    {{ getInstancePackageName(instance) }}
                  </span>
                </div>
              </div>
            </div>
          </td>
          <td class="px-3 py-3">
            <span :class="['badge inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs', getStatusInfo(instance.status, t).class]">
              <span :class="['w-1.5 h-1.5 rounded-full', getStatusInfo(instance.status, t).dot]"></span>
              {{ getStatusInfo(instance.status, t).label }}
            </span>
          </td>
          <td class="pl-4 pr-3 py-3">
            <div class="flex items-start gap-2">
              <FlagIcon :code="(instance as any).host?.country_code || (instance as any).hostCountryCode || 'us'" size="xs" class="mt-0.5 flex-shrink-0" />
              <div class="space-y-0.5 min-w-0">
                <div
                  class="text-xs font-medium uppercase truncate"
                  :class="themeStore.isDark ? 'text-gray-300' : 'text-gray-500'"
                  :title="getInstanceHostName(instance)"
                >
                  {{ getInstanceHostName(instance) }}
                </div>
                <template v-if="getIps(instance).length > 0">
                  <div
                    v-for="(ipObj, idx) in getIps(instance)"
                    :key="idx"
                    class="text-xs font-mono truncate"
                    :class="themeStore.isDark ? 'text-gray-300' : 'text-gray-600'"
                    :title="ipObj.ip"
                  >
                    {{ ipObj.type === 'ipv6' ? truncateIpv6(ipObj.ip) : ipObj.ip }}
                  </div>
                </template>
                <span v-else class="text-themed-muted text-xs">-</span>
              </div>
            </div>
          </td>
          <td class="px-3 py-3">
            <div class="space-y-0.5">
              <div class="text-sm text-themed-muted">
                {{ instance.cpu }}% / {{ formatMemory(instance.memory) }} / {{ formatDisk(instance.disk) }}
              </div>
              <div class="text-xs text-gray-400 dark:text-gray-500">
                {{ formatBytes(Number((instance as any).monthlyTrafficUsed || 0)) }}
                <span> / </span>
                <template v-if="(instance as any).monthlyTrafficLimit">
                  {{ formatBytes(Number((instance as any).monthlyTrafficLimit)) }}
                </template>
                <template v-else>
                  {{ $t('instance.mobileCard.unlimited') }}
                </template>
              </div>
            </div>
          </td>
          <td class="px-3 py-3">
            <div class="space-y-0.5">
              <div class="text-sm text-themed-muted whitespace-nowrap">
                {{ (instance as any).portLimit ?? '-' }} {{ $t('instance.mobileCard.ports') }}
                <span class="mx-0.5">/</span>
                {{ (instance as any).snapshotLimit ?? '-' }} {{ $t('instance.mobileCard.snapshots') }}
                <span class="mx-0.5">/</span>
                {{ (instance as any).siteLimit ?? '-' }} {{ $t('instance.mobileCard.sites') }}
              </div>
              <div class="text-xs">
                <span class="text-themed-muted">{{ $t('instance.expireAt') }}:</span>
                <span class="ml-1 text-themed-muted" :title="getInstanceExpiryInfo(instance).title || ''">
                  <template v-if="getInstanceExpiryInfo(instance).dateText">
                    {{ getInstanceExpiryInfo(instance).dateText }}
                    <span class="mx-1">|</span>
                  </template>
                  <span class="font-medium" :class="getInstanceExpiryInfo(instance).className">
                    {{ getInstanceExpiryInfo(instance).remainingText }}
                  </span>
                </span>
              </div>
            </div>
          </td>
          <td v-if="isAdmin" class="px-3 py-3">
            <span
              class="text-xs truncate"
              :class="themeStore.isDark ? 'text-gray-400' : 'text-gray-500'"
            >{{ (instance as any).username || '-' }}</span>
          </td>
          <td class="px-4 py-3 text-right">
            <div class="flex items-center justify-end gap-1">
              <InstanceOrderMenu
                v-if="canReorderInstances"
                class="mr-1"
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
                class="p-1.5 rounded hover:bg-green-50 dark:hover:bg-green-900/20 text-green-500 transition-colors disabled:opacity-50"
                :title="$t('instance.actions.start')"
                @click.stop="emit('row-action', instance, 'start')"
              >
                <svg v-if="actionLoading[instance.id] === 'start'" class="w-5 h-5 animate-spin" fill="none" viewBox="0 0 24 24">
                  <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                  <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                <svg v-else class="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M8 5v14l11-7z" />
                </svg>
              </button>
              <button
                v-if="instance.status?.toLowerCase() === 'running'"
                :disabled="!!actionLoading[instance.id]"
                class="p-1.5 rounded hover:bg-amber-50 dark:hover:bg-amber-900/20 text-amber-500 transition-colors disabled:opacity-50"
                :title="$t('instance.actions.stop')"
                @click.stop="emit('row-action', instance, 'stop')"
              >
                <svg v-if="actionLoading[instance.id] === 'stop'" class="w-5 h-5 animate-spin" fill="none" viewBox="0 0 24 24">
                  <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                  <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
                </svg>
                <svg v-else class="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M6 6h12v12H6z" />
                </svg>
              </button>
              <button
                v-if="instance.status?.toLowerCase() === 'running'"
                :disabled="!!actionLoading[instance.id]"
                class="p-1.5 rounded hover:bg-blue-50 dark:hover:bg-blue-900/20 text-blue-500 transition-colors disabled:opacity-50"
                :title="$t('instance.actions.restart')"
                @click.stop="emit('row-action', instance, 'restart')"
              >
                <svg v-if="actionLoading[instance.id] === 'restart'" class="w-5 h-5 animate-spin" fill="none" viewBox="0 0 24 24">
                  <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                  <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
                </svg>
                <svg v-else class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                </svg>
              </button>
              <button
                v-if="canRetryProvision(instance)"
                :disabled="!!actionLoading[instance.id]"
                class="p-1.5 rounded hover:bg-blue-50 dark:hover:bg-blue-900/20 text-blue-500 transition-colors disabled:opacity-50"
                :title="$t('instance.actions.retry')"
                @click.stop="emit('row-action', instance, 'retry')"
              >
                <svg :class="['w-5 h-5', actionLoading[instance.id] === 'retry' ? 'animate-spin' : '']" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8 8 0 104.582 9M20 4v5h-5" />
                </svg>
              </button>
              <span
                class="p-1.5 rounded hover:bg-gray-100 dark:hover:bg-gray-800 text-themed-muted transition-colors"
                :title="$t('instance.details')"
              >
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7" />
                </svg>
              </span>
            </div>
          </td>
        </tr>
      </TransitionGroup>
    </table>
  </div>
</template>

<style scoped>
.instance-table-order-move {
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
  .instance-table-order-move {
    transition-duration: 1ms;
  }
}
</style>
