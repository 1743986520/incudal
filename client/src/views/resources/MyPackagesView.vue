<script setup lang="ts">
import { ref, computed, onMounted, onActivated, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import api from '@/api'
import SkeletonLoader from '@/components/SkeletonLoader.vue'
import UserAvatar from '@/components/UserAvatar.vue'
import PackageQuotaReleaseModal from '@/components/PackageQuotaReleaseModal.vue'
import { useToast } from '@/stores/toast'
import { useThemeStore } from '@/stores/theme'
import { useAuthStore } from '@/stores/auth'
import type { Package, Host } from '@/types/api'

defineOptions({ name: 'MyPackagesView' })

const { t } = useI18n()
const router = useRouter()
const toast = useToast()
const themeStore = useThemeStore()
const authStore = useAuthStore()

const isAdmin = computed(() => authStore.user?.role === 'admin')
const scope = ref<'mine' | 'hosted'>('mine')
const filterUserId = ref('')
const packages = ref<Package[]>([])
const hosts = ref<Host[]>([])
const loading = ref(true)
const searchQuery = ref('')
const packagesPage = ref(1)
const packagesPageSize = 100
const showQuotaReleaseModal = ref(false)
const quotaReleasePackage = ref<Package | null>(null)
const showPackageActions = computed(() => scope.value === 'mine' || isAdmin.value)

let hasInitialLoad = false
let filterTimer: ReturnType<typeof setTimeout> | null = null

const filteredPackages = computed(() => {
  const query = searchQuery.value.toLowerCase().trim()
  if (!query) return packages.value

  return packages.value.filter(pkg => {
    if (pkg.name.toLowerCase().includes(query)) return true
    if (pkg.description?.toLowerCase().includes(query)) return true
    return getHostNames(pkg).toLowerCase().includes(query)
  })
})

const packagesTotalPages = computed(() => Math.max(1, Math.ceil(filteredPackages.value.length / packagesPageSize)))
const paginatedPackages = computed(() => {
  const start = (packagesPage.value - 1) * packagesPageSize
  return filteredPackages.value.slice(start, start + packagesPageSize)
})

const packagesPageNumbers = computed(() => {
  const current = packagesPage.value
  const total = packagesTotalPages.value
  const pages: (number | string)[] = []

  if (total <= 7) {
    for (let i = 1; i <= total; i++) pages.push(i)
  } else {
    pages.push(1)
    if (current <= 3) {
      pages.push(2, 3, 4, 5, '...', total)
    } else if (current >= total - 2) {
      pages.push('...', total - 4, total - 3, total - 2, total - 1, total)
    } else {
      pages.push('...', current - 1, current, current + 1, '...', total)
    }
  }
  return pages
})

onMounted(async () => {
  await Promise.all([loadPackages(), loadHosts()])
  hasInitialLoad = true
})

onActivated(async () => {
  if (hasInitialLoad) {
    await Promise.all([loadPackages(), loadHosts()])
  }
})

watch(packagesTotalPages, (newTotal) => {
  if (packagesPage.value > newTotal) {
    packagesPage.value = Math.max(1, newTotal)
  }
})

watch(filterUserId, () => {
  if (filterTimer) clearTimeout(filterTimer)
  filterTimer = setTimeout(() => {
    packagesPage.value = 1
    void loadPackages()
  }, 300)
})

async function loadPackages(): Promise<void> {
  loading.value = true
  try {
    if (isAdmin.value && scope.value === 'hosted') {
      const response = await api.packages.listHosted({
        ...(filterUserId.value ? { userId: parseInt(filterUserId.value, 10) } : {})
      })
      packages.value = response.packages || []
    } else if (isAdmin.value && scope.value === 'mine') {
      const response = await api.packages.list({ all: true, scope: 'mine' })
      packages.value = response.packages || []
    } else {
      const response = await api.packages.list({ all: true })
      packages.value = (response.packages || []).filter(pkg => pkg.isOwn === true)
    }
  } finally {
    loading.value = false
  }
}

async function loadHosts(): Promise<void> {
  try {
    const response = await api.hosts.list(isAdmin.value ? { pageSize: '1000' } : { mine: 'true', pageSize: '1000' })
    hosts.value = (response as { hosts?: Host[] }).hosts || []
  } catch (err) {
    console.error('加载宿主机失败:', err)
  }
}

function switchScope(newScope: 'mine' | 'hosted'): void {
  if (scope.value === newScope) return
  scope.value = newScope
  filterUserId.value = ''
  packagesPage.value = 1
  void loadPackages()
}

function onSearchChange(): void {
  packagesPage.value = 1
}

function clearSearch(): void {
  searchQuery.value = ''
  packagesPage.value = 1
}

function goToPackagesPage(p: number | string): void {
  if (typeof p !== 'number') return
  if (p < 1 || p > packagesTotalPages.value) return
  packagesPage.value = p
}

function openCreate(): void {
  router.push({ name: 'my-package-create' })
}

function openDetail(pkg: Package): void {
  router.push({ name: 'my-package-detail', params: { id: pkg.id } })
}

function openQuotaReleaseModal(pkg: Package): void {
  quotaReleasePackage.value = pkg
  showQuotaReleaseModal.value = true
}

function handleQuotaReleaseSuccess(): void {
  void Promise.all([loadPackages(), loadHosts()])
}

function getHostNames(pkg: Package & { host_ids?: number[] }): string {
  const hostIds = pkg.host_ids || []
  if (hostIds.length === 0) return t('admin.packages.noHostsBound')

  return hostIds
    .map(id => hosts.value.find(host => host.id === id)?.name || `Host #${id}`)
    .join(', ')
}

function getPackageNetworkModeLabel(pkg: Package): string {
  const mode = (pkg.network_mode || pkg.networkMode || 'nat').toLowerCase()
  const key = `common.networkMode.${mode}`
  const translated = t(key)
  return translated === key ? mode : translated
}

function getPackageInstanceTypeLabel(pkg: Package): string {
  return pkg.instance_type === 'vm' ? t('common.instanceType.vm') : t('common.instanceType.container')
}

function formatTrafficMultiplier(value: unknown): string {
  const multiplier = Number(value ?? 1)
  if (!Number.isFinite(multiplier)) return '1x'
  return `${Math.round(multiplier * 1000) / 1000}x`
}

function getPackageTrafficMultiplierItems(pkg: Package & { host_ids?: number[] }): Array<{ hostName: string; multiplier: string }> {
  const hostIds = pkg.host_ids || []
  const multipliers = pkg.host_traffic_multipliers || {}

  if (hostIds.length === 0) {
    return [{ hostName: t('admin.packages.noHostsBound'), multiplier: formatTrafficMultiplier(1) }]
  }

  return hostIds.map(id => ({
    hostName: hosts.value.find(host => host.id === id)?.name || `Host #${id}`,
    multiplier: formatTrafficMultiplier(multipliers[String(id)] ?? 1)
  }))
}

function getPackageTrafficMultiplierLabel(pkg: Package & { host_ids?: number[] }): string {
  return [...new Set(getPackageTrafficMultiplierItems(pkg).map(item => item.multiplier))].join(' / ')
}

function getPackageTrafficMultiplierTitle(pkg: Package & { host_ids?: number[] }): string {
  return getPackageTrafficMultiplierItems(pkg)
    .map(item => `${item.hostName}: ${item.multiplier}`)
    .join(', ')
}

function isPackagePublic(pkg: Package): boolean {
  const globalShared = (pkg as { global_shared?: unknown }).global_shared
  const active = (pkg as { active?: unknown }).active
  const isActive = active === true || active === 1
  return isActive && (globalShared === true || globalShared === 1 || pkg.isGlobalShared === true)
}

function copyShareLink(pkg: Package): void {
  const hostNames = getHostNames(pkg)
  const isHostedPackage = hostNames.split(', ').some(name => name.toUpperCase().startsWith('PEER'))
  const source = isHostedPackage ? 'market' : 'official'
  const link = `${window.location.origin}/instances/create?source=${source}&package=${pkg.id}`

  navigator.clipboard.writeText(link).then(() => {
    toast.success(t('resources.packages.shareLinkCopied'))
  }).catch(() => {
    toast.error(t('common.copyFailed'))
  })
}
</script>

<template>
  <div class="space-y-6 animate-fade-in">
    <div class="page-header">
      <div>
        <h1 class="page-title">{{ t('resources.packages.title') }}</h1>
        <p class="page-description">{{ t('resources.packages.description') }}</p>
      </div>
    </div>

    <div class="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 sm:gap-4">
      <div class="flex items-center gap-3 flex-wrap">
        <div class="relative flex-1 sm:flex-none sm:w-56">
          <svg class="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-themed-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <input
            v-model="searchQuery"
            type="text"
            class="input pl-10 pr-8 w-full"
            :placeholder="t('resources.packages.searchPlaceholder')"
            @input="onSearchChange"
          />
          <button
            v-if="searchQuery"
            type="button"
            class="absolute right-2 top-1/2 -translate-y-1/2 p-1 rounded transition-colors"
            :class="themeStore.isDark ? 'text-gray-500 hover:text-gray-300 hover:bg-gray-700' : 'text-gray-400 hover:text-gray-600 hover:bg-gray-100'"
            @click="clearSearch"
          >
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div v-if="isAdmin" class="inline-flex rounded-lg p-1" :class="themeStore.isDark ? 'bg-gray-800' : 'bg-gray-100'">
          <button
            type="button"
            class="px-3 py-1.5 text-sm font-medium rounded-md transition-colors"
            :class="scope === 'mine'
              ? (themeStore.isDark ? 'bg-gray-700 text-white' : 'bg-white text-gray-900 shadow-sm')
              : (themeStore.isDark ? 'text-gray-400 hover:text-gray-200' : 'text-gray-500 hover:text-gray-700')"
            @click="switchScope('mine')"
          >
            {{ t('resources.packages.mine') }}
          </button>
          <button
            type="button"
            class="px-3 py-1.5 text-sm font-medium rounded-md transition-colors"
            :class="scope === 'hosted'
              ? (themeStore.isDark ? 'bg-gray-700 text-white' : 'bg-white text-gray-900 shadow-sm')
              : (themeStore.isDark ? 'text-gray-400 hover:text-gray-200' : 'text-gray-500 hover:text-gray-700')"
            @click="switchScope('hosted')"
          >
            {{ t('resources.packages.hosted') }}
          </button>
        </div>

        <div v-if="isAdmin && scope === 'hosted'" class="relative sm:w-36">
          <input
            v-model="filterUserId"
            type="text"
            :placeholder="t('resources.packages.filterByUserId')"
            class="input pl-9 w-full"
          />
          <svg class="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 icon-themed" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
          </svg>
        </div>
      </div>

      <button v-if="scope === 'mine'" type="button" class="btn-primary" @click="openCreate">
        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
        </svg>
        {{ t('resources.packages.create') }}
      </button>
    </div>

    <SkeletonLoader v-if="loading" type="list" />

    <div v-else-if="filteredPackages.length === 0" class="card p-12 text-center">
      <svg
        class="w-12 h-12 mx-auto mb-4"
        :class="themeStore.isDark ? 'text-gray-700' : 'text-gray-300'"
        fill="none" stroke="currentColor" viewBox="0 0 24 24"
      >
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1" d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4" />
      </svg>
      <template v-if="searchQuery">
        <p class="text-themed-secondary">{{ t('resources.packages.noSearchResults') }}</p>
        <button type="button" class="text-xs text-primary hover:underline mt-2" @click="clearSearch">{{ t('resources.packages.clearSearch') }}</button>
      </template>
      <template v-else>
        <p class="text-themed-secondary">{{ t('resources.packages.noPackages') }}</p>
        <p class="text-xs text-themed-muted mt-2">{{ t('resources.packages.noPackagesHint') }}</p>
      </template>
    </div>

    <template v-else>
      <div class="card overflow-hidden">
        <div class="overflow-x-auto">
          <table class="w-full text-sm">
            <thead>
              <tr :class="themeStore.isDark ? 'bg-gray-800/50 border-b border-gray-700' : 'bg-gray-50 border-b border-gray-200'">
                <th class="text-left px-4 py-3 font-medium text-themed-muted whitespace-nowrap">{{ t('admin.packages.name') }}</th>
                <th v-if="isAdmin && scope === 'hosted'" class="text-left px-4 py-3 font-medium text-themed-muted whitespace-nowrap">{{ t('resources.packages.owner') }}</th>
                <th class="text-left px-4 py-3 font-medium text-themed-muted whitespace-nowrap">{{ t('admin.packages.status') }}</th>
                <th class="text-left px-4 py-3 font-medium text-themed-muted whitespace-nowrap">{{ t('resources.packages.networkModeColumn') }}</th>
                <th class="text-left px-4 py-3 font-medium text-themed-muted whitespace-nowrap">{{ t('resources.packages.instanceTypeColumn') }}</th>
                <th class="text-right px-4 py-3 font-medium text-themed-muted whitespace-nowrap">{{ t('resources.packages.trafficMultiplierColumn') }}</th>
                <th class="text-left px-4 py-3 font-medium text-themed-muted whitespace-nowrap">{{ t('resources.packages.hostColumn') }}</th>
                <th class="text-right px-4 py-3 font-medium text-themed-muted whitespace-nowrap">{{ t('resources.packages.instanceColumn') }}</th>
                <th v-if="showPackageActions" class="text-right px-4 py-3 font-medium text-themed-muted whitespace-nowrap">{{ t('common.actions') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="pkg in paginatedPackages"
                :key="pkg.id"
                class="border-b transition-colors cursor-pointer"
                :class="[
                  themeStore.isDark ? 'border-gray-800 hover:bg-gray-800/30' : 'border-gray-100 hover:bg-gray-50',
                  pkg.active !== 1 ? 'opacity-60' : ''
                ]"
                @click="openDetail(pkg)"
              >
                <td class="px-4 py-3 whitespace-nowrap">
                  <div class="flex items-center gap-2 min-w-0">
                    <span class="font-medium truncate" :class="themeStore.isDark ? 'text-gray-200' : 'text-gray-900'">{{ pkg.name }}</span>
                    <span
                      v-if="isPackagePublic(pkg)"
                      class="shrink-0 inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ring-1 bg-blue-50 text-blue-700 ring-blue-200 dark:bg-blue-500/15 dark:text-blue-300 dark:ring-blue-500/30"
                    >
                      {{ t('resources.packages.publicBadge') }}
                    </span>
                  </div>
                  <div v-if="pkg.description" class="text-xs text-themed-muted mt-0.5 max-w-48 truncate">{{ pkg.description }}</div>
                </td>

                <td v-if="isAdmin && scope === 'hosted'" class="px-4 py-3 whitespace-nowrap">
                  <div v-if="pkg.owner" class="flex items-center gap-2">
                    <UserAvatar :avatar-style="pkg.owner.avatarStyle" :badge-id="pkg.owner.avatarBadgeId || null" :size="28" :username="pkg.owner.username" />
                    <div>
                      <div class="text-sm font-medium text-themed">{{ pkg.owner.username }}</div>
                      <div class="text-xs text-themed-muted">UID: {{ pkg.owner.id }}</div>
                    </div>
                  </div>
                  <span v-else class="text-themed-muted">-</span>
                </td>

                <td class="px-4 py-3 whitespace-nowrap">
                  <span v-if="pkg.active === 1" class="badge badge-success text-xs">{{ t('admin.packages.active') }}</span>
                  <span v-else class="badge badge-default text-xs" :title="t('admin.packages.archivedHint')">{{ t('admin.packages.inactive') }}</span>
                </td>

                <td class="px-4 py-3 whitespace-nowrap" :class="themeStore.isDark ? 'text-gray-300' : 'text-gray-600'">
                  {{ getPackageNetworkModeLabel(pkg) }}
                </td>

                <td class="px-4 py-3 whitespace-nowrap" :class="themeStore.isDark ? 'text-gray-300' : 'text-gray-600'">
                  {{ getPackageInstanceTypeLabel(pkg) }}
                </td>

                <td
                  class="px-4 py-3 text-right font-mono whitespace-nowrap"
                  :class="themeStore.isDark ? 'text-gray-300' : 'text-gray-600'"
                  :title="getPackageTrafficMultiplierTitle(pkg)"
                >
                  {{ getPackageTrafficMultiplierLabel(pkg) }}
                </td>

                <td class="px-4 py-3 whitespace-nowrap">
                  <span class="text-xs text-themed-muted max-w-32 truncate block">{{ getHostNames(pkg) }}</span>
                </td>

                <td class="px-4 py-3 text-right font-mono whitespace-nowrap" :class="themeStore.isDark ? 'text-gray-300' : 'text-gray-600'">
                  {{ pkg.instance_count || 0 }}
                </td>

                <td v-if="showPackageActions" class="px-4 py-3">
                  <div class="flex items-center justify-end gap-1">
                    <button
                      type="button"
                      class="p-1.5 transition-colors rounded"
                      :class="themeStore.isDark ? 'text-gray-500 hover:text-blue-400 hover:bg-gray-800' : 'text-gray-400 hover:text-blue-600 hover:bg-gray-100'"
                      :title="t('resources.packages.copyShareLink')"
                      @click.stop="copyShareLink(pkg)"
                    >
                      <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
                      </svg>
                    </button>
                    <button
                      type="button"
                      class="p-1.5 transition-colors rounded"
                      :class="themeStore.isDark ? 'text-gray-500 hover:text-teal-400 hover:bg-gray-800' : 'text-gray-400 hover:text-teal-600 hover:bg-gray-100'"
                      :title="t('quotaRelease.title')"
                      @click.stop="openQuotaReleaseModal(pkg)"
                    >
                      <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
                      </svg>
                    </button>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <div v-if="packagesTotalPages > 1" class="flex flex-col sm:flex-row items-center justify-between gap-3 px-4 py-3 text-sm text-themed-muted border-t" :class="themeStore.isDark ? 'border-gray-800' : 'border-gray-100'">
          <span>{{ t('common.total') }} {{ filteredPackages.length }} {{ t('common.items') }}</span>
          <div class="flex items-center gap-1 flex-wrap justify-center">
            <button :disabled="packagesPage <= 1" type="button" class="btn-ghost btn-sm" :class="packagesPage <= 1 ? 'cursor-not-allowed' : ''" @click="goToPackagesPage(packagesPage - 1)">{{ t('instance.prevPage') }}</button>
            <template v-for="(p, idx) in packagesPageNumbers" :key="idx">
              <span v-if="p === '...'" class="px-2 py-1 text-themed-muted">...</span>
              <button
                v-else
                type="button"
                class="min-w-[32px] px-2 py-1 rounded transition-colors"
                :class="[
                  p === packagesPage
                    ? (themeStore.isDark ? 'bg-blue-600 text-white' : 'bg-blue-500 text-white')
                    : (themeStore.isDark ? 'hover:bg-gray-700' : 'hover:bg-gray-100')
                ]"
                @click="goToPackagesPage(p)"
              >
                {{ p }}
              </button>
            </template>
            <button :disabled="packagesPage >= packagesTotalPages" type="button" class="btn-ghost btn-sm" :class="packagesPage >= packagesTotalPages ? 'cursor-not-allowed' : ''" @click="goToPackagesPage(packagesPage + 1)">{{ t('instance.nextPage') }}</button>
          </div>
        </div>
      </div>
    </template>

    <PackageQuotaReleaseModal
      v-if="quotaReleasePackage"
      :visible="showQuotaReleaseModal"
      :package-id="quotaReleasePackage.id"
      :package-name="quotaReleasePackage.name"
      @close="showQuotaReleaseModal = false"
      @success="handleQuotaReleaseSuccess"
    />
  </div>
</template>
