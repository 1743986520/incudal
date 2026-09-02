<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute, useRouter } from 'vue-router'
import api from '@/api'
import SkeletonLoader from '@/components/SkeletonLoader.vue'
import PackageQuotaReleaseModal from '@/components/PackageQuotaReleaseModal.vue'
import PackagePlansTab from '@/components/package/PackagePlansTab.vue'
import PackageFormView from '@/views/resources/PackageFormView.vue'
import { useAuthStore } from '@/stores/auth'
import { useThemeStore } from '@/stores/theme'
import { useToast } from '@/stores/toast'
import { translateError } from '@/utils/errorHandler'
import { formatBytes, formatDisk, formatMemory } from '@/utils/formatters'
import type { Host, Package } from '@/types/api'

defineOptions({ name: 'MyPackageDetailView' })

type TabType = 'overview' | 'config' | 'plans'

const { t } = useI18n()
const route = useRoute()
const router = useRouter()
const toast = useToast()
const themeStore = useThemeStore()
const authStore = useAuthStore()

const pkg = ref<Package | null>(null)
const hosts = ref<Host[]>([])
const loading = ref(true)
const activeTab = ref<TabType>(normalizeTab(route.query.tab))
const showQuotaReleaseModal = ref(false)
const deleting = ref(false)

const isAdmin = computed(() => authStore.user?.role === 'admin')
const canManagePackage = computed(() => Boolean(pkg.value && (isAdmin.value || pkg.value.isOwn === true || pkg.value.ownerId === authStore.user?.id)))

const statusInfo = computed(() => {
  if (!pkg.value) return { label: '', class: '' }
  const activeValue = pkg.value.active as unknown
  const active = activeValue === 1 || activeValue === true
  return active
    ? { label: t('admin.packages.active'), class: 'badge-success' }
    : { label: t('admin.packages.inactive'), class: 'badge-default' }
})

const hasPaidPlans = computed(() => (pkg.value?.planSummary?.total || 0) > 0)

const tabs = computed(() => [
  { key: 'overview' as TabType, labelKey: 'resources.packages.detail.tabs.overview', icon: 'M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z' },
  ...(canManagePackage.value
    ? [
        { key: 'config' as TabType, labelKey: 'resources.packages.detail.tabs.config', icon: 'M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z' },
        { key: 'plans' as TabType, labelKey: 'resources.packages.detail.tabs.plans', icon: 'M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01' }
      ]
    : [])
])

onMounted(async () => {
  await Promise.all([loadPackage(), loadHosts()])
})

watch(() => route.params.id, async (newId, oldId) => {
  if (route.name !== 'my-package-detail') return
  if (newId && newId !== oldId) {
    loading.value = true
    pkg.value = null
    activeTab.value = normalizeTab(route.query.tab)
    await Promise.all([loadPackage(), loadHosts()])
  }
})

watch(() => route.query.tab, (tab) => {
  const nextTab = normalizeTab(tab)
  if (pkg.value && !canManagePackage.value && nextTab !== 'overview') {
    setActiveTab('overview')
    return
  }
  if (nextTab !== activeTab.value) activeTab.value = nextTab
})

watch(canManagePackage, (canManage) => {
  if (pkg.value && !canManage && activeTab.value !== 'overview') {
    setActiveTab('overview')
  }
})

function normalizeTab(tab: unknown): TabType {
  return tab === 'config' || tab === 'plans' || tab === 'overview' ? tab : 'overview'
}

function setActiveTab(tab: TabType): void {
  activeTab.value = tab
  router.replace({
    name: 'my-package-detail',
    params: { id: route.params.id },
    query: tab === 'overview' ? {} : { ...route.query, tab }
  })
}

async function loadPackage(): Promise<void> {
  const packageId = Number(route.params.id)
  if (!Number.isInteger(packageId) || packageId <= 0) {
    toast.error(t('resources.packages.detail.invalidId'))
    router.replace({ name: 'my-packages' })
    return
  }

    try {
      const response = await api.packages.get(packageId) as Package | { package?: Package }
      pkg.value = ('package' in response && response.package) ? response.package : response as Package
      if (!canManagePackage.value && activeTab.value !== 'overview') {
        setActiveTab('overview')
      }
    } catch (err: any) {
    toast.error(t('admin.packages.loadFailed') + ': ' + translateError(err))
    router.replace({ name: 'my-packages' })
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

function onConfigSaved(): void {
  void Promise.all([loadPackage(), loadHosts()])
}

function handleQuotaReleaseSuccess(): void {
  void Promise.all([loadPackage(), loadHosts()])
}

function getBoundHostIds(packageItem: Package): number[] {
  return packageItem.host_ids || []
}

function getBoundHosts(packageItem: Package): Array<Host | { id: number; name: string; country_code?: string }> {
  return getBoundHostIds(packageItem).map(id => hosts.value.find(host => host.id === id) || { id, name: `Host #${id}` })
}

function getHostNames(packageItem: Package): string {
  const boundHosts = getBoundHosts(packageItem)
  if (boundHosts.length === 0) return t('admin.packages.noHostsBound')
  return boundHosts.map(host => host.name).join(', ')
}

function getPackageNetworkModeLabel(packageItem: Package): string {
  const mode = (packageItem.network_mode || packageItem.networkMode || 'nat').toLowerCase()
  const key = `common.networkMode.${mode}`
  const translated = t(key)
  return translated === key ? mode : translated
}

function getPackageInstanceTypeLabel(packageItem: Package): string {
  return packageItem.instance_type === 'vm' ? t('common.instanceType.vm') : t('common.instanceType.container')
}

function isPackagePublic(packageItem: Package): boolean {
  const globalShared = (packageItem as { global_shared?: unknown }).global_shared
  const active = (packageItem as { active?: unknown }).active
  const isActive = active === true || active === 1
  return isActive && (globalShared === true || globalShared === 1 || packageItem.isGlobalShared === true)
}

function formatBoolean(value: unknown): string {
  return value === true || value === 1 ? t('common.yes') : t('common.no')
}

function formatTrafficLimit(bytes: string | null | undefined): string {
  if (!bytes) return t('admin.packages.unlimitedPlaceholder')
  const value = Number(bytes)
  if (!Number.isFinite(value) || value <= 0) return t('admin.packages.unlimitedPlaceholder')
  return formatBytes(value)
}

function formatPrice(cents: number | null | undefined): string {
  if (cents === null || cents === undefined) return '-'
  return `¥${(cents / 100).toFixed(2)}`
}

function formatNumberRange(min: number | null | undefined, max: number | null | undefined, formatter: (value: number) => string): string {
  if (min === null || min === undefined) return '-'
  if (max === null || max === undefined || min === max) return formatter(min)
  return `${formatter(min)} - ${formatter(max)}`
}

function formatTrafficRange(min: string | null | undefined, max: string | null | undefined): string {
  if (!min) return '-'
  if (!max || min === max) return formatTrafficLimit(min)
  return `${formatTrafficLimit(min)} - ${formatTrafficLimit(max)}`
}

function formatSpeedRange(min: string | null | undefined, max: string | null | undefined): string {
  const formatSpeed = (value: string | null | undefined): string => {
    if (!value || value === '0') return '-'
    const bytes = Number(value)
    if (!Number.isFinite(bytes) || bytes <= 0) return '-'
    return `${Math.round(bytes / (1024 * 1024))} Mbps`
  }
  if (!min) return '-'
  if (!max || min === max) return formatSpeed(min)
  return `${formatSpeed(min)} - ${formatSpeed(max)}`
}

function formatTrafficMultiplier(value: unknown): string {
  const multiplier = Number(value ?? 1)
  if (!Number.isFinite(multiplier)) return '1x'
  return `${Math.round(multiplier * 1000) / 1000}x`
}

function getPackageTrafficMultiplierItems(packageItem: Package): Array<{ hostName: string; multiplier: string }> {
  const hostIds = getBoundHostIds(packageItem)
  const multipliers = packageItem.host_traffic_multipliers || {}
  if (hostIds.length === 0) {
    return [{ hostName: t('admin.packages.noHostsBound'), multiplier: formatTrafficMultiplier(1) }]
  }
  return hostIds.map(id => ({
    hostName: hosts.value.find(host => host.id === id)?.name || `Host #${id}`,
    multiplier: formatTrafficMultiplier(multipliers[String(id)] ?? 1)
  }))
}

function getPackageTrafficMultiplierLabel(packageItem: Package): string {
  return [...new Set(getPackageTrafficMultiplierItems(packageItem).map(item => item.multiplier))].join(' / ')
}

function copyShareLink(packageItem: Package): void {
  const hostNames = getHostNames(packageItem)
  const isHostedPackage = hostNames.split(', ').some(name => name.toUpperCase().startsWith('PEER'))
  const source = isHostedPackage ? 'market' : 'official'
  const link = `${window.location.origin}/instances/create?source=${source}&package=${packageItem.id}`

  navigator.clipboard.writeText(link).then(() => {
    toast.success(t('resources.packages.shareLinkCopied'))
  }).catch(() => {
    toast.error(t('common.copyFailed'))
  })
}

async function deletePackage(): Promise<void> {
  if (!pkg.value || deleting.value) return
  if (!confirm(t('admin.packages.confirmDelete', { name: pkg.value.name }))) return

  deleting.value = true
  try {
    await api.packages.delete(pkg.value.id)
    toast.success(t('admin.packages.packageDeleted'))
    router.push({ name: 'my-packages' })
  } catch (err: any) {
    toast.error(t('admin.packages.deleteFailed') + ': ' + translateError(err))
  } finally {
    deleting.value = false
  }
}
</script>

<template>
  <div class="space-y-6 animate-fade-in">
    <div v-if="loading">
      <SkeletonLoader type="detail" />
    </div>

    <template v-else-if="pkg">
      <div class="page-header flex-col sm:flex-row gap-4">
        <div class="flex items-center gap-3 min-w-0">
          <RouterLink
            to="/resources/packages"
            class="shrink-0 transition-colors"
            :class="themeStore.isDark ? 'text-gray-500 hover:text-gray-300' : 'text-gray-400 hover:text-gray-600'"
          >
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M15 19l-7-7 7-7" />
            </svg>
          </RouterLink>
          <div class="min-w-0">
            <div class="flex flex-wrap items-center gap-3">
              <h1 class="page-title truncate">{{ pkg.name }}</h1>
              <span :class="['badge', statusInfo.class]">{{ statusInfo.label }}</span>
              <span
                v-if="isPackagePublic(pkg)"
                class="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ring-1 bg-blue-50 text-blue-700 ring-blue-200 dark:bg-blue-500/15 dark:text-blue-300 dark:ring-blue-500/30"
              >
                {{ t('resources.packages.publicBadge') }}
              </span>
            </div>
            <p class="page-description mt-0.5 truncate">{{ pkg.description || getHostNames(pkg) }}</p>
          </div>
        </div>

        <div class="flex items-center gap-2 flex-wrap">
          <button type="button" class="btn-secondary btn-sm sm:btn" @click="copyShareLink(pkg)">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
            </svg>
            {{ t('resources.packages.copyShareLink') }}
          </button>
          <button v-if="canManagePackage" type="button" class="btn-primary btn-sm sm:btn" @click="showQuotaReleaseModal = true">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
            </svg>
            {{ t('quotaRelease.title') }}
          </button>
        </div>
      </div>

      <div class="relative">
        <div
          class="flex gap-1 p-1 rounded-xl overflow-x-auto scrollbar-hide scroll-smooth"
          :class="themeStore.isDark ? 'bg-gray-900' : 'bg-gray-100'"
        >
          <button
            v-for="tab in tabs"
            :key="tab.key"
            type="button"
            :class="[
              'flex items-center gap-1.5 sm:gap-2 px-3 sm:px-4 py-2 text-xs sm:text-sm font-medium rounded-lg transition-all whitespace-nowrap shrink-0',
              activeTab === tab.key
                ? (themeStore.isDark ? 'bg-gray-800 text-white shadow-sm' : 'bg-white text-gray-900 shadow-sm')
                : (themeStore.isDark ? 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/50' : 'text-gray-500 hover:text-gray-900 hover:bg-white/50')
            ]"
            @click="setActiveTab(tab.key as TabType)"
          >
            <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" :d="tab.icon" />
            </svg>
            <span>{{ t(tab.labelKey) }}</span>
          </button>
        </div>
      </div>

      <div v-if="activeTab === 'overview'" class="space-y-6">
        <div v-if="!hasPaidPlans" class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
          <div class="card p-4">
            <div class="text-xs text-themed-muted">{{ t('resources.packages.detail.overview.freePackage') }}</div>
            <div class="mt-2 text-2xl font-semibold text-themed">{{ pkg.cpu_max }}%</div>
            <div class="text-xs text-themed-muted">{{ t('admin.packages.cpu') }}</div>
          </div>
          <div class="card p-4">
            <div class="text-xs text-themed-muted">{{ t('admin.packages.memory') }}</div>
            <div class="mt-2 text-2xl font-semibold text-themed">{{ formatMemory(pkg.memory_max) }}</div>
          </div>
          <div class="card p-4">
            <div class="text-xs text-themed-muted">{{ t('admin.packages.disk') }}</div>
            <div class="mt-2 text-2xl font-semibold text-themed">{{ formatDisk(pkg.disk_max) }}</div>
          </div>
          <div class="card p-4">
            <div class="text-xs text-themed-muted">{{ t('resources.packages.instanceColumn') }}</div>
            <div class="mt-2 text-2xl font-semibold text-themed">{{ pkg.instance_count || 0 }}</div>
          </div>
        </div>

        <div v-else class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
          <div class="card p-4">
            <div class="text-xs text-themed-muted">{{ t('resources.packages.detail.overview.availablePlans') }}</div>
            <div class="mt-2 text-2xl font-semibold text-themed">{{ pkg.planSummary?.availableCount || 0 }}</div>
            <div class="text-xs text-themed-muted">{{ t('resources.packages.detail.overview.totalPlans', { count: pkg.planSummary?.total || 0 }) }}</div>
          </div>
          <div class="card p-4">
            <div class="text-xs text-themed-muted">{{ t('resources.packages.detail.overview.lowestPrice') }}</div>
            <div class="mt-2 text-2xl font-semibold text-themed">{{ formatPrice(pkg.planSummary?.minPrice) }}</div>
            <div class="text-xs text-themed-muted">{{ t('resources.plans.monthly') }} {{ formatPrice(pkg.planSummary?.minMonthlyPrice) }}</div>
          </div>
          <div class="card p-4">
            <div class="text-xs text-themed-muted">{{ t('resources.packages.detail.overview.resourceRange') }}</div>
            <div class="mt-2 text-lg font-semibold text-themed">
              {{ formatNumberRange(pkg.planSummary?.minCpu, pkg.planSummary?.maxCpu, value => `${value}%`) }}
            </div>
            <div class="text-xs text-themed-muted">
              {{ formatNumberRange(pkg.planSummary?.minMemory, pkg.planSummary?.maxMemory, formatMemory) }} / {{ formatNumberRange(pkg.planSummary?.minDisk, pkg.planSummary?.maxDisk, formatDisk) }}
            </div>
          </div>
          <div class="card p-4">
            <div class="text-xs text-themed-muted">{{ t('resources.packages.detail.overview.trafficRange') }}</div>
            <div class="mt-2 text-lg font-semibold text-themed">{{ formatTrafficRange(pkg.planSummary?.minTrafficLimit, pkg.planSummary?.maxTrafficLimit) }}</div>
            <div class="text-xs text-themed-muted">{{ formatSpeedRange(pkg.planSummary?.minTrafficLimitSpeed, pkg.planSummary?.maxTrafficLimitSpeed) }}</div>
          </div>
        </div>

        <div class="grid grid-cols-1 xl:grid-cols-3 gap-6">
          <div class="card p-5 xl:col-span-2">
            <h2 class="text-base font-medium text-themed mb-4">{{ t('resources.packages.detail.overview.basic') }}</h2>
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm">
              <div>
                <div class="text-xs text-themed-muted">{{ t('resources.packages.networkModeColumn') }}</div>
                <div class="mt-1 text-themed">{{ getPackageNetworkModeLabel(pkg) }}</div>
              </div>
              <div>
                <div class="text-xs text-themed-muted">{{ t('resources.packages.instanceTypeColumn') }}</div>
                <div class="mt-1 text-themed">{{ getPackageInstanceTypeLabel(pkg) }}</div>
              </div>
              <div>
                <div class="text-xs text-themed-muted">{{ t('admin.packages.trafficLimit') }}</div>
                <div class="mt-1 text-themed">{{ formatTrafficLimit(pkg.monthly_traffic_limit) }}</div>
              </div>
              <div>
                <div class="text-xs text-themed-muted">{{ t('resources.packages.trafficMultiplierColumn') }}</div>
                <div class="mt-1 text-themed">{{ getPackageTrafficMultiplierLabel(pkg) }}</div>
              </div>
              <div>
                <div class="text-xs text-themed-muted">{{ t('admin.packages.privileged') }}</div>
                <div class="mt-1 text-themed">{{ formatBoolean(pkg.privileged) }}</div>
              </div>
              <div>
                <div class="text-xs text-themed-muted">{{ t('admin.packages.nested') }}</div>
                <div class="mt-1 text-themed">{{ formatBoolean(pkg.nested) }}</div>
              </div>
            </div>
          </div>

          <div class="card p-5">
            <h2 class="text-base font-medium text-themed mb-4">{{ t('resources.packages.detail.overview.visibility') }}</h2>
            <div class="space-y-3 text-sm">
              <div class="flex items-center justify-between gap-3">
                <span class="text-themed-muted">{{ t('packageForm.fields.publicAccess') }}</span>
                <span class="text-themed">{{ formatBoolean(isPackagePublic(pkg)) }}</span>
              </div>
              <div class="flex items-center justify-between gap-3">
                <span class="text-themed-muted">{{ t('packageForm.fields.globalMaxInstances') }}</span>
                <span class="text-themed">{{ pkg.global_max_instances || '-' }}</span>
              </div>
              <div class="flex items-center justify-between gap-3">
                <span class="text-themed-muted">{{ t('packageForm.fields.requiredPackage') }}</span>
                <span class="text-themed truncate">{{ pkg.required_package_name || '-' }}</span>
              </div>
            </div>
          </div>
        </div>

        <div class="card p-5">
          <div class="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between mb-4">
            <h2 class="text-base font-medium text-themed">{{ t('resources.packages.detail.overview.boundHosts') }}</h2>
            <span class="text-xs text-themed-muted">{{ getBoundHostIds(pkg).length }} {{ t('common.items') }}</span>
          </div>

          <div v-if="getBoundHosts(pkg).length === 0" class="text-sm text-themed-muted">
            {{ t('admin.packages.noHostsBound') }}
          </div>
          <div v-else class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
            <div
              v-for="host in getBoundHosts(pkg)"
              :key="host.id"
              class="rounded-lg border p-3"
              :class="themeStore.isDark ? 'border-gray-800 bg-gray-900/40' : 'border-gray-200 bg-gray-50'"
            >
              <div class="flex items-center justify-between gap-3">
                <div class="min-w-0">
                  <div class="truncate text-sm font-medium text-themed">{{ host.name }}</div>
                  <div class="text-xs text-themed-muted">ID: {{ host.id }}</div>
                </div>
                <span class="text-xs font-mono text-themed-muted">{{ getPackageTrafficMultiplierItems(pkg).find(item => item.hostName === host.name)?.multiplier || '1x' }}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div v-else-if="activeTab === 'config' && canManagePackage" class="space-y-6">
        <PackageFormView embedded :package-id="pkg.id" @saved="onConfigSaved" />

        <div v-if="canManagePackage" class="card p-5 border" :class="themeStore.isDark ? 'border-red-500/30 bg-red-500/5' : 'border-red-200 bg-red-50/50'">
          <div class="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <h2 class="text-base font-medium text-error">{{ t('resources.packages.detail.danger.title') }}</h2>
              <p class="mt-1 text-sm text-themed-muted">{{ t('resources.packages.detail.danger.deleteHint') }}</p>
            </div>
            <button type="button" class="btn-danger" :disabled="deleting" @click="deletePackage">
              <span v-if="deleting" class="loading-spinner w-4 h-4"></span>
              <span v-else>{{ t('common.delete') }}</span>
            </button>
          </div>
        </div>
      </div>

      <PackagePlansTab v-else-if="activeTab === 'plans' && canManagePackage" :pkg="pkg" @changed="onConfigSaved" />

      <PackageQuotaReleaseModal
        :visible="showQuotaReleaseModal"
        :package-id="pkg.id"
        :package-name="pkg.name"
        @close="showQuotaReleaseModal = false"
        @success="handleQuotaReleaseSuccess"
      />
    </template>
  </div>
</template>
