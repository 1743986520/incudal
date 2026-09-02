<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import api from '@/api'
import { usePageSeo } from '@/composables/usePageSeo'
import { useAuthStore } from '@/stores/auth'
import { useThemeStore } from '@/stores/theme'
import { useBrand } from '@/composables/useBrand'
import {
  formatPublicPrice,
  getPackageTrafficLabel,
  getStartingMonthlyPrice,
  type PackageSource,
  type PublicPackage,
  type PublicRegion
} from '@/utils/publicCatalog'

defineOptions({
  name: 'PortalView'
})

const router = useRouter()
const { t } = useI18n()
const authStore = useAuthStore()
const themeStore = useThemeStore()
const brand = useBrand()

const packages = ref<PublicPackage[]>([])
const regions = ref<PublicRegion[]>([])
const loading = ref(true)

const spotlightPackages = computed(() => {
  const allPackages = [...packages.value].sort((left, right) => {
    if (left.soldOut !== right.soldOut) {
      return left.soldOut ? 1 : -1
    }

    const leftPrice = getStartingMonthlyPrice(left)
    const rightPrice = getStartingMonthlyPrice(right)

    if (leftPrice !== null && rightPrice !== null && leftPrice !== rightPrice) {
      return leftPrice - rightPrice
    }

    return left.name.localeCompare(right.name, 'zh')
  })

  return allPackages.slice(0, 4)
})

const statCards = computed(() => [
  { label: t('publicSite.portal.stats.packages'), value: String(packages.value.length) },
  { label: t('publicSite.portal.stats.regions'), value: String(regions.value.length) },
  { label: t('publicSite.portal.stats.official'), value: String(packages.value.filter(pkg => pkg.sourceType === 'official').length) },
  { label: t('publicSite.portal.stats.market'), value: String(packages.value.filter(pkg => pkg.sourceType === 'market').length) }
])

const platformCards = computed(() => [
  {
    title: t('publicSite.portal.experienceNoLoginTitle'),
    description: t('publicSite.portal.experienceNoLoginDescription')
  },
  {
    title: t('publicSite.portal.experienceRoutingTitle'),
    description: t('publicSite.portal.experienceRoutingDescription')
  },
  {
    title: t('publicSite.portal.experienceThemeTitle'),
    description: t('publicSite.portal.experienceThemeDescription')
  }
])

const ecosystemCards = computed(() => [
  {
    key: 'official',
    source: 'official' as PackageSource,
    title: t('publicSite.portal.officialTitle'),
    description: t('publicSite.portal.officialDescription'),
    points: [
      t('publicSite.portal.officialPoint1'),
      t('publicSite.portal.officialPoint2'),
      t('publicSite.portal.officialPoint3')
    ]
  },
  {
    key: 'market',
    source: 'market' as PackageSource,
    title: t('publicSite.portal.marketTitle'),
    description: t('publicSite.portal.marketDescription'),
    points: [
      t('publicSite.portal.marketPoint1'),
      t('publicSite.portal.marketPoint2'),
      t('publicSite.portal.marketPoint3')
    ]
  }
])

const consoleActionLabel = computed(() => (
  authStore.isAuthenticated ? t('publicSite.actions.console') : t('publicSite.actions.signIn')
))

const consoleActionCompactLabel = computed(() => (
  authStore.isAuthenticated ? t('publicSite.actions.consoleCompact') : t('publicSite.actions.signIn')
))

const ui = computed(() => themeStore.isDark
  ? {
      badge: 'border-gray-800 bg-gray-950 text-gray-300', body: 'text-gray-400',
      primaryButton: 'bg-white text-gray-900 hover:bg-gray-100 focus-visible:ring-white/20',
      secondaryButton: 'border border-gray-800 text-gray-100 hover:bg-gray-900 focus-visible:ring-gray-700',
      statCard: 'border border-gray-800 bg-gray-950', statValue: 'text-gray-100', statLabel: 'text-gray-500',
      previewCard: 'border border-gray-800 bg-gray-950 text-gray-100', previewLabel: 'text-gray-500', previewTitle: 'text-gray-100',
      previewButton: 'bg-white text-gray-900 hover:bg-gray-100', previewBody: 'text-gray-400',
      terminalCard: 'border border-gray-800 bg-black text-gray-300', terminalMeta: 'text-gray-600',
      platformCard: 'border border-gray-800 bg-gray-900 text-gray-100', platformTitle: 'text-gray-100', platformBody: 'text-gray-400',
      sectionLabel: 'text-gray-500', sectionBody: 'text-gray-400',
      ecosystemOfficialCard: 'border border-gray-800 bg-gray-950 text-gray-100', ecosystemMarketCard: 'border border-gray-800 bg-gray-950 text-gray-100',
      ecosystemOfficialBody: 'text-gray-400', ecosystemMarketBody: 'text-gray-400', ecosystemOfficialList: 'text-gray-300', ecosystemMarketList: 'text-gray-300',
      ecosystemOfficialButton: 'bg-white text-gray-900 hover:bg-gray-100', ecosystemMarketButton: 'border border-gray-700 text-gray-100 hover:bg-gray-900',
      browseWrap: 'border border-gray-800 bg-gray-950', browseCard: 'border border-gray-800 hover:border-gray-700',
      emptyState: 'border-gray-800 bg-gray-950 text-gray-500', skeleton: 'bg-gray-800'
    }
  : {
      badge: 'border-gray-200 bg-white text-gray-600', body: 'text-gray-600',
      primaryButton: 'bg-gray-900 text-white hover:bg-gray-700 focus-visible:ring-gray-900/20',
      secondaryButton: 'border border-gray-300 text-gray-900 hover:bg-gray-100 focus-visible:ring-gray-300',
      statCard: 'border border-gray-200 bg-white shadow-sm', statValue: 'text-gray-900', statLabel: 'text-gray-500',
      previewCard: 'border border-gray-200 bg-white text-gray-900 shadow-sm', previewLabel: 'text-gray-500', previewTitle: 'text-gray-900',
      previewButton: 'bg-gray-900 text-white hover:bg-gray-700', previewBody: 'text-gray-600',
      terminalCard: 'border border-gray-800 bg-gray-950 text-gray-200', terminalMeta: 'text-gray-500',
      platformCard: 'border border-gray-200 bg-gray-50 text-gray-900', platformTitle: 'text-gray-900', platformBody: 'text-gray-600',
      sectionLabel: 'text-gray-500', sectionBody: 'text-gray-600',
      ecosystemOfficialCard: 'border border-gray-200 bg-white text-gray-900 shadow-sm', ecosystemMarketCard: 'border border-gray-200 bg-white text-gray-900 shadow-sm',
      ecosystemOfficialBody: 'text-gray-600', ecosystemMarketBody: 'text-gray-600', ecosystemOfficialList: 'text-gray-700', ecosystemMarketList: 'text-gray-700',
      ecosystemOfficialButton: 'bg-gray-900 text-white hover:bg-gray-700', ecosystemMarketButton: 'border border-gray-300 text-gray-900 hover:bg-gray-100',
      browseWrap: 'border border-gray-200 bg-gray-50', browseCard: 'border border-gray-200 hover:border-gray-300 hover:shadow-sm',
      emptyState: 'border-gray-300 bg-white text-gray-500', skeleton: 'bg-gray-200'
    }
)

usePageSeo(() => ({
  title: `${brand.brandName} - ${brand.brandSubtitle}`,
  description: brand.brandSubtitle,
  canonical: `${window.location.origin}/`,
  keywords: t('publicSite.seo.keywords').replace(/Incudal/g, brand.brandName)
}))

function formatPackageTraffic(pkg: PublicPackage): string {
  return getPackageTrafficLabel(pkg, t('common.unlimited'))
}

function getPriceLabel(pkg: PublicPackage): string {
  const startPrice = getStartingMonthlyPrice(pkg)
  if (startPrice === null) {
    return t('publicSite.market.free')
  }

  return t('publicSite.market.fromMonthly', { price: formatPublicPrice(startPrice) })
}

function getSourceChipClass(source: PackageSource): string {
  void source
  return themeStore.isDark ? 'border border-gray-700 text-gray-300' : 'border border-gray-300 text-gray-600'
}

function getSourceDotClass(source: PackageSource): string {
  void source
  return themeStore.isDark ? 'bg-gray-500' : 'bg-gray-400'
}

function getInstanceChipClass(instanceType: string): string {
  if (instanceType === 'vm') {
    return themeStore.isDark ? 'border border-gray-700 text-gray-300' : 'border border-gray-300 text-gray-600'
  }

  return themeStore.isDark
    ? 'border border-gray-700 text-gray-400'
    : 'border border-gray-300 text-gray-500'
}

function getEcosystemCardClass(source: PackageSource): string {
  if (source === 'official') {
    return themeStore.isDark ? ui.value.ecosystemOfficialCard : ui.value.ecosystemOfficialCard
  }
  return themeStore.isDark ? ui.value.ecosystemMarketCard : ui.value.ecosystemMarketCard
}

function getPackageCardClass(_source: PackageSource): string {
  return themeStore.isDark
    ? 'bg-gray-950 hover:bg-gray-900'
    : 'bg-white hover:bg-gray-50'
}

function getPriceTextClass(source: PackageSource): string {
  if (source === 'official') {
    return themeStore.isDark ? 'text-gray-100' : 'text-gray-900'
  }
  return themeStore.isDark ? 'text-gray-300' : 'text-gray-700'
}

function browseCatalog(source?: PackageSource): void {
  void router.push({
    path: '/market',
    query: source ? { source } : undefined
  })
}

function goToHostingGuide(): void {
  void router.push({ name: 'help-article', params: { slug: 'hosting-tutorial' } })
}

function openPackage(pkg: PublicPackage): void {
  void router.push({
    path: '/market',
    query: {
      source: pkg.sourceType,
      package: String(pkg.id)
    }
  })
}

function goToConsole(): void {
  if (authStore.isAuthenticated) {
    const target = authStore.isAdmin ? '/admin/users' : '/dashboard'
    void router.push(target)
    return
  }

  void router.push('/login')
}

async function loadCatalog(): Promise<void> {
  loading.value = true

  try {
    const [packagesResponse, regionsResponse] = await Promise.all([
      api.packages.listPublic(),
      api.packages.getPublicRegions()
    ])

    packages.value = (packagesResponse.packages || []) as unknown as PublicPackage[]
    regions.value = regionsResponse.regions || []
  } catch (error) {
    console.error('Failed to load public catalog:', error)
    packages.value = []
    regions.value = []
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  void loadCatalog()
})
</script>

<template>
  <div class="relative">
    <section class="relative px-4 pb-20 pt-14 sm:px-6 lg:px-8">
      <div class="relative mx-auto grid max-w-7xl gap-10 lg:grid-cols-[1.1fr_0.9fr] lg:items-center">
        <div class="max-w-3xl">
          <div
            class="inline-flex items-center gap-2 rounded-lg border px-3 py-1.5 text-xs font-medium"
            :class="ui.badge"
          >
            <span class="h-1.5 w-1.5 rounded-lg" :class="themeStore.isDark ? 'bg-[#a8c7fa]' : 'bg-[#0b57d0]'"></span>
            {{ t('publicSite.portal.badge') }}
          </div>

          <h1 class="mt-6 text-4xl font-normal tracking-[-0.02em] sm:text-5xl lg:text-[3.5rem] lg:leading-[1.1]">
            {{ t('publicSite.portal.title') }}
          </h1>
          <p class="mt-6 max-w-2xl text-base leading-7 sm:text-lg sm:leading-8" :class="ui.body">
            {{ t('publicSite.portal.description') }}
          </p>

          <div class="mt-8 flex flex-col gap-3 sm:flex-row">
            <button
              class="inline-flex h-10 items-center justify-center gap-2 rounded-lg px-6 text-sm font-medium tracking-[0.01em] transition-[background-color,box-shadow] duration-150 focus-visible:outline-none focus-visible:ring-4"
              :class="ui.primaryButton"
              @click="browseCatalog()"
            >
              <span>{{ t('publicSite.actions.browseProducts') }}</span>
              <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.5 4.5l6 6m0 0l-6 6m6-6h-15" />
              </svg>
            </button>

            <button
              class="inline-flex h-10 items-center justify-center gap-2 rounded-lg px-6 text-sm font-medium tracking-[0.01em] transition-colors duration-150 focus-visible:outline-none focus-visible:ring-4"
              :class="ui.secondaryButton"
              @click="goToConsole"
            >
              <span class="sm:hidden">{{ consoleActionCompactLabel }}</span>
              <span class="hidden sm:inline">{{ consoleActionLabel }}</span>
            </button>
          </div>

          <div class="mt-10 grid grid-cols-2 gap-3 xl:grid-cols-4">
            <div
              v-for="item in statCards"
              :key="item.label"
              class="rounded-lg px-4 py-4 transition-shadow duration-150"
              :class="ui.statCard"
            >
              <div class="text-xs font-medium" :class="ui.statLabel">
                {{ item.label }}
              </div>
              <div class="mt-2 text-2xl font-normal tracking-[-0.02em]" :class="ui.statValue">
                {{ item.value }}
              </div>
            </div>
          </div>
        </div>

        <div class="relative">
          <div
            class="relative overflow-hidden rounded-xl p-6"
            :class="ui.previewCard"
          >
            <div class="flex flex-col items-start gap-4 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <div class="text-xs font-medium" :class="ui.previewLabel">
                  {{ t('publicSite.portal.previewLabel') }}
                </div>
                <div class="mt-2 text-2xl font-normal tracking-[-0.02em]" :class="ui.previewTitle">
                  {{ t('publicSite.portal.previewTitle') }}
                </div>
              </div>

              <button
                class="h-10 rounded-lg px-5 text-sm font-medium transition-colors duration-150"
                :class="ui.previewButton"
                @click="browseCatalog()"
              >
                {{ t('publicSite.actions.viewCatalog') }}
              </button>
            </div>

            <p class="mt-4 text-sm leading-6" :class="ui.previewBody">
              {{ t('publicSite.portal.previewDescription') }}
            </p>

            <div class="mt-6 rounded-lg p-5 font-mono text-xs leading-6" :class="ui.terminalCard">
              <div class="flex flex-wrap items-center justify-between gap-2">
                <span>root@incudal</span>
                <span :class="ui.terminalMeta">incus console</span>
              </div>
              <div class="mt-4 space-y-1">
                <div>{{ t('publicSite.portal.controlPoint1') }}</div>
                <div>{{ t('publicSite.portal.controlPoint2') }}</div>
                <div>{{ t('publicSite.portal.controlPoint3') }}</div>
              </div>
            </div>

            <div class="mt-6 grid gap-3 sm:grid-cols-3">
              <div
                v-for="card in platformCards"
                :key="card.title"
                class="rounded-lg p-4 transition-colors duration-150"
                :class="ui.platformCard"
              >
                <div class="text-sm font-medium" :class="ui.platformTitle">
                  {{ card.title }}
                </div>
                <p class="mt-2 text-xs leading-5" :class="ui.platformBody">
                  {{ card.description }}
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>

    <section class="px-4 py-20 sm:px-6 lg:px-8">
      <div class="mx-auto max-w-7xl">
        <div class="max-w-2xl">
          <div class="text-xs font-medium" :class="ui.sectionLabel">
            {{ t('publicSite.portal.catalogLabel') }}
          </div>
          <h2 class="mt-4 text-3xl font-normal tracking-[-0.02em] sm:text-[2.25rem] sm:leading-[1.15]">
            {{ t('publicSite.portal.catalogTitle') }}
          </h2>
          <p class="mt-4 text-base leading-7" :class="ui.sectionBody">
            {{ t('publicSite.portal.catalogDescription') }}
          </p>
        </div>

        <div class="mt-10 grid gap-6 lg:grid-cols-2">
          <article
            v-for="line in ecosystemCards"
            :key="line.key"
            class="rounded-xl p-7 transition-shadow duration-150"
            :class="getEcosystemCardClass(line.source)"
          >
            <div class="flex flex-col items-start gap-4 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <h3 class="text-2xl font-normal tracking-[-0.02em]">
                  {{ line.title }}
                </h3>
                <p class="mt-3 text-sm leading-6" :class="line.source === 'official' ? ui.ecosystemOfficialBody : ui.ecosystemMarketBody">
                  {{ line.description }}
                </p>
              </div>
              <span
                class="rounded-lg px-2.5 py-1 text-[11px] font-medium tracking-[0.02em]"
                :class="getSourceChipClass(line.source)"
              >
                {{ line.source === 'official' ? t('publicSite.market.official') : t('publicSite.market.market') }}
              </span>
            </div>

            <div class="mt-6 space-y-3 text-sm" :class="line.source === 'official' ? ui.ecosystemOfficialList : ui.ecosystemMarketList">
              <div v-for="point in line.points" :key="point" class="flex items-start gap-3">
                <span class="mt-1.5 h-1.5 w-1.5 rounded-lg" :class="getSourceDotClass(line.source)"></span>
                <span>{{ point }}</span>
              </div>
            </div>

            <div class="mt-6 flex flex-wrap gap-3">
              <button
                class="inline-flex h-10 items-center gap-2 rounded-lg px-6 text-sm font-medium transition-colors duration-150"
                :class="line.source === 'official' ? ui.ecosystemOfficialButton : ui.ecosystemMarketButton"
                @click="browseCatalog(line.source)"
              >
                {{ line.source === 'official' ? t('publicSite.actions.browseOfficial') : t('publicSite.actions.browseMarket') }}
              </button>
              <button
                v-if="line.source === 'market'"
                class="inline-flex h-10 items-center gap-2 rounded-lg border px-5 text-sm font-medium transition-colors duration-150"
                :class="ui.ecosystemMarketButton"
                @click="goToHostingGuide"
              >
                {{ t('publicSite.actions.viewHostingTutorial') }}
              </button>
            </div>
          </article>
        </div>
      </div>
    </section>

    <section class="px-4 pb-20 sm:px-6 lg:px-8">
      <div
        class="mx-auto max-w-7xl rounded-xl px-6 py-10 sm:px-10"
        :class="ui.browseWrap"
      >
        <div class="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div class="max-w-2xl">
            <div class="text-xs font-medium" :class="ui.sectionLabel">
              {{ t('publicSite.portal.browseLabel') }}
            </div>
            <h2 class="mt-4 text-3xl font-normal tracking-[-0.02em] sm:text-[2.25rem] sm:leading-[1.15]">
              {{ t('publicSite.portal.browseTitle') }}
            </h2>
            <p class="mt-4 text-base leading-7" :class="ui.sectionBody">
              {{ t('publicSite.portal.browseDescription') }}
            </p>
          </div>

          <button
            class="inline-flex h-10 items-center justify-center gap-2 rounded-lg px-6 text-sm font-medium tracking-[0.01em] transition-[background-color,box-shadow] duration-150 focus-visible:outline-none focus-visible:ring-4"
            :class="ui.primaryButton"
            @click="browseCatalog()"
          >
            {{ t('publicSite.actions.browseProducts') }}
          </button>
        </div>

        <div class="mt-8 grid gap-4 lg:grid-cols-2">
          <template v-if="loading">
            <div
              v-for="index in 4"
              :key="index"
              class="h-40 animate-pulse rounded-xl"
              :class="ui.skeleton"
            ></div>
          </template>

          <template v-else-if="spotlightPackages.length > 0">
            <button
              v-for="pkg in spotlightPackages"
              :key="pkg.id"
              class="flex flex-col gap-4 rounded-lg p-5 text-left transition-[background-color,box-shadow] duration-150 sm:flex-row sm:items-start sm:justify-between"
              :class="[ui.browseCard, getPackageCardClass(pkg.sourceType)]"
              @click="openPackage(pkg)"
            >
              <div class="min-w-0">
                <div class="flex flex-wrap items-center gap-2">
                  <span
                    class="rounded-lg px-2 py-0.5 text-[11px] font-medium tracking-[0.02em]"
                    :class="getSourceChipClass(pkg.sourceType)"
                  >
                    {{ pkg.sourceType === 'official' ? t('publicSite.market.official') : t('publicSite.market.market') }}
                  </span>
                  <span
                    class="rounded-lg px-2 py-0.5 text-[11px] font-medium tracking-[0.02em]"
                    :class="getInstanceChipClass(pkg.instance_type)"
                  >
                    {{ pkg.instance_type === 'vm' ? 'KVM' : 'LXC' }}
                  </span>
                </div>
                <div class="mt-3 truncate text-lg font-medium" :class="ui.platformTitle">
                  {{ pkg.name }}
                </div>
                <div class="portal-package-description mt-2 text-sm leading-5" :class="ui.sectionBody">
                  {{ pkg.description || t('publicSite.portal.packageFallback') }}
                </div>
              </div>

              <div class="sm:shrink-0 sm:text-right">
                <div class="text-sm font-medium" :class="getPriceTextClass(pkg.sourceType)">
                  {{ getPriceLabel(pkg) }}
                </div>
                <div class="mt-1 text-xs" :class="ui.statLabel">
                  {{ formatPackageTraffic(pkg) }}
                </div>
              </div>
            </button>
          </template>

          <div
            v-else
            class="rounded-lg border border-dashed px-4 py-8 text-center text-sm"
            :class="ui.emptyState"
          >
            {{ t('publicSite.portal.emptyPackages') }}
          </div>
        </div>
      </div>
    </section>
  </div>
</template>

<style scoped>
.portal-package-description {
  display: -webkit-box;
  max-width: 100%;
  min-width: 0;
  overflow: hidden;
  overflow-wrap: anywhere;
  word-break: break-word;
  text-overflow: ellipsis;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
  line-clamp: 2;
}
</style>
