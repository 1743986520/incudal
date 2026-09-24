<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute, useRouter } from 'vue-router'
import api from '@/api'
import SkeletonLoader from '@/components/SkeletonLoader.vue'
import { useAuthStore } from '@/stores/auth'
import { useThemeStore } from '@/stores/theme'
import { useToast } from '@/stores/toast'
import { translateError } from '@/utils/errorHandler'
import type { Package, PackagePlan } from '@/types/api'

defineOptions({ name: 'PackagePlanFormView' })

type PlanStatus = 'active' | 'soldOut' | 'inactive'

const MAX_PACKAGE_PLAN_PRICE_CENTS = 99999999
const MAX_PACKAGE_PLAN_PRICE = MAX_PACKAGE_PLAN_PRICE_CENTS / 100

const { t } = useI18n()
const route = useRoute()
const router = useRouter()
const toast = useToast()
const themeStore = useThemeStore()
const authStore = useAuthStore()

const pkg = ref<Package | null>(null)
const loading = ref(true)
const saving = ref(false)
const formError = ref('')

const packageId = computed(() => Number(route.params.id))
const planId = computed(() => route.params.planId ? Number(route.params.planId) : null)
const isEditMode = computed(() => Number.isInteger(planId.value) && Number(planId.value) > 0)

const planForm = ref({
  name: '',
  description: '',
  cpu: 100,
  memory: 512,
  disk: 5120,
  portLimit: 3,
  snapshotLimit: 3,
  swapSize: 0,
  siteLimit: 1,
  trafficLimit: 1,
  trafficLimitSpeed: 10,
  trafficBillingMode: 'package' as 'package' | 'usage',
  trafficUnitPrice: 0,
  billingMode: 'package' as 'package' | 'hourly',
  price: 0,
  billingCycle: 1,
  trafficResetEnabled: false,
  trafficResetPrice: 0,
  status: 'active' as PlanStatus,
  sortOrder: 0,
  slaGuarantee: null as number | null
})

const planStatusOptions = computed(() => [
  { value: 'active' as PlanStatus, label: t('resources.plans.statusActive'), description: t('resources.plans.statusActiveHint') },
  { value: 'soldOut' as PlanStatus, label: t('resources.plans.statusSoldOut'), description: t('resources.plans.statusSoldOutHint') },
  { value: 'inactive' as PlanStatus, label: t('resources.plans.statusInactive'), description: t('resources.plans.statusInactiveHint') }
])

const selectedPlanStatusOption = computed(() =>
  planStatusOptions.value.find(option => option.value === planForm.value.status) || planStatusOptions.value[0]
)

const billingCycleOptions = computed(() => {
  if (!authStore.isAdmin) {
    return [{ value: 1, label: t('resources.plans.monthly') }]
  }
  return [
    { value: 1, label: t('resources.plans.monthly') },
    { value: 3, label: t('resources.plans.quarterly') },
    { value: 6, label: t('resources.plans.semiAnnual') },
    { value: 12, label: t('resources.plans.yearly') }
  ]
})

const canManagePackage = computed(() =>
  Boolean(pkg.value && (authStore.isAdmin || pkg.value.isOwn === true || pkg.value.ownerId === authStore.user?.id))
)

onMounted(async () => {
  if (!Number.isInteger(packageId.value) || packageId.value <= 0) {
    toast.error(t('resources.packages.detail.invalidId'))
    router.replace({ name: 'my-packages' })
    return
  }

  try {
    const packageResponse = await api.packages.get(packageId.value) as Package | { package?: Package }
    pkg.value = ('package' in packageResponse && packageResponse.package) ? packageResponse.package : packageResponse as Package
    if (!canManagePackage.value) {
      toast.error(t('errors.FORBIDDEN'))
      router.replace({ name: 'my-package-detail', params: { id: packageId.value }, query: { tab: 'overview' } })
      return
    }

    if (isEditMode.value && planId.value) {
      const response = await api.packages.getPlan(packageId.value, planId.value)
      applyPlan(response.plan)
    } else {
      const plansResponse = await api.packages.getPlans(packageId.value)
      resetForCreate(plansResponse.plans.length)
    }
  } catch (err: any) {
    toast.error(translateError(err) || t('resources.plans.loadFailed'))
    router.replace({ name: 'my-package-detail', params: { id: packageId.value }, query: { tab: 'plans' } })
  } finally {
    loading.value = false
  }
})

function resetForCreate(sortOrder: number): void {
  planForm.value = {
    name: '',
    description: '',
    cpu: pkg.value?.cpu_max || 100,
    memory: pkg.value?.memory_max || 512,
    disk: pkg.value?.disk_max || 5120,
    portLimit: 3,
    snapshotLimit: 3,
    swapSize: 0,
    siteLimit: 1,
    trafficLimit: 1,
    trafficLimitSpeed: 10,
    trafficBillingMode: 'package',
    trafficUnitPrice: 0,
    billingMode: 'package',
    price: 0,
    billingCycle: 1,
    trafficResetEnabled: false,
    trafficResetPrice: 0,
    status: 'active',
    sortOrder,
    slaGuarantee: null
  }
}

function applyPlan(plan: PackagePlan): void {
  planForm.value = {
    name: plan.name,
    description: plan.description || '',
    cpu: plan.cpu,
    memory: plan.memory,
    disk: plan.disk,
    portLimit: plan.portLimit,
    snapshotLimit: plan.snapshotLimit,
    swapSize: plan.swapSize || 0,
    siteLimit: plan.siteLimit,
    trafficLimit: bytesToGB(plan.trafficLimit),
    trafficLimitSpeed: bytesToMbps(plan.trafficLimitSpeed),
    trafficBillingMode: plan.trafficBillingMode || 'package',
    trafficUnitPrice: (plan.trafficUnitPrice || 0) / 100,
    billingMode: plan.billingMode || 'package',
    price: plan.price / 100,
    billingCycle: plan.billingCycle,
    trafficResetEnabled: Boolean(plan.trafficResetEnabled),
    trafficResetPrice: (plan.trafficResetPrice || 0) / 100,
    status: !plan.isActive ? 'inactive' : plan.isSoldOut ? 'soldOut' : 'active',
    sortOrder: plan.sortOrder,
    slaGuarantee: plan.slaGuarantee
  }
}

function bytesToGB(bytes: string | null | undefined): number {
  if (!bytes) return 0
  const value = Number(bytes)
  if (!Number.isFinite(value) || value < 0) return 0
  return Math.round((value / (1024 * 1024 * 1024)) * 1000000) / 1000000
}

function bytesToMbps(bytes: string | null | undefined): number {
  if (!bytes || bytes === '0') return 10
  const value = Number(bytes)
  if (!Number.isFinite(value) || value <= 0) return 10
  return Math.round(value / (1024 * 1024)) || 10
}

function gbToBytes(gb: string | number): string {
  const value = typeof gb === 'string' ? Number.parseFloat(gb) : gb
  if (!Number.isFinite(value) || value < 0) return ''
  return Math.floor(value * 1024 * 1024 * 1024).toString()
}

function mbpsToBytes(mbps: string | number): string {
  const value = typeof mbps === 'string' ? Number.parseFloat(mbps) : mbps
  if (!Number.isFinite(value) || value <= 0) return ''
  return Math.floor(value * 1024 * 1024).toString()
}

function normalizePlanPriceCents(value: unknown): number | null {
  const price = Number(value)
  if (!Number.isFinite(price) || price < 0 || price > MAX_PACKAGE_PLAN_PRICE) return null
  const cents = price * 100
  if (Math.abs(cents - Math.round(cents)) >= 1e-8) return null
  const roundedCents = Math.round(cents)
  return roundedCents <= MAX_PACKAGE_PLAN_PRICE_CENTS ? roundedCents : null
}

function normalizeTrafficUnitPriceCents(value: unknown): number | null {
  const price = Number(value)
  if (!Number.isFinite(price) || price <= 0 || price > MAX_PACKAGE_PLAN_PRICE) return null
  const tenThousandthsOfYuan = price * 10000
  if (Math.abs(tenThousandthsOfYuan - Math.round(tenThousandthsOfYuan)) >= 1e-8) return null
  return Math.round(tenThousandthsOfYuan) / 100
}

function getPlanStatusSegmentClass(status: PlanStatus): string {
  const selected = planForm.value.status === status
  if (!selected) {
    return themeStore.isDark
      ? 'text-gray-400 hover:bg-gray-800 hover:text-gray-200'
      : 'text-gray-500 hover:bg-gray-100 hover:text-gray-900'
  }
  if (status === 'active') {
    return themeStore.isDark
      ? 'bg-emerald-500/15 text-emerald-300 ring-1 ring-emerald-500/30'
      : 'bg-white text-emerald-700 shadow-sm ring-1 ring-emerald-200'
  }
  if (status === 'soldOut') {
    return themeStore.isDark
      ? 'bg-amber-500/15 text-amber-300 ring-1 ring-amber-500/30'
      : 'bg-white text-amber-700 shadow-sm ring-1 ring-amber-200'
  }
  return themeStore.isDark
    ? 'bg-gray-700 text-gray-200 ring-1 ring-gray-600'
    : 'bg-white text-gray-700 shadow-sm ring-1 ring-gray-200'
}

function goBack(): void {
  router.push({ name: 'my-package-detail', params: { id: packageId.value }, query: { tab: 'plans' } })
}

async function savePlan(): Promise<void> {
  formError.value = ''
  if (!planForm.value.name.trim()) {
    formError.value = t('resources.plans.nameRequired')
    return
  }

  const hourlyBilling = planForm.value.billingMode === 'hourly'
  const priceCents = hourlyBilling ? 0 : normalizePlanPriceCents(planForm.value.price)
  if (priceCents === null) {
    formError.value = t('resources.plans.priceRangeError', { max: MAX_PACKAGE_PLAN_PRICE.toFixed(2) })
    return
  }

  const usageBilling = planForm.value.trafficBillingMode === 'usage'
  const trafficUnitPriceCents = usageBilling ? normalizeTrafficUnitPriceCents(planForm.value.trafficUnitPrice) : 0
  if (usageBilling && (!trafficUnitPriceCents || trafficUnitPriceCents <= 0)) {
    formError.value = t('resources.plans.trafficUnitPriceRequired')
    return
  }
  if (!usageBilling && Number(planForm.value.trafficLimit) <= 0) {
    formError.value = t('resources.plans.packageTrafficRequired')
    return
  }

  const trafficResetPriceCents = !usageBilling && planForm.value.trafficResetEnabled
    ? normalizePlanPriceCents(planForm.value.trafficResetPrice)
    : 0
  if (trafficResetPriceCents === null) {
    formError.value = t('resources.plans.trafficResetPriceRangeError', { max: MAX_PACKAGE_PLAN_PRICE.toFixed(2) })
    return
  }

  saving.value = true
  try {
    const data = {
      name: planForm.value.name.trim(),
      description: planForm.value.description.trim() || undefined,
      cpu: planForm.value.cpu,
      memory: planForm.value.memory,
      disk: planForm.value.disk,
      portLimit: planForm.value.portLimit,
      snapshotLimit: planForm.value.snapshotLimit,
      backupLimit: 0,
      siteLimit: planForm.value.siteLimit,
      swapSize: planForm.value.swapSize,
      trafficLimit: gbToBytes(planForm.value.trafficLimit) || '0',
      trafficLimitSpeed: mbpsToBytes(planForm.value.trafficLimitSpeed) || '0',
      trafficBillingMode: planForm.value.trafficBillingMode,
      trafficUnitPrice: trafficUnitPriceCents ?? 0,
      billingMode: planForm.value.billingMode,
      price: priceCents,
      billingCycle: hourlyBilling ? 1 : planForm.value.billingCycle,
      trafficResetEnabled: usageBilling ? false : planForm.value.trafficResetEnabled,
      trafficResetPrice: usageBilling ? 0 : trafficResetPriceCents,
      isActive: planForm.value.status !== 'inactive',
      isSoldOut: planForm.value.status === 'soldOut',
      sortOrder: planForm.value.sortOrder,
      slaGuarantee: planForm.value.slaGuarantee ?? undefined
    }

    if (isEditMode.value && planId.value) {
      await api.packages.updatePlan(packageId.value, planId.value, data)
      toast.success(t('resources.plans.updateSuccess'))
    } else {
      await api.packages.createPlan(packageId.value, data)
      toast.success(t('resources.plans.createSuccess'))
    }

    goBack()
  } catch (err: any) {
    formError.value = translateError(err) || t('resources.plans.saveFailed')
  } finally {
    saving.value = false
  }
}
</script>

<template>
  <div class="space-y-6 animate-fade-in">
    <SkeletonLoader v-if="loading" type="detail" />

    <template v-else-if="pkg">
      <div class="page-header flex-col gap-4 sm:flex-row">
        <div class="flex items-center gap-3 min-w-0">
          <button
            type="button"
            class="shrink-0 transition-colors"
            :class="themeStore.isDark ? 'text-gray-500 hover:text-gray-300' : 'text-gray-400 hover:text-gray-600'"
            @click="goBack"
          >
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M15 19l-7-7 7-7" />
            </svg>
          </button>
          <div class="min-w-0">
            <h1 class="page-title truncate">{{ isEditMode ? t('resources.plans.edit') : t('resources.plans.create') }}</h1>
            <p class="page-description truncate">{{ pkg.name }} · {{ t('resources.plans.formDescription') }}</p>
          </div>
        </div>

        <div class="flex items-center gap-2">
          <button type="button" class="btn-secondary" :disabled="saving" @click="goBack">{{ t('common.cancel') }}</button>
          <button type="button" class="btn-primary" :disabled="saving || !planForm.name.trim()" @click="savePlan">
            <span v-if="saving" class="loading-spinner w-4 h-4"></span>
            <template v-else>{{ t('common.save') }}</template>
          </button>
        </div>
      </div>

      <div v-if="formError" class="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-500/30 dark:bg-red-500/10 dark:text-red-300">
        {{ formError }}
      </div>

      <div class="grid gap-6 xl:grid-cols-[1fr_320px]">
        <form class="space-y-6" @submit.prevent="savePlan">
          <section class="card p-5">
            <h2 class="text-base font-medium text-themed">{{ t('resources.plans.basicInfo') }}</h2>
            <div class="mt-4 grid gap-4 sm:grid-cols-2">
              <div>
                <label class="block text-xs font-medium text-themed-muted mb-1.5">{{ t('resources.plans.name') }} *</label>
                <input v-model="planForm.name" type="text" class="input" :placeholder="t('resources.plans.namePlaceholder')" />
              </div>
              <div>
                <label class="block text-xs font-medium text-themed-muted mb-1.5">{{ t('resources.plans.description') }}</label>
                <input v-model="planForm.description" type="text" class="input" :placeholder="t('resources.plans.descriptionPlaceholder')" />
              </div>
              <div>
                <label class="block text-xs font-medium text-themed-muted mb-1.5">{{ t('resources.plans.billingMode') }}</label>
                <select v-model="planForm.billingMode" class="input">
                  <option value="package">{{ t('resources.plans.packageBilling') }}</option>
                  <option value="hourly">{{ t('resources.plans.hourlyBilling') }}</option>
                </select>
                <p class="mt-1 text-xs text-themed-muted">{{ t(planForm.billingMode === 'hourly' ? 'resources.plans.hourlyBillingHint' : 'resources.plans.packageBillingHint') }}</p>
              </div>
            </div>
          </section>

          <section class="card p-5">
            <h2 class="text-base font-medium text-themed">{{ t('resources.plans.resourceConfig') }}</h2>
            <div class="mt-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              <div>
                <label class="block text-xs font-medium text-themed-muted mb-1.5">CPU (%)</label>
                <input v-model.number="planForm.cpu" type="number" min="15" max="10000" step="5" class="input" />
              </div>
              <div>
                <label class="block text-xs font-medium text-themed-muted mb-1.5">{{ t('admin.packages.memory') }} (MB)</label>
                <input v-model.number="planForm.memory" type="number" min="128" max="62144" step="64" class="input" />
              </div>
              <div>
                <label class="block text-xs font-medium text-themed-muted mb-1.5">{{ t('admin.packages.disk') }} (MB)</label>
                <input v-model.number="planForm.disk" type="number" min="512" max="104857600" step="512" class="input" />
              </div>
              <div>
                <label class="block text-xs font-medium text-themed-muted mb-1.5">{{ t('resources.plans.trafficBillingMode') }}</label>
                <select v-model="planForm.trafficBillingMode" class="input">
                  <option value="package">{{ t('resources.plans.packageTraffic') }}</option>
                  <option value="usage">{{ t('resources.plans.usageTraffic') }}</option>
                </select>
              </div>
              <div>
                <label class="block text-xs font-medium text-themed-muted mb-1.5">{{ t(planForm.trafficBillingMode === 'usage' ? 'resources.plans.includedTraffic' : 'resources.plans.trafficLimit') }} (GB) *</label>
                <input v-model.number="planForm.trafficLimit" type="number" :min="planForm.trafficBillingMode === 'usage' ? 0 : 1" max="100000" step="1" class="input" />
              </div>
              <div v-if="planForm.trafficBillingMode === 'package'">
                <label class="block text-xs font-medium text-themed-muted mb-1.5">{{ t('resources.plans.trafficSpeed') }} (Mbps) *</label>
                <input v-model.number="planForm.trafficLimitSpeed" type="number" min="1" max="10000" step="1" class="input" />
              </div>
              <div v-else>
                <label class="block text-xs font-medium text-themed-muted mb-1.5">{{ t('resources.plans.trafficUnitPrice') }} ({{ t('resources.plans.priceUnit') }} / GB) *</label>
                <input v-model.number="planForm.trafficUnitPrice" type="number" min="0.0001" :max="MAX_PACKAGE_PLAN_PRICE" step="0.0001" class="input" />
                <p class="mt-1 text-xs text-themed-muted">{{ t('resources.plans.hourlySettlement') }}</p>
              </div>
            </div>
          </section>

          <section class="card p-5">
            <h2 class="text-base font-medium text-themed">{{ t('resources.plans.quota') }}</h2>
            <div class="mt-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              <div>
                <label class="block text-xs font-medium text-themed-muted mb-1.5">{{ t('resources.plans.portLimit') }}</label>
                <input v-model.number="planForm.portLimit" type="number" min="0" class="input" />
              </div>
              <div>
                <label class="block text-xs font-medium text-themed-muted mb-1.5">{{ t('resources.plans.snapshotLimit') }}</label>
                <input v-model.number="planForm.snapshotLimit" type="number" min="0" class="input" />
              </div>
              <div v-if="pkg.instance_type !== 'vm'">
                <label class="block text-xs font-medium text-themed-muted mb-1.5">{{ t('resources.plans.swapSize') }} (MB)</label>
                <input v-model.number="planForm.swapSize" type="number" min="0" max="1048576" step="128" class="input" />
              </div>
              <div>
                <label class="block text-xs font-medium text-themed-muted mb-1.5">{{ t('resources.plans.siteLimit') }}</label>
                <input v-model.number="planForm.siteLimit" type="number" min="0" class="input" />
              </div>
              <div>
                <label class="block text-xs font-medium text-themed-muted mb-1.5">{{ t('resources.plans.sortOrder') }}</label>
                <input v-model.number="planForm.sortOrder" type="number" min="0" class="input" />
              </div>
            </div>
          </section>

          <section class="card p-5">
            <h2 class="text-base font-medium text-themed">{{ t('resources.plans.billingConfig') }}</h2>
            <div class="mt-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              <div v-if="planForm.billingMode !== 'hourly'">
                <label class="block text-xs font-medium text-themed-muted mb-1.5">{{ t('resources.plans.price') }} ({{ t('resources.plans.priceUnit') }})</label>
                <input v-model.number="planForm.price" type="number" min="0" :max="MAX_PACKAGE_PLAN_PRICE" step="0.01" class="input" />
                <p class="mt-1 text-xs text-themed-muted">{{ t('resources.plans.priceRangeHint', { max: MAX_PACKAGE_PLAN_PRICE.toFixed(2) }) }}</p>
              </div>
              <div v-if="planForm.billingMode !== 'hourly'">
                <label class="block text-xs font-medium text-themed-muted mb-1.5">{{ t('resources.plans.billingCycle') }}</label>
                <select v-model.number="planForm.billingCycle" class="input">
                  <option v-for="opt in billingCycleOptions" :key="opt.value" :value="opt.value">{{ opt.label }}</option>
                </select>
              </div>
              <div v-else class="rounded-lg border px-3 py-2 text-sm text-themed-muted sm:col-span-2 lg:col-span-2">
                {{ t('resources.plans.hourlyBillingPriceHint') }}
              </div>
              <div>
                <label class="block text-xs font-medium text-themed-muted mb-1.5">{{ t('resources.plans.slaGuarantee') }} (%)</label>
                <input v-model.number="planForm.slaGuarantee" type="number" min="1" max="100" step="0.01" class="input" placeholder="99.9" />
              </div>
            </div>

            <div v-if="planForm.trafficBillingMode === 'package'" class="mt-4 rounded-lg border p-4" :class="themeStore.isDark ? 'border-gray-800 bg-gray-900/40' : 'border-gray-100 bg-gray-50'">
              <div class="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                <label class="flex min-w-0 cursor-pointer items-start gap-3">
                  <input v-model="planForm.trafficResetEnabled" type="checkbox" class="mt-0.5 h-4 w-4 flex-shrink-0 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500" />
                  <span class="min-w-0">
                    <span class="block text-sm font-medium text-themed">{{ t('resources.plans.allowTrafficReset') }}</span>
                    <span class="mt-1 block text-xs leading-5 text-themed-muted">{{ t('resources.plans.allowTrafficResetHint') }}</span>
                  </span>
                </label>
                <div v-if="planForm.trafficResetEnabled" class="w-full sm:w-56">
                  <label class="block text-xs font-medium text-themed-muted mb-1.5">{{ t('resources.plans.trafficResetPrice') }} ({{ t('resources.plans.priceUnit') }})</label>
                  <input v-model.number="planForm.trafficResetPrice" type="number" min="0" :max="MAX_PACKAGE_PLAN_PRICE" step="0.01" class="input" />
                  <p class="mt-1 text-xs text-themed-muted">{{ t('resources.plans.trafficResetPriceHint') }}</p>
                </div>
              </div>
            </div>
          </section>
        </form>

        <aside class="space-y-4">
          <section class="card p-5">
            <h2 class="text-base font-medium text-themed">{{ t('resources.plans.status') }}</h2>
            <div class="mt-4 grid gap-2">
              <button
                v-for="option in planStatusOptions"
                :key="option.value"
                type="button"
                class="rounded-lg border px-3 py-3 text-left transition-colors"
                :class="[
                  getPlanStatusSegmentClass(option.value),
                  themeStore.isDark ? 'border-gray-800' : 'border-gray-200'
                ]"
                @click="planForm.status = option.value"
              >
                <div class="text-sm font-medium">{{ option.label }}</div>
                <div class="mt-0.5 text-xs opacity-80">{{ option.description }}</div>
              </button>
            </div>
            <p class="mt-3 text-xs text-themed-muted">{{ selectedPlanStatusOption.description }}</p>
          </section>
        </aside>
      </div>
    </template>
  </div>
</template>
