<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import api from '@/api'
import SkeletonLoader from '@/components/SkeletonLoader.vue'
import PackagePlanCard from '@/components/package/PackagePlanCard.vue'
import { useToast } from '@/stores/toast'
import { useThemeStore } from '@/stores/theme'
import { translateError } from '@/utils/errorHandler'
import type { Package, PackagePlan } from '@/types/api'

type PlanStatus = 'active' | 'soldOut' | 'inactive'

const props = defineProps<{
  pkg: Package
}>()

const emit = defineEmits<{
  (e: 'changed'): void
}>()

const { t } = useI18n()
const router = useRouter()
const toast = useToast()
const themeStore = useThemeStore()

const plans = ref<PackagePlan[]>([])
const plansLoading = ref(false)
const updatingStatusId = ref<number | null>(null)
const deletingPlanId = ref<number | null>(null)

const availableCount = computed(() => plans.value.filter(plan => plan.isActive && !plan.isSoldOut).length)
const soldOutCount = computed(() => plans.value.filter(plan => plan.isActive && plan.isSoldOut).length)
const inactiveCount = computed(() => plans.value.filter(plan => !plan.isActive).length)
const minPrice = computed(() => {
  const packagePlans = plans.value.filter(plan => plan.billingMode !== 'hourly')
  const candidates = packagePlans.filter(plan => plan.isActive && !plan.isSoldOut)
  const source = candidates.length > 0 ? candidates : packagePlans
  if (source.length === 0) return null
  return Math.min(...source.map(plan => plan.price))
})

onMounted(() => {
  void loadPlans()
})

watch(() => props.pkg.id, () => {
  void loadPlans()
})

async function loadPlans(): Promise<void> {
  plansLoading.value = true
  try {
    const response = await api.packages.getPlans(props.pkg.id)
    plans.value = response.plans || []
  } catch (err) {
    console.error('加载方案列表失败:', err)
    plans.value = []
  } finally {
    plansLoading.value = false
  }
}

function formatPrice(cents: number | null): string {
  if (cents === null) return '-'
  return `¥${(cents / 100).toFixed(2)}`
}

function openCreatePlan(): void {
  router.push({ name: 'my-package-plan-create', params: { id: props.pkg.id } })
}

function openEditPlan(plan: PackagePlan): void {
  router.push({ name: 'my-package-plan-edit', params: { id: props.pkg.id, planId: plan.id } })
}

async function updatePlanStatus(plan: PackagePlan, status: PlanStatus): Promise<void> {
  if (updatingStatusId.value !== null) return

  updatingStatusId.value = plan.id
  try {
    await api.packages.updatePlan(props.pkg.id, plan.id, {
      isActive: status !== 'inactive',
      isSoldOut: status === 'soldOut'
    })
    toast.success(t('resources.plans.statusUpdateSuccess'))
    await loadPlans()
    emit('changed')
  } catch (err: any) {
    toast.error(translateError(err) || t('resources.plans.statusUpdateFailed'))
  } finally {
    updatingStatusId.value = null
  }
}

async function deletePlan(plan: PackagePlan): Promise<void> {
  if (deletingPlanId.value !== null) return
  if (!confirm(t('resources.plans.confirmDelete', { name: plan.name }))) return

  deletingPlanId.value = plan.id
  try {
    await api.packages.deletePlan(props.pkg.id, plan.id)
    toast.success(t('resources.plans.deleteSuccess'))
    await loadPlans()
    emit('changed')
  } catch (err: any) {
    toast.error(translateError(err) || t('resources.plans.deleteFailed'))
  } finally {
    deletingPlanId.value = null
  }
}
</script>

<template>
  <div class="space-y-5">
    <div class="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <h2 class="text-lg font-semibold text-themed">{{ t('resources.plans.title') }}</h2>
        <p class="mt-1 text-sm text-themed-muted">{{ t('resources.plans.listDescription') }}</p>
      </div>
      <button type="button" class="btn-primary" @click="openCreatePlan">
        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
        </svg>
        {{ t('resources.plans.add') }}
      </button>
    </div>

    <div class="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
      <div class="rounded-lg border p-4" :class="themeStore.isDark ? 'border-gray-800 bg-gray-950/40' : 'border-gray-200 bg-white'">
        <div class="text-xs text-themed-muted">{{ t('resources.plans.totalPlans') }}</div>
        <div class="mt-1 text-2xl font-semibold text-themed">{{ plans.length }}</div>
      </div>
      <div class="rounded-lg border p-4" :class="themeStore.isDark ? 'border-gray-800 bg-gray-950/40' : 'border-gray-200 bg-white'">
        <div class="text-xs text-themed-muted">{{ t('resources.plans.statusActive') }}</div>
        <div class="mt-1 text-2xl font-semibold text-emerald-600 dark:text-emerald-300">{{ availableCount }}</div>
      </div>
      <div class="rounded-lg border p-4" :class="themeStore.isDark ? 'border-gray-800 bg-gray-950/40' : 'border-gray-200 bg-white'">
        <div class="text-xs text-themed-muted">{{ t('resources.plans.statusSoldOut') }}</div>
        <div class="mt-1 text-2xl font-semibold text-amber-600 dark:text-amber-300">{{ soldOutCount }}</div>
      </div>
      <div class="rounded-lg border p-4" :class="themeStore.isDark ? 'border-gray-800 bg-gray-950/40' : 'border-gray-200 bg-white'">
        <div class="text-xs text-themed-muted">{{ t('resources.plans.statusInactive') }}</div>
        <div class="mt-1 text-2xl font-semibold text-themed">{{ inactiveCount }}</div>
      </div>
      <div class="rounded-lg border p-4" :class="themeStore.isDark ? 'border-gray-800 bg-gray-950/40' : 'border-gray-200 bg-white'">
        <div class="text-xs text-themed-muted">{{ t('resources.plans.lowestPrice') }}</div>
        <div class="mt-1 text-2xl font-semibold text-themed">{{ formatPrice(minPrice) }}</div>
      </div>
    </div>

    <SkeletonLoader v-if="plansLoading" type="list" />

    <div v-else-if="plans.length === 0" class="rounded-lg border p-12 text-center" :class="themeStore.isDark ? 'border-gray-800 bg-gray-950/40' : 'border-gray-200 bg-white'">
      <div class="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-lg" :class="themeStore.isDark ? 'bg-gray-900 text-gray-500' : 'bg-gray-100 text-gray-400'">
        <svg class="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 5h6m-6 4h6m-7 4h8M5 3h14a1 1 0 011 1v16l-4-2-4 2-4-2-4 2V4a1 1 0 011-1z" />
        </svg>
      </div>
      <p class="text-sm font-medium text-themed">{{ t('resources.plans.noPlans') }}</p>
      <p class="mt-1 text-xs text-themed-muted">{{ t('resources.plans.noPlansHint') }}</p>
      <button type="button" class="btn-primary mt-5" @click="openCreatePlan">{{ t('resources.plans.add') }}</button>
    </div>

    <div v-else class="space-y-3">
      <PackagePlanCard
        v-for="plan in plans"
        :key="plan.id"
        :plan="plan"
        :instance-type="pkg.instance_type"
        :updating-status="updatingStatusId === plan.id || deletingPlanId === plan.id"
        @edit="openEditPlan"
        @delete="deletePlan"
        @status-change="updatePlanStatus"
      />
    </div>
  </div>
</template>
