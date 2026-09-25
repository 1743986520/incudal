<script setup lang="ts">
import { copyToClipboard } from '@/utils/clipboard'
import { formatDateTime as formatDate } from '@/utils/formatters'
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import api from '@/api'
import { useToast } from '@/stores/toast'
import { translateError } from '@/utils/errorHandler'
import SkeletonLoader from '@/components/SkeletonLoader.vue'
import type { OfficialCoupon, OfficialCouponRenewalMode, OfficialCouponScope } from '@/types/api'

const props = withDefaults(defineProps<{
  embedded?: boolean
}>(), {
  embedded: false
})

const { t } = useI18n()
const toast = useToast()

interface CouponForm {
  code: string
  name: string
  remark: string
  discountPercent: number
  scope: OfficialCouponScope
  reusable: boolean
  maxUsesPerUser: number | null
  totalUsageLimit: number | null
  enabled: boolean
  startsAt: string
  expiresAt: string
  renewalMode: OfficialCouponRenewalMode
  discountedChargeLimit: number | null
}

interface CouponUsage {
  id: number
  userId: number
  username: string | null
  userEmail: string | null
  instanceId: number | null
  instanceName: string | null
  instanceStatus: string | null
  packageName: string | null
  originalPrice: number
  discountAmount: number
  createdAt: string
}

const coupons = ref<OfficialCoupon[]>([])
const loading = ref(true)
const page = ref(1)
const pageSize = ref(20)
const total = ref(0)
const totalPages = ref(1)

const filters = ref({
  search: '',
  enabled: 'all' as 'all' | 'true' | 'false',
  scope: '' as '' | OfficialCouponScope
})

const showEditModal = ref(false)
const editingCoupon = ref<OfficialCoupon | null>(null)
const saving = ref(false)
const togglingId = ref<number | null>(null)
const deletingId = ref<number | null>(null)

const emptyForm = (): CouponForm => ({
  code: '',
  name: '',
  remark: '',
  discountPercent: 5,
  scope: 'all',
  reusable: false,
  maxUsesPerUser: null,
  totalUsageLimit: null,
  enabled: true,
  startsAt: '',
  expiresAt: '',
  renewalMode: 'purchase_only',
  discountedChargeLimit: null
})

const form = ref<CouponForm>(emptyForm())

const showUsagesModal = ref(false)
const usagesCoupon = ref<OfficialCoupon | null>(null)
const usages = ref<CouponUsage[]>([])
const usagesLoading = ref(false)
const usagesPage = ref(1)
const usagesPageSize = ref(20)
const usagesTotal = ref(0)
const usagesTotalPages = ref(1)

const pageSizeOptions = [20, 50, 100]

const discountPercentSuffix = computed(() => '%')

function formatMoney(amount: number): string {
  return `¥${Number(amount || 0).toFixed(2)}`
}

/** ISO 字符串 -> datetime-local 输入值（本地时间） */
function toDateTimeLocal(value: string | null): string {
  if (!value) return ''
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return ''
  const offset = date.getTimezoneOffset() * 60000
  return new Date(date.getTime() - offset).toISOString().slice(0, 16)
}

/** datetime-local 输入值 -> ISO 字符串 */
function fromDateTimeLocal(value: string): string | null {
  if (!value) return null
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return null
  return date.toISOString()
}

function scopeLabel(scope: OfficialCouponScope): string {
  return t(`admin.officialCoupons.scope.${scope}`)
}

function scopeClass(scope: OfficialCouponScope): string {
  if (scope === 'official_only') return 'badge-default'
  if (scope === 'hosted_only') return 'badge-warning'
  return 'badge-success'
}

function discountLabel(coupon: OfficialCoupon): string {
  const percent = (coupon.discountRate * 100)
  return `${Number(percent.toFixed(2))}${discountPercentSuffix.value} off`
}

function usageLabel(coupon: OfficialCoupon): string {
  if (coupon.totalUsageLimit === null) {
    return t('admin.officialCoupons.usageUnlimited', { used: coupon.usedCount })
  }
  return t('admin.officialCoupons.usageLimited', {
    used: coupon.usedCount,
    limit: coupon.totalUsageLimit
  })
}

function userLimitLabel(coupon: OfficialCoupon): string {
  if (!coupon.reusable) return t('admin.officialCoupons.perUserOnce')
  if (coupon.maxUsesPerUser === null) return t('admin.officialCoupons.perUserUnlimited')
  return t('admin.officialCoupons.perUserTimes', { count: coupon.maxUsesPerUser })
}

function renewalModeLabel(coupon: OfficialCoupon): string {
  const mode = coupon.renewalMode
  if (mode === 'limited') {
    const limit = coupon.discountedChargeLimit
    if (limit === null) return t('admin.officialCoupons.renewalMode.limited')
    return t('admin.officialCoupons.renewalModeLimitedTimes', { count: limit })
  }
  return t(`admin.officialCoupons.renewalMode.${mode}`)
}

function validityLabel(coupon: OfficialCoupon): string {
  if (!coupon.startsAt && !coupon.expiresAt) return t('admin.officialCoupons.alwaysValid')
  const start = coupon.startsAt ? formatDate(coupon.startsAt) : t('admin.officialCoupons.noStart')
  const end = coupon.expiresAt ? formatDate(coupon.expiresAt) : t('admin.officialCoupons.noEnd')
  return `${start} ~ ${end}`
}

async function loadCoupons() {
  loading.value = true
  try {
    const res = await api.admin.getOfficialCoupons({
      page: page.value,
      pageSize: pageSize.value,
      search: filters.value.search.trim() || undefined,
      enabled: filters.value.enabled,
      scope: filters.value.scope || undefined
    })
    coupons.value = res.items || []
    total.value = res.total
    totalPages.value = res.totalPages
  } catch (error) {
    toast.error(translateError(error))
  } finally {
    loading.value = false
  }
}

function search() {
  page.value = 1
  loadCoupons()
}

function resetFilters() {
  filters.value = { search: '', enabled: 'all', scope: '' }
  search()
}

function openCreateModal() {
  editingCoupon.value = null
  form.value = emptyForm()
  showEditModal.value = true
}

function openEditModal(coupon: OfficialCoupon) {
  editingCoupon.value = coupon
  form.value = {
    code: coupon.code,
    name: coupon.name,
    remark: coupon.remark || '',
    discountPercent: Number((coupon.discountRate * 100).toFixed(2)),
    scope: coupon.scope,
    reusable: coupon.reusable,
    maxUsesPerUser: coupon.maxUsesPerUser,
    totalUsageLimit: coupon.totalUsageLimit,
    enabled: coupon.enabled,
    startsAt: toDateTimeLocal(coupon.startsAt),
    expiresAt: toDateTimeLocal(coupon.expiresAt),
    renewalMode: coupon.renewalMode,
    discountedChargeLimit: coupon.discountedChargeLimit
  }
  showEditModal.value = true
}

/** 切换到 limited 模式时给折价月数一个默认值，方便直接修改 */
function onRenewalModeChange() {
  if (form.value.renewalMode === 'limited' && form.value.discountedChargeLimit === null) {
    form.value.discountedChargeLimit = 3
  }
}

function validateForm(): string | null {
  const current = form.value
  if (!current.name.trim()) return t('admin.officialCoupons.validation.nameRequired')
  if (!Number.isFinite(current.discountPercent) || current.discountPercent <= 0 || current.discountPercent >= 100) {
    return t('admin.officialCoupons.validation.discountInvalid')
  }
  if (current.reusable && current.maxUsesPerUser !== null) {
    if (!Number.isInteger(current.maxUsesPerUser) || current.maxUsesPerUser < 1) {
      return t('admin.officialCoupons.validation.maxUsesInvalid')
    }
  }
  if (current.totalUsageLimit !== null) {
    if (!Number.isInteger(current.totalUsageLimit) || current.totalUsageLimit < 1) {
      return t('admin.officialCoupons.validation.totalUsageInvalid')
    }
  }
  if (current.renewalMode === 'limited') {
    if (current.discountedChargeLimit === null || !Number.isInteger(current.discountedChargeLimit) || current.discountedChargeLimit < 1) {
      return t('admin.officialCoupons.validation.chargeLimitRequired')
    }
  }
  if (current.startsAt && current.expiresAt && new Date(current.startsAt) >= new Date(current.expiresAt)) {
    return t('admin.officialCoupons.validation.rangeInvalid')
  }
  return null
}

async function saveCoupon() {
  const error = validateForm()
  if (error) {
    toast.warning(error)
    return
  }

  const current = form.value
  const payload = {
    code: current.code.trim() || undefined,
    name: current.name.trim(),
    remark: current.remark.trim() || null,
    discountRate: Number((current.discountPercent / 100).toFixed(4)),
    scope: current.scope,
    reusable: current.reusable,
    maxUsesPerUser: current.reusable ? current.maxUsesPerUser : null,
    totalUsageLimit: current.totalUsageLimit,
    enabled: current.enabled,
    startsAt: fromDateTimeLocal(current.startsAt),
    expiresAt: fromDateTimeLocal(current.expiresAt),
    renewalMode: current.renewalMode,
    discountedChargeLimit: current.renewalMode === 'limited' ? current.discountedChargeLimit : null
  }

  saving.value = true
  try {
    if (editingCoupon.value) {
      await api.admin.updateOfficialCoupon(editingCoupon.value.id, payload)
      toast.success(t('admin.officialCoupons.updateSuccess'))
    } else {
      await api.admin.createOfficialCoupon(payload)
      toast.success(t('admin.officialCoupons.createSuccess'))
    }
    showEditModal.value = false
    await loadCoupons()
  } catch (err) {
    toast.error(translateError(err))
  } finally {
    saving.value = false
  }
}

async function toggleEnabled(coupon: OfficialCoupon) {
  togglingId.value = coupon.id
  try {
    await api.admin.updateOfficialCoupon(coupon.id, { enabled: !coupon.enabled })
    toast.success(coupon.enabled ? t('admin.officialCoupons.disabled') : t('admin.officialCoupons.enabled'))
    await loadCoupons()
  } catch (error) {
    toast.error(translateError(error))
  } finally {
    togglingId.value = null
  }
}

async function deleteCoupon(coupon: OfficialCoupon) {
  if (!window.confirm(t('admin.officialCoupons.deleteConfirm', { code: coupon.code }))) return

  deletingId.value = coupon.id
  try {
    await api.admin.deleteOfficialCoupon(coupon.id)
    toast.success(t('admin.officialCoupons.deleteSuccess'))
    await loadCoupons()
  } catch (error) {
    toast.error(translateError(error))
  } finally {
    deletingId.value = null
  }
}

async function loadUsages(id: number, targetPage = 1) {
  usagesLoading.value = true
  try {
    const res = await api.admin.getOfficialCouponUsages(id, {
      page: targetPage,
      pageSize: usagesPageSize.value
    })
    usages.value = res.items || []
    usagesTotal.value = res.total
    usagesPage.value = res.page
    usagesTotalPages.value = res.totalPages
    usagesCoupon.value = res.coupon
  } catch (error) {
    toast.error(translateError(error))
  } finally {
    usagesLoading.value = false
  }
}

function openUsagesModal(coupon: OfficialCoupon) {
  usagesCoupon.value = coupon
  usages.value = []
  usagesPage.value = 1
  usagesTotal.value = 0
  usagesTotalPages.value = 1
  showUsagesModal.value = true
  loadUsages(coupon.id, 1)
}

function changeUsagesPageSize(event: Event) {
  usagesPageSize.value = Number((event.target as HTMLSelectElement).value)
  if (usagesCoupon.value) loadUsages(usagesCoupon.value.id, 1)
}

function changeUsagesPage(targetPage: number) {
  if (!usagesCoupon.value) return
  if (targetPage < 1 || targetPage > usagesTotalPages.value) return
  loadUsages(usagesCoupon.value.id, targetPage)
}

async function copyText(text: string) {
  if (await copyToClipboard(text)) {
    toast.success(t('common.copied'))
  }
}

onMounted(() => {
  loadCoupons()
})
</script>

<template>
  <div :class="['animate-fade-in', props.embedded ? 'space-y-4' : '']">
    <div class="page-header flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
      <div>
        <h1 class="page-title">{{ $t('admin.officialCoupons.title') }}</h1>
        <p class="text-sm text-themed-muted mt-1">{{ $t('admin.officialCoupons.description') }}</p>
      </div>
      <button class="btn btn-primary" @click="openCreateModal">
        {{ $t('admin.officialCoupons.create') }}
      </button>
    </div>

    <div class="card p-4 md:p-5">
      <div class="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <input
          v-model="filters.search"
          class="input w-full sm:col-span-2"
          :placeholder="$t('admin.officialCoupons.searchPlaceholder')"
          @keyup.enter="search"
        />
        <select v-model="filters.enabled" class="input w-full" @change="search">
          <option value="all">{{ $t('admin.officialCoupons.allStatus') }}</option>
          <option value="true">{{ $t('admin.officialCoupons.statusEnabled') }}</option>
          <option value="false">{{ $t('admin.officialCoupons.statusDisabled') }}</option>
        </select>
        <select v-model="filters.scope" class="input w-full" @change="search">
          <option value="">{{ $t('admin.officialCoupons.allScopes') }}</option>
          <option value="all">{{ $t('admin.officialCoupons.scope.all') }}</option>
          <option value="official_only">{{ $t('admin.officialCoupons.scope.official_only') }}</option>
          <option value="hosted_only">{{ $t('admin.officialCoupons.scope.hosted_only') }}</option>
        </select>
      </div>
      <div class="mt-4 flex flex-wrap items-center justify-between gap-3">
        <div class="text-sm text-themed-muted">{{ $t('admin.billing.totalCount', { count: total }) }}</div>
        <div class="flex gap-2">
          <button class="btn btn-ghost btn-sm" @click="resetFilters">{{ $t('common.reset') }}</button>
          <button class="btn btn-primary btn-sm" @click="search">{{ $t('common.search') }}</button>
        </div>
      </div>
    </div>

    <SkeletonLoader v-if="loading" :count="5" />

    <div v-else-if="coupons.length > 0" class="card overflow-hidden">
      <div class="overflow-x-auto">
        <table class="w-full min-w-[1250px] text-sm">
          <thead class="bg-themed-secondary/80">
            <tr>
              <th class="p-3 text-left whitespace-nowrap">{{ $t('admin.officialCoupons.code') }}</th>
              <th class="p-3 text-left whitespace-nowrap">{{ $t('admin.officialCoupons.name') }}</th>
              <th class="p-3 text-left whitespace-nowrap">{{ $t('admin.officialCoupons.discount') }}</th>
              <th class="p-3 text-left whitespace-nowrap">{{ $t('admin.officialCoupons.scopeLabel') }}</th>
              <th class="p-3 text-left whitespace-nowrap">{{ $t('admin.officialCoupons.usage') }}</th>
              <th class="p-3 text-left whitespace-nowrap">{{ $t('admin.officialCoupons.perUser') }}</th>
              <th class="p-3 text-left whitespace-nowrap">{{ $t('admin.officialCoupons.renewalLabel') }}</th>
              <th class="p-3 text-left whitespace-nowrap">{{ $t('admin.officialCoupons.validity') }}</th>
              <th class="p-3 text-left whitespace-nowrap">{{ $t('admin.officialCoupons.statusLabel') }}</th>
              <th class="p-3 text-left whitespace-nowrap">{{ $t('common.actions') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="coupon in coupons" :key="coupon.id" class="border-t border-themed hover:bg-themed-secondary/40">
              <td class="p-3 font-mono text-xs whitespace-nowrap">
                <button class="hover:text-blue-500" @click="copyText(coupon.code)">{{ coupon.code }}</button>
              </td>
              <td class="p-3 whitespace-nowrap">
                <div class="font-medium text-themed">{{ coupon.name }}</div>
                <div v-if="coupon.remark" class="mt-0.5 max-w-[220px] truncate text-xs text-themed-muted" :title="coupon.remark">
                  {{ coupon.remark }}
                </div>
              </td>
              <td class="p-3 whitespace-nowrap font-medium text-green-600 dark:text-green-400">{{ discountLabel(coupon) }}</td>
              <td class="p-3 whitespace-nowrap">
                <span :class="['badge', scopeClass(coupon.scope)]">{{ scopeLabel(coupon.scope) }}</span>
              </td>
              <td class="p-3 whitespace-nowrap text-themed-muted">{{ usageLabel(coupon) }}</td>
              <td class="p-3 whitespace-nowrap text-themed-muted">{{ userLimitLabel(coupon) }}</td>
              <td class="p-3 whitespace-nowrap text-themed-muted">{{ renewalModeLabel(coupon) }}</td>
              <td class="p-3 whitespace-nowrap text-xs text-themed-muted">{{ validityLabel(coupon) }}</td>
              <td class="p-3 whitespace-nowrap">
                <span :class="['badge', coupon.enabled ? 'badge-success' : 'badge-default']">
                  {{ coupon.enabled ? $t('admin.officialCoupons.statusEnabled') : $t('admin.officialCoupons.statusDisabled') }}
                </span>
              </td>
              <td class="p-3 whitespace-nowrap">
                <div class="flex flex-wrap gap-1">
                  <button class="btn btn-sm btn-ghost" @click="openUsagesModal(coupon)">
                    {{ $t('admin.officialCoupons.usages') }}
                  </button>
                  <button class="btn btn-sm btn-ghost" @click="openEditModal(coupon)">
                    {{ $t('common.edit') }}
                  </button>
                  <button
                    class="btn btn-sm btn-ghost"
                    :disabled="togglingId === coupon.id"
                    @click="toggleEnabled(coupon)"
                  >
                    {{ coupon.enabled ? $t('admin.officialCoupons.disable') : $t('admin.officialCoupons.enable') }}
                  </button>
                  <button
                    class="btn btn-sm btn-ghost text-red-500"
                    :disabled="deletingId === coupon.id || coupon.usedCount > 0"
                    :title="coupon.usedCount > 0 ? $t('admin.officialCoupons.deleteUsedHint') : undefined"
                    @click="deleteCoupon(coupon)"
                  >
                    {{ deletingId === coupon.id ? $t('common.deleting') : $t('common.delete') }}
                  </button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <div v-else class="card p-10 text-center">
      <div class="text-base font-medium text-themed">{{ $t('admin.officialCoupons.empty') }}</div>
      <div class="mt-1 text-sm text-themed-muted">{{ $t('admin.officialCoupons.description') }}</div>
      <button class="btn btn-primary mt-4" @click="openCreateModal">{{ $t('admin.officialCoupons.create') }}</button>
    </div>

    <div v-if="coupons.length > 0" class="card mt-4 flex flex-col gap-4 p-4 sm:flex-row sm:items-center sm:justify-between">
      <div class="flex items-center gap-2 text-sm text-themed-muted">
        <span>{{ $t('admin.billing.perPage') }}</span>
        <select
          :value="pageSize"
          class="input w-20 py-1"
          @change="pageSize = Number(($event.target as HTMLSelectElement).value); page = 1; loadCoupons()"
        >
          <option v-for="size in pageSizeOptions" :key="size" :value="size">{{ size }}</option>
        </select>
        <span>{{ $t('admin.billing.totalCount', { count: total }) }}</span>
      </div>
      <div v-if="totalPages > 1" class="flex items-center gap-2">
        <button class="btn btn-sm btn-ghost" :disabled="page <= 1" @click="page--; loadCoupons()">{{ $t('common.prevPage') }}</button>
        <span class="text-sm text-themed-muted">{{ page }} / {{ totalPages }}</span>
        <button class="btn btn-sm btn-ghost" :disabled="page >= totalPages" @click="page++; loadCoupons()">{{ $t('common.nextPage') }}</button>
      </div>
    </div>

    <Teleport to="body">
      <div v-if="showEditModal" class="modal-overlay" @click.self="showEditModal = false">
        <div class="modal-content coupon-edit-modal flex flex-col">
          <div class="modal-header flex-shrink-0">
            <h3 class="modal-title">
              {{ editingCoupon ? $t('admin.officialCoupons.editTitle') : $t('admin.officialCoupons.createTitle') }}
            </h3>
            <button class="btn btn-ghost btn-sm" @click="showEditModal = false">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
          <div class="modal-body min-h-0 flex-1 overflow-y-auto">
            <div class="grid gap-4 sm:grid-cols-2">
              <div>
                <label class="label">{{ $t('admin.officialCoupons.code') }}</label>
                <input v-model="form.code" type="text" maxlength="32" class="input w-full font-mono" :placeholder="$t('admin.officialCoupons.codePlaceholder')" />
              </div>
              <div>
                <label class="label">{{ $t('admin.officialCoupons.name') }}</label>
                <input v-model="form.name" type="text" maxlength="64" class="input w-full" :placeholder="$t('admin.officialCoupons.namePlaceholder')" />
              </div>
              <div>
                <label class="label">{{ $t('admin.officialCoupons.discountPercent') }}</label>
                <input v-model.number="form.discountPercent" type="number" min="0.01" max="99.99" step="0.01" class="input w-full" />
                <p class="mt-1 text-xs text-themed-muted">{{ $t('admin.officialCoupons.discountHint') }}</p>
              </div>
              <div>
                <label class="label">{{ $t('admin.officialCoupons.scopeLabel') }}</label>
                <select v-model="form.scope" class="input w-full">
                  <option value="all">{{ $t('admin.officialCoupons.scope.all') }}</option>
                  <option value="official_only">{{ $t('admin.officialCoupons.scope.official_only') }}</option>
                  <option value="hosted_only">{{ $t('admin.officialCoupons.scope.hosted_only') }}</option>
                </select>
              </div>
              <div>
                <label class="label">{{ $t('admin.officialCoupons.renewalLabel') }}</label>
                <select v-model="form.renewalMode" class="input w-full" @change="onRenewalModeChange">
                  <option value="purchase_only">{{ $t('admin.officialCoupons.renewalMode.purchase_only') }}</option>
                  <option value="limited">{{ $t('admin.officialCoupons.renewalMode.limited') }}</option>
                  <option value="recurring">{{ $t('admin.officialCoupons.renewalMode.recurring') }}</option>
                </select>
              </div>
              <div v-if="form.renewalMode === 'limited'">
                <label class="label">{{ $t('admin.officialCoupons.discountedChargeLimit') }}</label>
                <input v-model.number="form.discountedChargeLimit" type="number" min="1" step="1" class="input w-full" />
                <p class="mt-1 text-xs text-themed-muted">{{ $t('admin.officialCoupons.discountedChargeLimitHint') }}</p>
              </div>
              <div v-else class="hidden sm:block"></div>
              <div class="sm:col-span-2">
                <label class="label">{{ $t('admin.officialCoupons.remark') }}</label>
                <textarea v-model="form.remark" rows="2" maxlength="500" class="input w-full resize-y" :placeholder="$t('admin.officialCoupons.remarkPlaceholder')"></textarea>
              </div>
              <div>
                <label class="label">{{ $t('admin.officialCoupons.startsAt') }}</label>
                <input v-model="form.startsAt" type="datetime-local" class="input w-full" />
                <p class="mt-1 text-xs text-themed-muted">{{ $t('admin.officialCoupons.startsAtHint') }}</p>
              </div>
              <div>
                <label class="label">{{ $t('admin.officialCoupons.expiresAt') }}</label>
                <input v-model="form.expiresAt" type="datetime-local" class="input w-full" />
                <p class="mt-1 text-xs text-themed-muted">{{ $t('admin.officialCoupons.expiresAtHint') }}</p>
              </div>
              <div>
                <label class="label">{{ $t('admin.officialCoupons.totalUsageLimit') }}</label>
                <input v-model.number="form.totalUsageLimit" type="number" min="1" step="1" class="input w-full" :placeholder="$t('admin.officialCoupons.unlimitedPlaceholder')" />
                <p class="mt-1 text-xs text-themed-muted">{{ $t('admin.officialCoupons.totalUsageHint') }}</p>
              </div>
              <div class="space-y-3">
                <label class="flex items-center gap-2 text-sm text-themed">
                  <input v-model="form.reusable" type="checkbox" class="checkbox" />
                  <span>{{ $t('admin.officialCoupons.reusable') }}</span>
                </label>
                <div v-if="form.reusable">
                  <label class="label">{{ $t('admin.officialCoupons.maxUsesPerUser') }}</label>
                  <input v-model.number="form.maxUsesPerUser" type="number" min="1" step="1" class="input w-full" :placeholder="$t('admin.officialCoupons.unlimitedPlaceholder')" />
                  <p class="mt-1 text-xs text-themed-muted">{{ $t('admin.officialCoupons.maxUsesPerUserHint') }}</p>
                </div>
                <p v-else class="text-xs text-themed-muted">{{ $t('admin.officialCoupons.reusableHint') }}</p>
              </div>
              <div class="sm:col-span-2">
                <label class="flex items-center gap-2 text-sm text-themed">
                  <input v-model="form.enabled" type="checkbox" class="checkbox" />
                  <span>{{ $t('admin.officialCoupons.enabledLabel') }}</span>
                </label>
              </div>
              <div v-if="editingCoupon" class="sm:col-span-2 rounded-lg border border-themed p-3 text-sm">
                <div class="flex flex-wrap items-center justify-between gap-2">
                  <span class="text-themed-muted">{{ $t('admin.officialCoupons.usage') }}</span>
                  <span class="font-medium text-themed">{{ usageLabel(editingCoupon) }}</span>
                </div>
                <p class="mt-2 text-xs text-themed-muted">{{ $t('admin.officialCoupons.editUsageNotice') }}</p>
              </div>
            </div>
          </div>
          <div class="modal-footer flex-shrink-0">
            <button class="btn btn-ghost" @click="showEditModal = false">{{ $t('common.cancel') }}</button>
            <button class="btn btn-primary" :disabled="saving" @click="saveCoupon">
              {{ saving ? $t('common.saving') : $t('common.save') }}
            </button>
          </div>
        </div>
      </div>
    </Teleport>

    <Teleport to="body">
      <div v-if="showUsagesModal" class="modal-overlay" @click.self="showUsagesModal = false">
        <div class="modal-content coupon-usages-modal flex flex-col">
          <div class="modal-header flex-shrink-0">
            <div class="min-w-0">
              <h3 class="modal-title">{{ $t('admin.officialCoupons.usagesTitle') }}</h3>
              <p v-if="usagesCoupon" class="mt-1 truncate font-mono text-xs text-themed-muted">
                {{ usagesCoupon.code }} · {{ usagesCoupon.name }}
              </p>
            </div>
            <button class="btn btn-ghost btn-sm" @click="showUsagesModal = false">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
          <div class="modal-body min-h-0 flex-1 overflow-hidden">
            <div v-if="usagesLoading" class="py-6">
              <SkeletonLoader :count="4" />
            </div>
            <div v-else-if="usages.length > 0" class="flex h-full min-h-0 flex-col">
              <div class="min-h-0 flex-1 overflow-auto rounded-lg border border-themed">
                <table class="w-full min-w-[880px] text-sm">
                  <thead class="sticky top-0 bg-themed-secondary/90">
                    <tr>
                      <th class="p-3 text-left whitespace-nowrap">{{ $t('admin.officialCoupons.usageUser') }}</th>
                      <th class="p-3 text-left whitespace-nowrap">{{ $t('admin.officialCoupons.usageInstance') }}</th>
                      <th class="p-3 text-left whitespace-nowrap">{{ $t('admin.officialCoupons.usageOriginalPrice') }}</th>
                      <th class="p-3 text-left whitespace-nowrap">{{ $t('admin.officialCoupons.usageDiscount') }}</th>
                      <th class="p-3 text-left whitespace-nowrap">{{ $t('admin.officialCoupons.usageTime') }}</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="usage in usages" :key="usage.id" class="border-t border-themed">
                      <td class="p-3 whitespace-nowrap">
                        <div class="text-themed">{{ usage.username || `#${usage.userId}` }}</div>
                        <div v-if="usage.userEmail" class="mt-0.5 text-xs text-themed-muted">{{ usage.userEmail }}</div>
                      </td>
                      <td class="p-3 whitespace-nowrap">
                        <template v-if="usage.instanceId">
                          <div class="text-themed">{{ usage.instanceName || `#${usage.instanceId}` }}</div>
                          <div v-if="usage.packageName" class="mt-0.5 text-xs text-themed-muted">{{ usage.packageName }}</div>
                        </template>
                        <span v-else class="text-themed-muted">-</span>
                      </td>
                      <td class="p-3 whitespace-nowrap">{{ formatMoney(usage.originalPrice) }}</td>
                      <td class="p-3 whitespace-nowrap font-medium text-green-600 dark:text-green-400">-{{ formatMoney(usage.discountAmount) }}</td>
                      <td class="p-3 whitespace-nowrap text-themed-muted">{{ formatDate(usage.createdAt) }}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
              <div class="mt-3 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div class="flex items-center gap-2 text-sm text-themed-muted">
                  <span>{{ $t('admin.billing.perPage') }}</span>
                  <select :value="usagesPageSize" class="input w-20 py-1" @change="changeUsagesPageSize">
                    <option v-for="size in pageSizeOptions" :key="size" :value="size">{{ size }}</option>
                  </select>
                  <span>{{ $t('admin.billing.totalCount', { count: usagesTotal }) }}</span>
                </div>
                <div v-if="usagesTotalPages > 1" class="flex items-center gap-2">
                  <button class="btn btn-sm btn-ghost" :disabled="usagesPage <= 1" @click="changeUsagesPage(usagesPage - 1)">{{ $t('common.prevPage') }}</button>
                  <span class="text-sm text-themed-muted">{{ usagesPage }} / {{ usagesTotalPages }}</span>
                  <button class="btn btn-sm btn-ghost" :disabled="usagesPage >= usagesTotalPages" @click="changeUsagesPage(usagesPage + 1)">{{ $t('common.nextPage') }}</button>
                </div>
              </div>
            </div>
            <div v-else class="py-10 text-center text-sm text-themed-muted">
              {{ $t('admin.officialCoupons.usagesEmpty') }}
            </div>
          </div>
          <div class="modal-footer flex-shrink-0">
            <button class="btn btn-ghost" @click="showUsagesModal = false">{{ $t('common.close') }}</button>
          </div>
        </div>
      </div>
    </Teleport>
  </div>
</template>

<style scoped>
.coupon-edit-modal {
  width: min(94vw, 760px);
  max-width: none;
  max-height: 90vh;
  overflow: hidden;
}

.coupon-usages-modal {
  width: min(94vw, 1000px);
  max-width: none;
  max-height: 88vh;
  overflow: hidden;
}
</style>
