<script setup lang="ts">
defineOptions({ name: 'AdminHourlyBillingView' })

import { onMounted, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import api from '@/api'
import { useToast } from '@/stores/toast'
import { translateError } from '@/utils/errorHandler'
import type { HourlyPricing } from '@/types/api'

interface HourlyAdminInstance {
  id: number
  name: string
  status: string
  user?: { id: number; username: string }
  host?: { id: number; name: string }
  cpu: number
  memory: number
  disk: number
  account?: {
    status: string
    prepaidBalance: string
    totalCost: string
    outstandingAmount: string
  } | null
}

const { t } = useI18n()
const toast = useToast()
const loading = ref(true)
const saving = ref(false)
const reconciling = ref(false)
const error = ref('')
const versions = ref<HourlyPricing[]>([])
const instances = ref<HourlyAdminInstance[]>([])

const form = reactive({
  enabled: true,
  cpuUnitPercent: 5,
  memoryUnitMb: 64,
  diskUnitMb: 512,
  minCpu: 15,
  minMemoryMb: 128,
  minDiskMb: 512,
  cpuPricePerUnit: '0.0000',
  memoryPricePerUnit: '0.0000',
  diskPricePerUnit: '0.0000',
  reserveQuantum: '0.01',
  effectiveAt: ''
})

function formatMoney(value: string | number | null | undefined): string {
  const amount = Number(value)
  return Number.isFinite(amount) ? amount.toFixed(4) : '-'
}

function formatDate(value: string | null | undefined): string {
  if (!value) return '-'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? '-' : date.toLocaleString()
}

function fillForm(pricing: HourlyPricing | undefined): void {
  if (!pricing) return
  form.enabled = pricing.enabled
  form.cpuUnitPercent = pricing.cpuUnitPercent
  form.memoryUnitMb = pricing.memoryUnitMb
  form.diskUnitMb = pricing.diskUnitMb
  form.minCpu = pricing.minCpu
  form.minMemoryMb = pricing.minMemoryMb
  form.minDiskMb = pricing.minDiskMb
  form.cpuPricePerUnit = pricing.cpuPricePerUnit
  form.memoryPricePerUnit = pricing.memoryPricePerUnit
  form.diskPricePerUnit = pricing.diskPricePerUnit
  form.reserveQuantum = pricing.reserveQuantum
  form.effectiveAt = ''
}

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const [pricingResponse, instanceResponse] = await Promise.all([
      api.admin.getHourlyPricing(),
      api.admin.getHourlyInstances()
    ])
    versions.value = pricingResponse.versions || []
    instances.value = instanceResponse.instances as unknown as HourlyAdminInstance[]
    fillForm(versions.value[0])
  } catch (err) {
    error.value = translateError(err)
  } finally {
    loading.value = false
  }
}

async function publishPricing(): Promise<void> {
  saving.value = true
  error.value = ''
  try {
    await api.admin.createHourlyPricingVersion({
      enabled: form.enabled,
      cpuUnitPercent: form.cpuUnitPercent,
      memoryUnitMb: form.memoryUnitMb,
      diskUnitMb: form.diskUnitMb,
      minCpu: form.minCpu,
      minMemoryMb: form.minMemoryMb,
      minDiskMb: form.minDiskMb,
      cpuPricePerUnit: form.cpuPricePerUnit,
      memoryPricePerUnit: form.memoryPricePerUnit,
      diskPricePerUnit: form.diskPricePerUnit,
      reserveQuantum: form.reserveQuantum,
      effectiveAt: form.effectiveAt || undefined
    })
    toast.success(t('hourlyBilling.savePricingSuccess'))
    await load()
  } catch (err) {
    error.value = translateError(err)
    toast.error(error.value)
  } finally {
    saving.value = false
  }
}

async function reconcile(): Promise<void> {
  reconciling.value = true
  try {
    await api.admin.reconcileHourlyBilling()
    toast.success(t('hourlyBilling.reconcileSuccess'))
    await load()
  } catch (err) {
    toast.error(translateError(err))
  } finally {
    reconciling.value = false
  }
}

onMounted(load)
</script>

<template>
  <div class="space-y-6 animate-fade-in">
    <div class="page-header flex-col gap-3 sm:flex-row sm:items-start">
      <div>
        <h1 class="page-title text-lg sm:text-xl">{{ $t('hourlyBilling.adminTitle') }}</h1>
        <p class="page-description">{{ $t('hourlyBilling.adminDescription') }}</p>
      </div>
      <div class="flex w-full gap-2 sm:w-auto">
        <button type="button" class="btn-secondary flex-1 justify-center sm:flex-none" :disabled="loading || reconciling" @click="reconcile">
          {{ reconciling ? $t('common.processing') : $t('hourlyBilling.reconcile') }}
        </button>
        <button type="button" class="btn-secondary flex-1 justify-center sm:flex-none" :disabled="loading" @click="load">{{ $t('hourlyBilling.refresh') }}</button>
      </div>
    </div>

    <div v-if="loading" class="card p-8 text-center text-themed-muted">{{ $t('common.loading') }}</div>
    <template v-else>
      <div v-if="error" class="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-500">{{ error }}</div>

      <div class="grid gap-6 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <form class="card p-5 space-y-4" @submit.prevent="publishPricing">
          <div class="flex items-center justify-between gap-3">
            <h2 class="font-semibold text-themed">{{ $t('hourlyBilling.newPricing') }}</h2>
            <label class="flex items-center gap-2 text-sm text-themed-muted"><input v-model="form.enabled" type="checkbox" />{{ $t('hourlyBilling.enabled') }}</label>
          </div>
          <div class="grid gap-3 sm:grid-cols-3">
            <label><span class="label">CPU {{ $t('hourlyBilling.resourceUnit') }}</span><input v-model.number="form.cpuUnitPercent" type="number" min="1" class="input w-full" /></label>
            <label><span class="label">MB {{ $t('hourlyBilling.resourceUnit') }}</span><input v-model.number="form.memoryUnitMb" type="number" min="1" class="input w-full" /></label>
            <label><span class="label">MB {{ $t('hourlyBilling.resourceUnit') }}</span><input v-model.number="form.diskUnitMb" type="number" min="1" class="input w-full" /></label>
          </div>
          <div>
            <div class="mb-2 text-xs font-medium text-themed-muted">{{ $t('hourlyBilling.minimum') }}</div>
            <div class="grid gap-3 sm:grid-cols-3">
              <input v-model.number="form.minCpu" type="number" min="15" class="input w-full" aria-label="min CPU" />
              <input v-model.number="form.minMemoryMb" type="number" min="128" class="input w-full" aria-label="min memory" />
              <input v-model.number="form.minDiskMb" type="number" min="512" class="input w-full" aria-label="min disk" />
            </div>
          </div>
          <div>
            <div class="mb-2 text-xs font-medium text-themed-muted">{{ $t('hourlyBilling.pricePerUnit') }}</div>
            <div class="grid gap-3 sm:grid-cols-3">
              <input v-model="form.cpuPricePerUnit" type="text" inputmode="decimal" class="input w-full" aria-label="CPU price" />
              <input v-model="form.memoryPricePerUnit" type="text" inputmode="decimal" class="input w-full" aria-label="memory price" />
              <input v-model="form.diskPricePerUnit" type="text" inputmode="decimal" class="input w-full" aria-label="disk price" />
            </div>
          </div>
          <div class="grid gap-3 sm:grid-cols-2">
            <label><span class="label">{{ $t('hourlyBilling.reserveQuantum') }}</span><input v-model="form.reserveQuantum" type="text" inputmode="decimal" class="input w-full" /></label>
            <label><span class="label">{{ $t('hourlyBilling.effectiveAt') }}</span><input v-model="form.effectiveAt" type="datetime-local" class="input w-full" /></label>
          </div>
          <button type="submit" class="btn-primary w-full" :disabled="saving">{{ saving ? $t('common.saving') : $t('hourlyBilling.savePricing') }}</button>
        </form>

        <div class="card overflow-hidden">
          <div class="flex items-center justify-between border-b border-themed px-5 py-4">
            <h2 class="font-semibold text-themed">{{ $t('hourlyBilling.pricingTitle') }}</h2>
            <span class="text-xs text-themed-muted">{{ versions.length }} {{ $t('hourlyBilling.versions') }}</span>
          </div>
          <div class="overflow-x-auto">
            <table class="w-full min-w-[620px] text-xs">
              <thead class="border-b border-themed bg-themed-secondary text-themed-muted">
                <tr><th class="px-4 py-3 text-left">#</th><th class="px-4 py-3 text-left">{{ $t('hourlyBilling.effectiveAt') }}</th><th class="px-4 py-3 text-right">CPU</th><th class="px-4 py-3 text-right">MB</th><th class="px-4 py-3 text-right">{{ $t('hourlyBilling.reserveQuantum') }}</th></tr>
              </thead>
              <tbody class="divide-y divide-themed">
                <tr v-for="version in versions" :key="version.id" :class="version.enabled ? 'bg-blue-500/5' : ''">
                  <td class="px-4 py-3 text-themed">v{{ version.version }}<span v-if="version.enabled" class="ml-1 text-blue-500">●</span></td>
                  <td class="px-4 py-3 text-themed-muted">{{ formatDate(version.effectiveAt) }}</td>
                  <td class="px-4 py-3 text-right text-themed">¥{{ formatMoney(version.cpuPricePerUnit) }}</td>
                  <td class="px-4 py-3 text-right text-themed">¥{{ formatMoney(version.memoryPricePerUnit) }}</td>
                  <td class="px-4 py-3 text-right text-themed">¥{{ formatMoney(version.reserveQuantum) }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <div class="card overflow-hidden">
        <div class="border-b border-themed px-5 py-4"><h2 class="font-semibold text-themed">{{ $t('hourlyBilling.instancesTitle') }}</h2></div>
        <div v-if="instances.length === 0" class="p-8 text-center text-sm text-themed-muted">{{ $t('hourlyBilling.noInstances') }}</div>
        <div v-else class="overflow-x-auto">
          <table class="w-full min-w-[820px] text-sm">
            <thead class="border-b border-themed bg-themed-secondary text-xs text-themed-muted"><tr><th class="px-4 py-3 text-left">{{ $t('instance.name') }}</th><th class="px-4 py-3 text-left">{{ $t('hourlyBilling.user') }}</th><th class="px-4 py-3 text-left">{{ $t('instance.host') }}</th><th class="px-4 py-3 text-left">{{ $t('common.status') }}</th><th class="px-4 py-3 text-right">{{ $t('hourlyBilling.balance') }}</th><th class="px-4 py-3 text-right">{{ $t('hourlyBilling.outstanding') }}</th></tr></thead>
            <tbody class="divide-y divide-themed">
              <tr v-for="item in instances" :key="item.id">
                <td class="px-4 py-3"><RouterLink :to="`/instances/${item.id}`" class="text-blue-500 hover:underline">{{ item.name }}</RouterLink></td>
                <td class="px-4 py-3 text-themed-muted">{{ item.user?.username || '-' }}</td>
                <td class="px-4 py-3 text-themed-muted">{{ item.host?.name || '-' }}</td>
                <td class="px-4 py-3 text-themed-muted">{{ item.status }}</td>
                <td class="px-4 py-3 text-right text-themed">¥{{ formatMoney(item.account?.prepaidBalance) }}</td>
                <td class="px-4 py-3 text-right" :class="Number(item.account?.outstandingAmount || 0) > 0 ? 'text-red-500' : 'text-themed'">¥{{ formatMoney(item.account?.outstandingAmount) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </template>
  </div>
</template>
