<script setup lang="ts">
defineOptions({ name: 'HourlyInstanceCreateView' })

import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import api from '@/api'
import { useToast } from '@/stores/toast'
import { useThemeStore } from '@/stores/theme'
import { useInstanceResourcesStore } from '@/stores/instanceResources'
import { storeToRefs } from 'pinia'
import ImageSelector from '@/components/instance/ImageSelector.vue'
import SSHKeySelector from '@/components/instance/SSHKeySelector.vue'
import type { HourlyPricing, HourlyQuote, SystemImage } from '@/types/api'
import { translateError } from '@/utils/errorHandler'

interface HourlyHost {
  id: number
  name: string
  location: string | null
  countryCode: string
  architecture: string
  instanceType: string
  cpuAllowanceMax?: number
  memoryMax?: number
  storageSize?: number
  isAvailable?: boolean
}

interface ImageOption {
  value: string
  label: string
  icon: string | null
}

const { t } = useI18n()
const router = useRouter()
const toast = useToast()
const themeStore = useThemeStore()
const resourcesStore = useInstanceResourcesStore()
const { sshKeys } = storeToRefs(resourcesStore)

const loading = ref(true)
const submitting = ref(false)
const error = ref('')
const quoteLoading = ref(false)
const hostsLoading = ref(false)
const imagesLoading = ref(false)
const pricing = ref<HourlyPricing | null>(null)
const quote = ref<HourlyQuote | null>(null)
const hosts = ref<HourlyHost[]>([])
const availableImages = ref<ImageOption[]>([])
const refreshTimer = ref<ReturnType<typeof setTimeout> | null>(null)

const form = ref({
  name: '',
  instanceType: 'container' as 'container' | 'vm',
  hostId: null as number | null,
  image: '',
  cpu: 15,
  memory: 512,
  disk: 512,
  sshKeyId: null as number | null
})

const selectedHost = computed(() => hosts.value.find(host => host.id === form.value.hostId) || null)
const selectableHosts = computed(() => hosts.value.filter(host => supportsInstanceType(host, form.value.instanceType)))
const canSubmit = computed(() => Boolean(
  form.value.name.trim().length >= 2
  && form.value.hostId
  && form.value.image
  && form.value.sshKeyId
  && quote.value
  && !quoteLoading.value
  && !hostsLoading.value
  && !imagesLoading.value
))

function supportsInstanceType(host: HourlyHost, instanceType: 'container' | 'vm'): boolean {
  return host.instanceType === instanceType || host.instanceType === 'both'
}

function hostLabel(host: HourlyHost): string {
  const location = host.location ? ` · ${host.location}` : ''
  return `${host.name}${location}`
}

function formatPrice(value: string | number | null | undefined): string {
  const amount = Number(value)
  return Number.isFinite(amount) ? amount.toFixed(4) : '-'
}

function formatDate(value: string | null | undefined): string {
  if (!value) return '-'
  return new Date(value).toLocaleString()
}

function mapImages(images: SystemImage[]): ImageOption[] {
  return images.map(image => ({
    value: image.remoteAlias,
    label: image.name,
    icon: image.icon || image.name
  }))
}

async function loadQuote(): Promise<void> {
  if (!pricing.value) return
  quoteLoading.value = true
  try {
    const response = await api.instances.hourlyQuote({
      cpu: form.value.cpu,
      memory: form.value.memory,
      disk: form.value.disk
    })
    quote.value = response.breakdown
    pricing.value = response.pricing
  } catch (err) {
    quote.value = null
    error.value = translateError(err)
  } finally {
    quoteLoading.value = false
  }
}

async function loadHosts(): Promise<void> {
  if (!pricing.value) return
  hostsLoading.value = true
  try {
    const response = await api.instances.hourlyAvailableHosts({
      cpu: form.value.cpu,
      memory: form.value.memory,
      disk: form.value.disk
    })
    hosts.value = response.hosts as unknown as HourlyHost[]
    const compatibleHosts = selectableHosts.value
    const currentHost = compatibleHosts.find(host => host.id === form.value.hostId)
    if (!currentHost || currentHost.isAvailable === false) {
      form.value.hostId = compatibleHosts.find(host => host.isAvailable !== false)?.id || null
    }
  } catch (err) {
    hosts.value = []
    form.value.hostId = null
    error.value = translateError(err)
  } finally {
    hostsLoading.value = false
  }
}

async function loadImages(): Promise<void> {
  if (!form.value.hostId) {
    availableImages.value = []
    form.value.image = ''
    return
  }
  imagesLoading.value = true
  try {
    const response = await api.images.getSystemImages(
      form.value.instanceType,
      form.value.memory,
      form.value.hostId
    )
    availableImages.value = mapImages(response.images || [])
    if (!availableImages.value.some(image => image.value === form.value.image)) {
      form.value.image = availableImages.value[0]?.value || ''
    }
  } catch (err) {
    availableImages.value = []
    form.value.image = ''
    error.value = translateError(err)
  } finally {
    imagesLoading.value = false
  }
}

function scheduleResourceRefresh(): void {
  if (refreshTimer.value) clearTimeout(refreshTimer.value)
  refreshTimer.value = setTimeout(async () => {
    await Promise.all([loadQuote(), loadHosts()])
    await loadImages()
  }, 250)
}

async function submit(): Promise<void> {
  if (!canSubmit.value || !form.value.hostId || !form.value.sshKeyId) return
  submitting.value = true
  error.value = ''
  try {
    const result = await api.instances.createHourly({
      name: form.value.name.trim(),
      hostId: form.value.hostId,
      image: form.value.image,
      cpu: form.value.cpu,
      memory: form.value.memory,
      disk: form.value.disk,
      instanceType: form.value.instanceType,
      sshKeyId: form.value.sshKeyId
    })
    toast.success(t('hourlyBilling.createSuccess'))
    await router.push(`/instances/${result.instanceId}`)
  } catch (err) {
    error.value = translateError(err)
    toast.error(error.value)
  } finally {
    submitting.value = false
  }
}

watch(
  () => [form.value.cpu, form.value.memory, form.value.disk],
  scheduleResourceRefresh
)

watch(
  () => [form.value.instanceType, form.value.hostId, form.value.memory],
  () => { void loadImages() }
)

watch(
  () => form.value.instanceType,
  () => {
    form.value.hostId = null
    form.value.image = ''
    void loadHosts()
  }
)

onMounted(async () => {
  try {
    const [catalog] = await Promise.all([
      api.instances.hourlyCatalog(),
      resourcesStore.loadSshKeys()
    ])
    pricing.value = catalog.pricing
    if (!catalog.enabled || !catalog.pricing) {
      error.value = t('hourlyBilling.disabled')
      return
    }
    form.value.cpu = catalog.pricing.minCpu
    form.value.memory = catalog.pricing.minMemoryMb
    form.value.disk = catalog.pricing.minDiskMb
    const firstSupported = catalog.hosts.find(host => supportsInstanceType(host as HourlyHost, form.value.instanceType))
    if (!firstSupported) form.value.instanceType = 'vm'
    if (sshKeys.value.length > 0) form.value.sshKeyId = sshKeys.value[0].id
    await Promise.all([loadQuote(), loadHosts()])
    await loadImages()
  } catch (err) {
    error.value = translateError(err)
  } finally {
    loading.value = false
  }
})

onUnmounted(() => {
  if (refreshTimer.value) clearTimeout(refreshTimer.value)
})
</script>

<template>
  <div class="max-w-6xl mx-auto space-y-6 animate-fade-in">
    <div class="page-header flex-col gap-4 sm:flex-row sm:items-start">
      <div>
        <div class="flex items-center gap-2 mb-1">
          <RouterLink to="/instances" class="btn-ghost btn-sm">← {{ $t('common.back') }}</RouterLink>
        </div>
        <h1 class="page-title text-lg sm:text-xl">{{ $t('hourlyBilling.createTitle') }}</h1>
        <p class="page-description">{{ $t('hourlyBilling.createDescription') }}</p>
      </div>
      <RouterLink to="/instances/create" class="btn-secondary w-full sm:w-auto justify-center">
        {{ $t('hourlyBilling.switchToPackage') }}
      </RouterLink>
    </div>

    <div v-if="loading" class="card p-8 text-center text-themed-muted">{{ $t('common.loading') }}</div>
    <div v-else-if="error && !pricing" class="card p-5 text-sm text-red-500">{{ error }}</div>

    <form v-else class="grid gap-6 lg:grid-cols-[minmax(0,1fr)_340px]" @submit.prevent="submit">
      <div class="space-y-4">
        <div class="card p-5 space-y-4">
          <div class="flex items-center justify-between gap-3">
            <div>
              <h2 class="font-semibold text-themed">{{ $t('hourlyBilling.resourceTitle') }}</h2>
              <p class="text-xs text-themed-muted mt-1">{{ $t('hourlyBilling.resourceHint') }}</p>
            </div>
            <span class="rounded-full px-2.5 py-1 text-xs font-medium bg-blue-500/10 text-blue-500">{{ $t('hourlyBilling.badge') }}</span>
          </div>

          <div class="grid gap-4 sm:grid-cols-2">
            <div>
              <label class="label">{{ $t('hourlyBilling.instanceName') }}</label>
              <input v-model="form.name" class="input w-full" :placeholder="$t('hourlyBilling.instanceNamePlaceholder')" required />
            </div>
            <div>
              <label class="label">{{ $t('hourlyBilling.instanceType') }}</label>
              <select v-model="form.instanceType" class="input w-full">
                <option value="container">{{ $t('common.instanceType.container') }}</option>
                <option value="vm">{{ $t('common.instanceType.vm') }}</option>
              </select>
            </div>
          </div>

          <div class="grid gap-4 sm:grid-cols-3">
            <label class="block">
              <span class="label">{{ $t('hourlyBilling.cpu') }}</span>
              <div class="relative"><input v-model.number="form.cpu" type="number" min="1" step="1" class="input w-full pr-12" /><span class="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-themed-muted">%</span></div>
            </label>
            <label class="block">
              <span class="label">{{ $t('hourlyBilling.memory') }}</span>
              <div class="relative"><input v-model.number="form.memory" type="number" min="1" step="1" class="input w-full pr-14" /><span class="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-themed-muted">MB</span></div>
            </label>
            <label class="block">
              <span class="label">{{ $t('hourlyBilling.disk') }}</span>
              <div class="relative"><input v-model.number="form.disk" type="number" min="1" step="1" class="input w-full pr-14" /><span class="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-themed-muted">MB</span></div>
            </label>
          </div>
          <p v-if="pricing" class="text-xs text-themed-muted">
            {{ $t('hourlyBilling.minimumResource', { cpu: pricing.minCpu, memory: pricing.minMemoryMb, disk: pricing.minDiskMb }) }}
          </p>
        </div>

        <div class="card p-5 space-y-4">
          <div class="flex items-center justify-between gap-3">
            <h2 class="font-semibold text-themed">{{ $t('hourlyBilling.hostTitle') }}</h2>
            <span v-if="hostsLoading" class="text-xs text-themed-muted">{{ $t('common.loading') }}</span>
          </div>
          <select v-model.number="form.hostId" class="input w-full" :disabled="hostsLoading">
            <option :value="null">{{ $t('hourlyBilling.selectHost') }}</option>
            <option v-for="host in selectableHosts" :key="host.id" :value="host.id" :disabled="host.isAvailable === false">
              {{ hostLabel(host) }}{{ host.isAvailable === false ? ` · ${$t('hourlyBilling.hostUnavailable')}` : '' }}
            </option>
          </select>
          <p v-if="selectableHosts.length === 0 && !hostsLoading" class="text-sm text-amber-500">{{ $t('hourlyBilling.noHosts') }}</p>
          <p v-else-if="selectedHost" class="text-xs text-themed-muted">{{ selectedHost.architecture }} · {{ $t(`common.instanceType.${form.instanceType}`) }}</p>
        </div>

        <ImageSelector
          :available-images="availableImages"
          :selected-image="form.image"
          :images-loading="imagesLoading"
          :step-number="3"
          :title="$t('hourlyBilling.imageTitle')"
          :empty-message="$t('hourlyBilling.noImages')"
          @update:selected-image="form.image = $event"
        />
        <SSHKeySelector
          :ssh-keys="sshKeys"
          :selected-key-id="form.sshKeyId"
          :step-number="4"
          :title="$t('hourlyBilling.sshKeyTitle')"
          @update:selected-key-id="form.sshKeyId = $event"
        />
      </div>

      <aside class="space-y-4 lg:sticky lg:top-4 lg:self-start">
        <div class="card p-5">
          <h2 class="font-semibold text-themed">{{ $t('hourlyBilling.quoteTitle') }}</h2>
          <div v-if="quoteLoading" class="py-8 text-center text-sm text-themed-muted">{{ $t('common.loading') }}</div>
          <div v-else-if="quote" class="mt-4 space-y-3">
            <div class="rounded-xl p-4" :class="themeStore.isDark ? 'bg-blue-900/20' : 'bg-blue-50'">
              <div class="text-xs text-themed-muted">{{ $t('hourlyBilling.hourlyPrice') }}</div>
              <div class="mt-1 text-3xl font-bold text-themed">¥{{ formatPrice(quote.hourlyPrice) }}<span class="text-sm font-normal text-themed-muted"> / {{ $t('hourlyBilling.hour') }}</span></div>
            </div>
            <div class="flex justify-between text-sm"><span class="text-themed-muted">{{ $t('hourlyBilling.cpuCost') }}</span><span class="text-themed">¥{{ formatPrice(quote.cpuAmount) }}</span></div>
            <div class="flex justify-between text-sm"><span class="text-themed-muted">{{ $t('hourlyBilling.memoryCost') }}</span><span class="text-themed">¥{{ formatPrice(quote.memoryAmount) }}</span></div>
            <div class="flex justify-between text-sm"><span class="text-themed-muted">{{ $t('hourlyBilling.diskCost') }}</span><span class="text-themed">¥{{ formatPrice(quote.diskAmount) }}</span></div>
            <p v-if="pricing" class="border-t border-themed pt-3 text-xs text-themed-muted">{{ $t('hourlyBilling.reserveHint', { amount: formatPrice(pricing.reserveQuantum), effectiveAt: formatDate(pricing.effectiveAt) }) }}</p>
          </div>
          <p v-else class="mt-4 text-sm text-themed-muted">{{ $t('hourlyBilling.quoteUnavailable') }}</p>
        </div>

        <div v-if="sshKeys.length === 0" class="rounded-lg border border-amber-500/30 bg-amber-500/10 p-4 text-sm text-amber-500">{{ $t('hourlyBilling.sshKeyRequired') }}</div>
        <div v-if="error" class="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-500">{{ error }}</div>
        <button type="submit" class="btn-primary w-full" :disabled="!canSubmit || submitting">
          {{ submitting ? $t('common.creating') : $t('hourlyBilling.createButton') }}
        </button>
      </aside>
    </form>
  </div>
</template>
