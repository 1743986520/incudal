<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import api from '@/api'
import type {
  SystemUpdateCheckResponse,
  SystemUpdateExecution,
  SystemUpdateMode,
  SystemUpdateStatusResponse
} from '@/types/api'
import { useToast } from '@/stores/toast'
import { translateError } from '@/utils/errorHandler'

const { t, locale } = useI18n()
const toast = useToast()

const DEFAULT_SOURCE = 'https://github.com/1743986520/incudal'
const source = ref(localStorage.getItem('incudal.update.source') || DEFAULT_SOURCE)
const mode = ref<SystemUpdateMode>('auto')
const loading = ref(true)
const checking = ref(false)
const applying = ref(false)
const status = ref<SystemUpdateStatusResponse | null>(null)
const checkResult = ref<SystemUpdateCheckResponse | null>(null)
const manualCommand = ref('')
let pollTimer: number | null = null

const execution = computed<SystemUpdateExecution | null>(() => status.value?.execution || null)
const isRunning = computed(() => execution.value?.status === 'running' || applying.value)
const currentVersion = computed(() => checkResult.value?.currentVersion || status.value?.currentVersion || 'unknown')
const sourceRepository = computed(() => checkResult.value?.sourceRepository || status.value?.sourceRepository || '')
const sourceUrl = computed(() => checkResult.value?.sourceUrl || status.value?.sourceUrl || source.value)

onMounted(() => {
  void loadStatus()
})

onUnmounted(() => stopPolling())

function normalizeSource(): string {
  const value = source.value.trim().replace(/\/+$/, '') || DEFAULT_SOURCE
  source.value = value
  localStorage.setItem('incudal.update.source', value)
  return value
}

function handleSourceInput() {
  checkResult.value = null
  manualCommand.value = ''
}

async function loadStatus() {
  loading.value = true
  try {
    status.value = await api.systemUpdate.status(normalizeSource())
    if (status.value.execution?.status === 'running') {
      applying.value = true
      startPolling()
    }
  } catch (error) {
    toast.error(`${t('admin.systemUpdate.loadFailed')}: ${translateError(error)}`)
  } finally {
    loading.value = false
  }
}

async function checkForUpdates() {
  checking.value = true
  manualCommand.value = ''
  try {
    checkResult.value = await api.systemUpdate.check(normalizeSource())
    status.value = await api.systemUpdate.status(source.value)
    toast.success(checkResult.value.updateAvailable
      ? t('admin.systemUpdate.updateAvailable')
      : t('admin.systemUpdate.alreadyLatest'))
  } catch (error) {
    toast.error(`${t('admin.systemUpdate.checkFailed')}: ${translateError(error)}`)
  } finally {
    checking.value = false
  }
}

async function applyUpdate() {
  if (!window.confirm(t('admin.systemUpdate.confirm', { source: normalizeSource() }))) return

  applying.value = true
  manualCommand.value = ''
  try {
    const result = await api.systemUpdate.apply(source.value, mode.value)
    status.value = {
      ...(status.value || {
        currentVersion: currentVersion.value,
        sourceRepository: sourceRepository.value,
        sourceUrl: sourceUrl.value,
        execution: null,
        executorAvailable: true,
        installDirectory: '/opt/incudal'
      }),
      execution: result.execution
    }
    toast.success(t('admin.systemUpdate.started'))
    startPolling()
  } catch (error: any) {
    if (typeof error?.command === 'string') {
      manualCommand.value = error.command
    }
    toast.error(`${t('admin.systemUpdate.applyFailed')}: ${translateError(error)}`)
    applying.value = false
  }
}

function startPolling() {
  stopPolling()
  pollTimer = window.setInterval(async () => {
    try {
      status.value = await api.systemUpdate.status(source.value)
      if (status.value.execution?.status !== 'running') {
        applying.value = false
        stopPolling()
      }
    } catch {
      // 更新可能正在重启服务，短暂请求失败时保留当前状态。
    }
  }, 2000)
}

function stopPolling() {
  if (pollTimer !== null) {
    window.clearInterval(pollTimer)
    pollTimer = null
  }
}

function formatDate(value: string | null | undefined): string {
  if (!value) return t('common.notSet')
  return new Date(value).toLocaleString(locale.value)
}

async function copyCommand() {
  if (!manualCommand.value) return
  try {
    await navigator.clipboard.writeText(manualCommand.value)
    toast.success(t('admin.systemUpdate.commandCopied'))
  } catch {
    toast.error(t('admin.systemUpdate.copyFailed'))
  }
}

function executionLabel(value: SystemUpdateExecution | null): string {
  if (!value) return t('admin.systemUpdate.notStarted')
  return t(`admin.systemUpdate.execution.${value.status}`)
}
</script>

<template>
  <div class="space-y-6">
    <div class="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
      <div>
        <h1 class="page-title">{{ t('admin.systemUpdate.title') }}</h1>
        <p class="page-description">{{ t('admin.systemUpdate.description') }}</p>
      </div>
      <button type="button" class="btn-secondary" :disabled="loading || checking || isRunning" @click="loadStatus">
        {{ t('common.refresh') }}
      </button>
    </div>

    <div class="card p-6 space-y-5">
      <div>
        <h2 class="text-themed font-medium">{{ t('admin.systemUpdate.sourceTitle') }}</h2>
        <p class="text-sm text-themed-muted mt-1">{{ t('admin.systemUpdate.sourceDescription') }}</p>
      </div>

      <div class="grid grid-cols-1 gap-4 md:grid-cols-[minmax(0,1fr)_12rem]">
        <div class="space-y-2">
          <label class="block text-sm text-themed-secondary" for="system-update-source">
            {{ t('admin.systemUpdate.sourceLabel') }}
          </label>
          <input
            id="system-update-source"
            v-model="source"
            class="input w-full font-mono text-sm"
            :disabled="isRunning"
            :placeholder="DEFAULT_SOURCE"
            @input="handleSourceInput"
            @change="normalizeSource"
          />
          <p class="text-xs text-themed-muted">{{ t('admin.systemUpdate.sourceHint') }}</p>
        </div>
        <div class="space-y-2">
          <label class="block text-sm text-themed-secondary" for="system-update-mode">
            {{ t('admin.systemUpdate.modeLabel') }}
          </label>
          <select id="system-update-mode" v-model="mode" class="input w-full" :disabled="isRunning">
            <option value="auto">{{ t('admin.systemUpdate.modes.auto') }}</option>
            <option value="docker">{{ t('admin.systemUpdate.modes.docker') }}</option>
            <option value="release">{{ t('admin.systemUpdate.modes.release') }}</option>
          </select>
        </div>
      </div>

      <div class="flex flex-wrap gap-3">
        <button type="button" class="btn-secondary" :disabled="checking || isRunning" @click="checkForUpdates">
          {{ checking ? t('admin.systemUpdate.checking') : t('admin.systemUpdate.check') }}
        </button>
        <button type="button" class="btn-primary" :disabled="checking || isRunning" @click="applyUpdate">
          {{ isRunning ? t('admin.systemUpdate.updating') : t('admin.systemUpdate.updateNow') }}
        </button>
      </div>
    </div>

    <div class="grid grid-cols-1 gap-6 lg:grid-cols-2">
      <div class="card p-6 space-y-4">
        <h2 class="text-themed font-medium">{{ t('admin.systemUpdate.versionTitle') }}</h2>
        <div class="grid grid-cols-2 gap-4">
          <div class="rounded-lg bg-themed-secondary/40 p-4">
            <div class="text-xs text-themed-muted">{{ t('admin.systemUpdate.currentVersion') }}</div>
            <div class="mt-1 text-lg font-semibold text-themed">{{ currentVersion }}</div>
          </div>
          <div class="rounded-lg bg-themed-secondary/40 p-4">
            <div class="text-xs text-themed-muted">{{ t('admin.systemUpdate.latestVersion') }}</div>
            <div class="mt-1 text-lg font-semibold text-themed">{{ checkResult?.latest.version || t('common.notSet') }}</div>
          </div>
        </div>
        <div v-if="checkResult" class="rounded-lg border p-4" :class="checkResult.updateAvailable ? 'border-amber-500/40 bg-amber-500/10' : 'border-green-500/40 bg-green-500/10'">
          <div class="font-medium text-themed">
            {{ checkResult.updateAvailable ? t('admin.systemUpdate.updateAvailable') : t('admin.systemUpdate.alreadyLatest') }}
          </div>
          <div class="mt-1 text-sm text-themed-muted">{{ checkResult.latest.name }}</div>
          <div class="mt-1 text-xs text-themed-muted">{{ t('admin.systemUpdate.publishedAt', { time: formatDate(checkResult.latest.publishedAt) }) }}</div>
          <a :href="checkResult.latest.url" target="_blank" rel="noopener noreferrer" class="mt-3 inline-block text-sm text-blue-500 hover:underline">
            {{ t('admin.systemUpdate.viewRelease') }}
          </a>
        </div>
        <div v-else class="text-sm text-themed-muted">{{ t('admin.systemUpdate.checkHint') }}</div>
      </div>

      <div class="card p-6 space-y-4">
        <h2 class="text-themed font-medium">{{ t('admin.systemUpdate.executionTitle') }}</h2>
        <dl class="space-y-3 text-sm">
          <div class="flex items-start justify-between gap-4">
            <dt class="text-themed-muted">{{ t('admin.systemUpdate.sourceRepository') }}</dt>
            <dd class="text-themed font-mono text-right break-all">{{ sourceRepository || t('common.notSet') }}</dd>
          </div>
          <div class="flex items-start justify-between gap-4">
            <dt class="text-themed-muted">{{ t('admin.systemUpdate.executionStatus') }}</dt>
            <dd class="text-themed">{{ executionLabel(execution) }}</dd>
          </div>
          <div v-if="execution" class="flex items-start justify-between gap-4">
            <dt class="text-themed-muted">{{ t('admin.systemUpdate.startedAt') }}</dt>
            <dd class="text-themed text-right">{{ formatDate(execution.startedAt) }}</dd>
          </div>
        </dl>
        <div v-if="execution?.output" class="rounded-lg bg-gray-950 p-3 text-xs text-gray-200">
          <pre class="max-h-56 overflow-auto whitespace-pre-wrap break-words">{{ execution.output }}</pre>
        </div>
        <div v-if="execution?.error" class="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-500">
          {{ execution.error }}
        </div>
        <div v-if="status && !status.executorAvailable" class="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-themed">
          {{ t('admin.systemUpdate.executorUnavailable') }}
        </div>
      </div>
    </div>

    <div v-if="manualCommand" class="card p-6 space-y-3">
      <h2 class="text-themed font-medium">{{ t('admin.systemUpdate.manualTitle') }}</h2>
      <p class="text-sm text-themed-muted">{{ t('admin.systemUpdate.manualDescription') }}</p>
      <div class="flex flex-col gap-3 sm:flex-row sm:items-start">
        <code class="min-w-0 flex-1 rounded-lg bg-gray-950 p-3 text-xs text-gray-200 break-all">{{ manualCommand }}</code>
        <button type="button" class="btn-secondary whitespace-nowrap" @click="copyCommand">
          {{ t('admin.systemUpdate.copyCommand') }}
        </button>
      </div>
    </div>

    <div class="rounded-lg border border-amber-500/30 bg-amber-500/10 p-4 text-sm text-themed">
      <strong>{{ t('admin.systemUpdate.noticeTitle') }}</strong>
      <span class="ml-1">{{ t('admin.systemUpdate.notice') }}</span>
    </div>
  </div>
</template>
