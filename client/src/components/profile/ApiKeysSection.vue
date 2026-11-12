<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import api from '@/api'
import { useToast } from '@/stores/toast'
import { translateError } from '@/utils/errorHandler'

const { t } = useI18n()
const toast = useToast()

interface ApiKeyItem {
  id: number
  name: string | null
  prefix: string
  status: 'active' | 'disabled'
  lastUsedAt: string | null
  requestCount: number
  createdAt: string
}

const keys = ref<ApiKeyItem[]>([])
const loading = ref<boolean>(false)
const creating = ref<boolean>(false)
const keyName = ref<string>('')
const actionBusyId = ref<number | null>(null)

onMounted(loadKeys)

async function loadKeys(): Promise<void> {
  loading.value = true
  try {
    const res = await api.apiKeys.list()
    keys.value = res.keys
  } catch (err: any) {
    toast.error(t('profile.apiKeys.loadFailed') + ': ' + (err?.message || ''))
  } finally {
    loading.value = false
  }
}

async function requestCreate(): Promise<void> {
  if (creating.value) return
  creating.value = true
  try {
    await api.apiKeys.requestCreate(keyName.value.trim() || undefined)
    toast.success(t('profile.apiKeys.confirmEmailSent'), 8000)
    keyName.value = ''
  } catch (err: any) {
    toast.error(t('profile.apiKeys.createFailed') + ': ' + (err?.message || ''))
  } finally {
    creating.value = false
  }
}

async function toggleStatus(item: ApiKeyItem): Promise<void> {
  if (actionBusyId.value !== null) return
  actionBusyId.value = item.id
  try {
    const next = item.status === 'active' ? 'disabled' : 'active'
    await api.apiKeys.setStatus(item.id, next)
    item.status = next
    toast.success(next === 'active' ? t('profile.apiKeys.enabled') : t('profile.apiKeys.disabled'))
  } catch (err: any) {
    toast.error(translateError(err))
  } finally {
    actionBusyId.value = null
  }
}

async function removeKey(item: ApiKeyItem): Promise<void> {
  if (actionBusyId.value !== null) return
  if (!window.confirm(t('profile.apiKeys.deleteConfirm', { prefix: item.prefix }))) return
  actionBusyId.value = item.id
  try {
    await api.apiKeys.remove(item.id)
    keys.value = keys.value.filter(k => k.id !== item.id)
    toast.success(t('profile.apiKeys.deleted'))
  } catch (err: any) {
    toast.error(translateError(err))
  } finally {
    actionBusyId.value = null
  }
}

function formatDateTime(value: string | null): string {
  if (!value) return t('profile.apiKeys.never')
  return new Date(value).toLocaleString()
}
</script>

<template>
  <div class="card p-5">
    <h2 class="text-sm font-medium text-themed-secondary mb-2">{{ $t('profile.apiKeys.title') }}</h2>
    <p class="text-xs text-themed-muted mb-4">{{ $t('profile.apiKeys.description') }}</p>

    <!-- 创建入口 -->
    <div class="flex flex-col sm:flex-row gap-3 sm:items-end mb-4">
      <div class="flex-1">
        <label class="block text-xs text-themed-muted mb-1.5">{{ $t('profile.apiKeys.name') }}</label>
        <input
          v-model="keyName"
          type="text"
          maxlength="64"
          class="input w-full"
          :placeholder="$t('profile.apiKeys.namePlaceholder')"
        />
      </div>
      <button type="button" class="btn-primary" :disabled="creating" @click="requestCreate">
        {{ creating ? $t('common.processing') : $t('profile.apiKeys.create') }}
      </button>
    </div>

    <div class="rounded-lg border p-3 text-xs text-themed-muted mb-4">
      {{ $t('profile.apiKeys.scopeHint') }}
    </div>

    <!-- 列表 -->
    <div v-if="loading" class="text-sm text-themed-muted py-4 text-center">{{ $t('common.loading') }}</div>
    <div v-else-if="keys.length === 0" class="text-sm text-themed-muted py-4 text-center">
      {{ $t('profile.apiKeys.empty') }}
    </div>
    <div v-else class="overflow-x-auto">
      <table class="w-full text-sm">
        <thead>
          <tr class="border-b border-themed text-left text-xs text-themed-muted">
            <th class="px-2 py-2 font-medium">{{ $t('profile.apiKeys.nameCol') }}</th>
            <th class="px-2 py-2 font-medium">{{ $t('profile.apiKeys.prefixLabel') }}</th>
            <th class="px-2 py-2 font-medium">{{ $t('profile.apiKeys.statusLabel') }}</th>
            <th class="px-2 py-2 font-medium">{{ $t('profile.apiKeys.lastUsed') }}</th>
            <th class="px-2 py-2 font-medium">{{ $t('profile.apiKeys.requests') }}</th>
            <th class="px-2 py-2 font-medium">{{ $t('profile.apiKeys.actions') }}</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-themed">
          <tr v-for="item in keys" :key="item.id">
            <td class="px-2 py-2 text-themed">{{ item.name || $t('profile.apiKeys.defaultName') }}</td>
            <td class="px-2 py-2 font-mono text-xs text-themed">{{ item.prefix }}…</td>
            <td class="px-2 py-2">
              <span
                class="badge badge-sm"
                :class="item.status === 'active' ? 'text-green-500' : 'text-themed-muted'"
              >
                {{ item.status === 'active' ? $t('profile.apiKeys.statusActive') : $t('profile.apiKeys.statusDisabled') }}
              </span>
            </td>
            <td class="px-2 py-2 text-xs text-themed-muted">{{ formatDateTime(item.lastUsedAt) }}</td>
            <td class="px-2 py-2 text-xs text-themed-muted">{{ item.requestCount }}</td>
            <td class="px-2 py-2">
              <div class="flex gap-2">
                <button
                  type="button"
                  class="btn-ghost btn-sm"
                  :disabled="actionBusyId === item.id"
                  @click="toggleStatus(item)"
                >
                  {{ item.status === 'active' ? $t('profile.apiKeys.disable') : $t('profile.apiKeys.enable') }}
                </button>
                <button
                  type="button"
                  class="btn-ghost btn-sm text-red-400"
                  :disabled="actionBusyId === item.id"
                  @click="removeKey(item)"
                >
                  {{ $t('profile.apiKeys.delete') }}
                </button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
