<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import api from '@/api'
import { useThemeStore } from '@/stores/theme'
import { useBrand } from '@/composables/useBrand'

const { t } = useI18n()
const themeStore = useThemeStore()
const brand = useBrand()

const status = ref<'loading' | 'success' | 'error'>('loading')
const message = ref<string>('')
const taskId = ref<number | undefined>(undefined)
const apiKey = ref<string>('')
const apiKeyCopied = ref<boolean>(false)

async function copyApiKey(): Promise<void> {
  try {
    await navigator.clipboard.writeText(apiKey.value)
    apiKeyCopied.value = true
    setTimeout(() => apiKeyCopied.value = false, 3000)
  } catch {
    // 剪贴板不可用时忽略，密钥文本仍可直接选中复制
  }
}

onMounted(async (): Promise<void> => {
  const token = new URLSearchParams(window.location.search).get('token')
  if (!token) {
    status.value = 'error'
    message.value = t('operationConfirm.missingToken')
    return
  }

  try {
    const res = await api.verification.confirm(token)
    status.value = 'success'
    message.value = res.message || t('operationConfirm.success')
    taskId.value = res.taskId
    apiKey.value = res.apiKey?.key || ''
  } catch (err: any) {
    status.value = 'error'
    message.value = err?.message || t('operationConfirm.failed')
  }
})
</script>

<template>
  <div
    class="min-h-screen flex items-center justify-center p-4"
    :class="themeStore.isDark ? 'bg-[#0a0a0a]' : 'bg-gray-50'"
  >
    <div class="w-full max-w-sm text-center">
      <div class="card p-8">
        <img
          :src="brand.brandLogoUrl"
          :alt="brand.brandName"
          class="w-14 h-14 mx-auto mb-4 rounded-xl"
        />

        <!-- Loading -->
        <template v-if="status === 'loading'">
          <div class="animate-spin w-8 h-8 border-2 border-themed-muted border-t-transparent rounded-full mx-auto mb-4" />
          <p class="text-sm text-themed-secondary">{{ $t('auth.operationConfirm.processing') }}</p>
        </template>

        <!-- Success -->
        <template v-else-if="status === 'success'">
          <div class="w-12 h-12 mx-auto mb-4 flex items-center justify-center rounded-full bg-green-100 text-green-600 text-2xl">✓</div>
          <h2 class="text-base font-semibold text-themed-primary mb-2">{{ $t('auth.operationConfirm.successTitle') }}</h2>
          <p class="text-sm text-themed-secondary mb-1">{{ message }}</p>
          <template v-if="apiKey">
            <div class="my-4 rounded-xl border p-4 text-left" :class="themeStore.isDark ? 'border-amber-500/40 bg-amber-500/10' : 'border-amber-200 bg-amber-50'">
              <p class="text-xs font-medium mb-2" :class="themeStore.isDark ? 'text-amber-200' : 'text-amber-700'">
                {{ $t('auth.operationConfirm.apiKeyOnceTitle') }}
              </p>
              <div class="flex items-center gap-2">
                <code class="flex-1 break-all text-xs font-mono px-2 py-1.5 rounded bg-themed-tertiary text-themed-primary select-all">{{ apiKey }}</code>
                <button type="button" class="btn-secondary btn-sm whitespace-nowrap" @click="copyApiKey">
                  {{ apiKeyCopied ? $t('auth.operationConfirm.copied') : $t('auth.operationConfirm.copy') }}
                </button>
              </div>
              <p class="mt-2 text-xs text-themed-muted">{{ $t('auth.operationConfirm.apiKeyOnceDesc') }}</p>
            </div>
          </template>
          <p v-if="taskId" class="text-xs text-themed-muted mb-4">{{ $t('auth.operationConfirm.taskQueued', { id: taskId }) }}</p>
          <p v-else-if="!apiKey" class="text-xs text-themed-muted mb-4">{{ $t('auth.operationConfirm.canClosePage') }}</p>
          <RouterLink to="/dashboard" class="btn-primary inline-block">{{ $t('auth.operationConfirm.backToPanel') }}</RouterLink>
        </template>

        <!-- Error -->
        <template v-else>
          <div class="w-12 h-12 mx-auto mb-4 flex items-center justify-center rounded-full bg-red-100 text-red-600 text-2xl">✕</div>
          <h2 class="text-base font-semibold text-themed-primary mb-2">{{ $t('auth.operationConfirm.failedTitle') }}</h2>
          <p class="text-sm text-themed-secondary mb-4">{{ message }}</p>
          <RouterLink to="/dashboard" class="btn-secondary inline-block">{{ $t('auth.operationConfirm.backToPanel') }}</RouterLink>
        </template>
      </div>
    </div>
  </div>
</template>
