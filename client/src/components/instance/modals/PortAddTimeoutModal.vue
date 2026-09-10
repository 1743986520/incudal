<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import { useThemeStore } from '@/stores/theme'

const { t } = useI18n()
const themeStore = useThemeStore()

interface Props {
  visible: boolean
  retryCount: number
  maxRetries: number
}

interface Emits {
  (e: 'update:visible', value: boolean): void
  (e: 'retry'): void
  (e: 'abandon'): void
}

const props = defineProps<Props>()
const emit = defineEmits<Emits>()

const canRetry = () => props.retryCount < props.maxRetries

function retry(): void {
  if (!canRetry()) return
  emit('retry')
  emit('update:visible', false)
}

function abandon(): void {
  emit('abandon')
  emit('update:visible', false)
}
</script>

<template>
  <Teleport to="body">
    <Transition name="modal">
      <div v-if="visible" class="fixed inset-0 z-[60] flex items-center justify-center p-4">
        <div
          class="absolute inset-0 backdrop-blur-sm"
          :class="themeStore.isDark ? 'bg-black/60' : 'bg-black/30'"
        ></div>

        <div
          class="modal-content relative w-full max-w-md rounded-xl border shadow-2xl"
          :class="themeStore.isDark ? 'border-gray-800 bg-gray-900' : 'border-gray-200 bg-white'"
        >
          <div
            class="flex items-center gap-3 border-b p-5"
            :class="themeStore.isDark ? 'border-gray-800' : 'border-gray-200'"
          >
            <div class="rounded-lg bg-amber-500/10 p-2">
              <svg class="h-5 w-5 text-amber-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            </div>
            <h3
              class="text-base font-medium"
              :class="themeStore.isDark ? 'text-gray-100' : 'text-gray-900'"
            >
              {{ t('portAddTimeout.title') }}
            </h3>
          </div>

          <div class="space-y-3 p-5">
            <p
              class="text-sm leading-6"
              :class="themeStore.isDark ? 'text-gray-400' : 'text-gray-600'"
            >
              {{ t('portAddTimeout.description') }}
            </p>
            <p
              class="text-xs"
              :class="themeStore.isDark ? 'text-gray-500' : 'text-gray-500'"
            >
              {{ t('portAddTimeout.retryCount', { count: retryCount, max: maxRetries }) }}
            </p>
          </div>

          <div
            class="flex justify-end gap-3 border-t p-5"
            :class="themeStore.isDark ? 'border-gray-800' : 'border-gray-200'"
          >
            <button type="button" class="btn-secondary" @click="abandon">
              {{ t('portAddTimeout.abandon') }}
            </button>
            <button
              type="button"
              class="btn-primary"
              :disabled="!canRetry()"
              @click="retry"
            >
              {{ canRetry() ? t('portAddTimeout.retry') : t('portAddTimeout.retryLimitReached') }}
            </button>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>
