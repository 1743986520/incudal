<script setup lang="ts">
interface Props {
  visible: boolean
  loading?: boolean
  title: string
  description: string
  confirmLabel: string
  cancelLabel: string
  loadingLabel: string
}

withDefaults(defineProps<Props>(), {
  loading: false
})

const emit = defineEmits<{
  close: []
  confirm: []
}>()
</script>

<template>
  <Teleport to="body">
    <Transition name="modal">
      <div v-if="visible" class="modal-overlay" @click.self="emit('close')">
        <div class="modal-content max-w-md">
          <div class="modal-header">
            <div class="flex items-center gap-3">
              <div class="w-10 h-10 rounded-xl bg-blue-500/15 flex items-center justify-center">
                <svg class="w-5 h-5 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9" />
                </svg>
              </div>
              <h3 class="modal-title">{{ title }}</h3>
            </div>
            <button type="button" class="text-themed-muted hover:text-themed" :disabled="loading" @click="emit('close')">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
          <div class="modal-body space-y-4">
            <p class="text-sm text-themed-secondary">{{ description }}</p>
            <div class="p-3 rounded-lg bg-yellow-500/10 border border-yellow-500/20 text-xs text-yellow-700 dark:text-yellow-300">
              {{ $t('profile.sshKeys.privateKeyWarningDesc') }}
            </div>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn-ghost btn-sm" :disabled="loading" @click="emit('close')">
              {{ cancelLabel }}
            </button>
            <button type="button" class="btn-primary btn-sm" :disabled="loading" @click="emit('confirm')">
              <svg v-if="loading" class="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              {{ loading ? loadingLabel : confirmLabel }}
            </button>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>
