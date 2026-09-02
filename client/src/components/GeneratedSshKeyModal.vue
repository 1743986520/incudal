<script setup lang="ts">
import { ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useToast } from '@/stores/toast'

interface Props {
  visible: boolean
  privateKey: string
  title: string
  description: string
  actionLabel: string
}

const props = defineProps<Props>()
const emit = defineEmits<{
  close: []
  action: []
}>()
const { t } = useI18n()
const toast = useToast()
const copied = ref(false)

watch(() => props.visible, (visible) => {
  if (visible) copied.value = false
})

async function copyPrivateKey(): Promise<void> {
  try {
    await navigator.clipboard.writeText(props.privateKey)
    copied.value = true
    setTimeout(() => { copied.value = false }, 2000)
  } catch {
    toast.error(t('profile.sshKeys.copyFailed'))
  }
}

function downloadPrivateKey(): void {
  if (!props.privateKey) return

  const blob = new Blob([props.privateKey], { type: 'application/x-pem-file' })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = 'id_rsa'
  document.body.appendChild(anchor)
  anchor.click()
  document.body.removeChild(anchor)
  URL.revokeObjectURL(url)
}
</script>

<template>
  <Teleport to="body">
    <Transition name="modal">
      <div v-if="visible" class="modal-overlay" @click.self="emit('close')">
        <div class="modal-content max-w-2xl">
          <div class="modal-header">
            <div class="flex items-center gap-3">
              <div class="w-10 h-10 rounded-xl bg-yellow-500/15 flex items-center justify-center">
                <svg class="w-5 h-5 text-yellow-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9" />
                </svg>
              </div>
              <div>
                <h3 class="modal-title">{{ title }}</h3>
                <p class="text-xs text-themed-muted mt-0.5">RSA 4096-bit</p>
              </div>
            </div>
            <button type="button" class="text-themed-muted hover:text-themed" @click="emit('close')">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
          <div class="modal-body space-y-4">
            <div class="flex items-start gap-3 p-3 rounded-lg bg-yellow-500/10 border border-yellow-500/20">
              <svg class="w-5 h-5 text-yellow-500 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333-.578 3 1.122 3z" />
              </svg>
              <div>
                <p class="text-sm font-medium text-yellow-600 dark:text-yellow-400">{{ description }}</p>
                <p class="text-xs text-yellow-600/80 dark:text-yellow-400/80 mt-1">{{ $t('profile.sshKeys.privateKeyWarningDesc') }}</p>
              </div>
            </div>
            <div>
              <label class="block text-xs text-themed-muted mb-2">{{ $t('profile.sshKeys.privateKeyContent') }}</label>
              <pre class="p-4 rounded-lg bg-themed-tertiary border border-themed font-mono text-xs text-themed-secondary overflow-x-auto whitespace-pre-wrap break-all max-h-[280px] overflow-y-auto">{{ privateKey }}</pre>
            </div>
          </div>
          <div class="modal-footer flex-wrap">
            <button type="button" class="btn-ghost btn-sm flex-1 sm:flex-none" @click="copyPrivateKey">
              {{ copied ? $t('common.copied') : $t('common.copy') }}
            </button>
            <button type="button" class="btn-primary btn-sm flex-1 sm:flex-none" @click="downloadPrivateKey">
              {{ $t('profile.sshKeys.download') }}
            </button>
            <button type="button" class="btn-primary btn-sm w-full sm:w-auto" @click="emit('action')">
              {{ actionLabel }}
            </button>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>
