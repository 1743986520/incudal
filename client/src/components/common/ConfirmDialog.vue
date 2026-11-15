<script setup lang="ts">
import { ref, watch, nextTick, onUnmounted } from 'vue'

/**
 * 共用确认弹窗：替代原生 confirm()
 * - role="dialog" + aria-modal + Esc 关闭 + 简易焦点圈定
 * - requireInput：需要用户输入指定文本才能确认（用于高危删除）
 */
const props = withDefaults(defineProps<{
  visible: boolean
  title: string
  message: string
  confirmLabel?: string
  cancelLabel?: string
  danger?: boolean
  loading?: boolean
  /** 需要用户照打的确认文本（如实例名）；提供时确认按钮在匹配前保持禁用 */
  requireInput?: string
  inputPlaceholder?: string
}>(), {
  confirmLabel: '',
  cancelLabel: '',
  danger: false,
  loading: false,
  requireInput: '',
  inputPlaceholder: '',
})

const emit = defineEmits<{
  confirm: []
  close: []
}>()

const inputText = ref('')
const contentEl = ref<HTMLElement | null>(null)

watch(() => props.visible, async (visible) => {
  inputText.value = ''
  if (visible) {
    await nextTick()
    const target = props.requireInput
      ? contentEl.value?.querySelector('input')
      : contentEl.value?.querySelector('button')
    ;(target as HTMLElement | null)?.focus()
    document.addEventListener('keydown', onKeydown)
  } else {
    document.removeEventListener('keydown', onKeydown)
  }
})

function onKeydown(e: KeyboardEvent): void {
  if (e.key === 'Escape') {
    emit('close')
    return
  }
  // 简易焦点圈定：Tab 循环
  if (e.key === 'Tab' && contentEl.value) {
    const focusables = contentEl.value.querySelectorAll<HTMLElement>(
      'button, input, [href], [tabindex]:not([tabindex="-1"])'
    )
    if (focusables.length === 0) return
    const first = focusables[0]
    const last = focusables[focusables.length - 1]
    if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault()
      first.focus()
    } else if (e.shiftKey && document.activeElement === first) {
      e.preventDefault()
      last.focus()
    }
  }
}

onUnmounted(() => document.removeEventListener('keydown', onKeydown))

const inputSatisfied = (): boolean =>
  !props.requireInput || inputText.value.trim() === props.requireInput
</script>

<template>
  <Teleport to="body">
    <Transition name="modal">
      <div
        v-if="visible"
        class="modal-overlay"
        role="dialog"
        aria-modal="true"
        :aria-label="title"
        @click.self="emit('close')"
      >
        <div ref="contentEl" class="modal-content max-w-md" @keydown="onKeydown">
          <div class="modal-header">
            <h3 class="modal-title">{{ title }}</h3>
            <button
              type="button"
              class="p-1 rounded hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
              :aria-label="$t('common.close')"
              @click="emit('close')"
            >
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>

          <div class="modal-body">
            <p class="text-sm text-themed-secondary whitespace-pre-line">{{ message }}</p>

            <div v-if="requireInput" class="mt-4">
              <label class="block text-xs text-themed-muted mb-1.5">
                {{ $t('common.confirmInputHint', { text: requireInput }) }}
              </label>
              <input
                v-model="inputText"
                type="text"
                class="input w-full"
                :placeholder="inputPlaceholder || requireInput"
                autocomplete="off"
              />
            </div>
          </div>

          <div class="modal-footer">
            <button type="button" class="btn-secondary" @click="emit('close')">
              {{ cancelLabel || $t('common.cancel') }}
            </button>
            <button
              type="button"
              :class="danger ? 'btn-danger' : 'btn-primary'"
              :disabled="loading || !inputSatisfied()"
              @click="emit('confirm')"
            >
              {{ loading ? $t('common.processing') : (confirmLabel || $t('common.confirm')) }}
            </button>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>
