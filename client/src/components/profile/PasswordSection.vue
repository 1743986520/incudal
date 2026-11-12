<script setup lang="ts">
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import api from '@/api'
import { useAuthStore } from '@/stores/auth'

const { t } = useI18n()
const authStore = useAuthStore()

interface PasswordForm {
  currentPassword: string
  newPassword: string
  confirmPassword: string
}

const passwordForm = ref<PasswordForm>({
  currentPassword: '',
  newPassword: '',
  confirmPassword: ''
})
const passwordLoading = ref<boolean>(false)
const passwordError = ref<string>('')
const passwordSuccess = ref<boolean>(false)

async function updatePassword(): Promise<void> {
  passwordError.value = ''
  passwordSuccess.value = false

  if (passwordForm.value.newPassword !== passwordForm.value.confirmPassword) {
    passwordError.value = t('profile.password.mismatch')
    return
  }

  if (passwordForm.value.newPassword.length < 6) {
    passwordError.value = t('profile.password.tooShort')
    return
  }

  passwordLoading.value = true
  try {
    const response = await api.users.update(authStore.user!.id, {
      password: passwordForm.value.newPassword,
      currentPassword: passwordForm.value.currentPassword
    } as any)
    passwordForm.value = { currentPassword: '', newPassword: '', confirmPassword: '' }
    passwordSuccess.value = true
    if (response.confirmEmailSent) {
      // 邮件确认链接：点击邮件中的链接后新密码才生效
      setTimeout(() => passwordSuccess.value = false, 6000)
      return
    }
    if (response.reauthRequired) {
      setTimeout(() => {
        authStore.clearLocalAuth()
        window.location.href = '/login'
      }, 1000)
      return
    }
    setTimeout(() => passwordSuccess.value = false, 3000)
  } catch (error: any) {
    passwordError.value = error?.message || t('profile.password.updateFailed')
  } finally {
    passwordLoading.value = false
  }
}
</script>

<template>
  <div class="card p-5">
    <h2 class="text-sm font-medium text-themed-secondary mb-4">{{ $t('profile.password.title') }}</h2>
    <form class="space-y-4" @submit.prevent="updatePassword">
      <div>
        <label class="block text-xs text-themed-muted mb-1.5">{{ $t('profile.password.current') }}</label>
        <input
          v-model="passwordForm.currentPassword"
          type="password"
          class="input"
          :placeholder="$t('profile.password.currentPlaceholder')"
          autocomplete="current-password"
        />
      </div>
      <div>
        <label class="block text-xs text-themed-muted mb-1.5">{{ $t('profile.password.new') }}</label>
        <input
          v-model="passwordForm.newPassword"
          type="password"
          class="input"
          :placeholder="$t('profile.password.newPlaceholder')"
          autocomplete="new-password"
        />
      </div>
      <div>
        <label class="block text-xs text-themed-muted mb-1.5">{{ $t('profile.password.confirm') }}</label>
        <input
          v-model="passwordForm.confirmPassword"
          type="password"
          class="input"
          :placeholder="$t('profile.password.confirmPlaceholder')"
          autocomplete="new-password"
        />
      </div>

      <div v-if="passwordError" class="text-sm text-red-400">{{ passwordError }}</div>
      <div v-if="passwordSuccess" class="text-sm text-green-400">{{ $t('profile.password.updatedConfirmEmail') }}</div>

      <button
        type="submit"
        :disabled="passwordLoading || !passwordForm.currentPassword || !passwordForm.newPassword"
        class="btn-secondary"
      >
        {{ passwordLoading ? $t('profile.password.updating') : $t('profile.password.update') }}
      </button>
    </form>
  </div>
</template>
