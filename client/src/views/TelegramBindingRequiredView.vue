<script setup lang="ts">
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import TelegramBindingSection from '@/components/profile/TelegramBindingSection.vue'

const route = useRoute()
const router = useRouter()
const { t } = useI18n()
const isBound = ref(false)

function continueToPanel(): void {
  const requestedRoute = route.query.redirect
  const target = typeof requestedRoute === 'string' && requestedRoute.startsWith('/') && !requestedRoute.startsWith('//')
    ? requestedRoute
    : '/dashboard'
  void router.replace(target)
}
</script>

<template>
  <div class="max-w-2xl mx-auto space-y-4 animate-fade-in">
    <div class="page-header">
      <h1 class="page-title">{{ t('auth.telegramBindingRequired.title') }}</h1>
      <p class="text-sm text-themed-muted mt-2">
        {{ t('auth.telegramBindingRequired.description') }}
      </p>
    </div>

    <TelegramBindingSection @binding-updated="isBound = $event" />

    <button v-if="isBound" type="button" class="btn-primary w-full sm:w-auto" @click="continueToPanel">
      {{ t('auth.telegramBindingRequired.continue') }}
    </button>
  </div>
</template>
