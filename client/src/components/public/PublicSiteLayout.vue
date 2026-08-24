<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { useThemeStore } from '@/stores/theme'
import PublicSiteFooter from '@/components/public/PublicSiteFooter.vue'
import PublicSiteHeader from '@/components/public/PublicSiteHeader.vue'

const route = useRoute()
const themeStore = useThemeStore()

const authRouteNames = new Set(['login', 'register', 'forgot-password'])

const isAuthPage = computed(() => authRouteNames.has(String(route.name || '')))
</script>

<template>
  <div
    class="flex min-h-screen flex-col"
    :class="themeStore.isDark
      ? 'bg-black text-gray-100'
      : 'bg-white text-gray-900'"
  >
    <PublicSiteHeader />

    <main class="relative flex flex-1 flex-col">
      <div
        v-if="isAuthPage"
        class="mx-auto flex w-full max-w-7xl flex-1 items-center justify-center px-4 py-10 sm:px-6 sm:py-14 lg:px-8"
      >
        <slot />
      </div>
      <slot v-else />
    </main>

    <PublicSiteFooter v-if="!isAuthPage" />
  </div>
</template>
