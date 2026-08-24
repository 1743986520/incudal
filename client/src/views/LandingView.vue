<script setup lang="ts">
import PortalView from '@/views/PortalView.vue'
import PublicSiteLayout from '@/components/public/PublicSiteLayout.vue'

defineOptions({ name: 'LandingView' })
</script>

<template>
  <PublicSiteLayout>
    <PortalView />
  </PublicSiteLayout>
</template>
