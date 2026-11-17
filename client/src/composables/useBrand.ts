import { useConfigStore } from '@/stores/config'

export function useBrand() {
  const configStore = useConfigStore()

  return {
    get brandName() {
      return configStore.brandName?.trim() || '黃帝云'
    },
    get brandSubtitle() {
      return configStore.brandSubtitle?.trim() || '黃帝云 · 低价 NAT VPS'
    },
    get brandLogoUrl() {
      return configStore.brandLogoUrl?.trim() || '/incudal_logo.webp'
    }
  }
}
