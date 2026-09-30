import { createApp } from 'vue'
import { createPinia } from 'pinia'
import router from './router'
import i18n, { getLocale, initLocale } from './locales'
import App from './App.vue'
import './styles/main.css'
import { applySeoTracking } from './utils/seoTracking'
import { reloadOnceForChunkError } from './utils/chunkReload'
// flag-icons CSS 改为懒加载，在 FlagIcon.vue 组件首次使用时动态导入，避免全量加载到首屏

// The old Service Worker duplicated static assets in CacheStorage and could
// keep serving stale chunks after a deploy. Retire only our root worker and
// remove only caches owned by Incudal; do not touch other site storage.
if (import.meta.env.PROD && 'serviceWorker' in navigator) {
  void (async () => {
    const registration = await navigator.serviceWorker.getRegistration('/')
    const workers = [registration?.active, registration?.waiting, registration?.installing]
    const hasLegacyWorker = workers.some(worker => worker && new URL(worker.scriptURL).pathname === '/sw.js')
    if (registration && hasLegacyWorker) await registration.unregister()

    if ('caches' in window) {
      const names = await caches.keys()
      await Promise.all(names
        .filter(name => name.startsWith('incudal-cache-'))
        .map(name => caches.delete(name)))
    }

    // Unregistering does not release the controller of the current document.
    // One bounded reload switches the tab to ordinary network requests.
    if (hasLegacyWorker && navigator.serviceWorker.controller) {
      const key = 'incudal.sw-retired-reload'
      if (sessionStorage.getItem(key) !== '1') {
        sessionStorage.setItem(key, '1')
        window.location.reload()
      }
    }
  })().catch(error => console.warn('Legacy Service Worker cleanup failed:', error))
}

const app = createApp(App)
const pinia = createPinia()

app.use(pinia)
app.use(router)
app.use(i18n)

// 全局错误处理
app.config.errorHandler = (err, _instance, info) => {
  console.error('Vue应用错误:', err, info)
  // 如果是组件加载错误，尝试重新加载页面
  if (err && typeof err === 'object' && 'message' in err) {
    const errorMessage = String(err.message)
    if (errorMessage.includes('Failed to fetch dynamically imported module') ||
        errorMessage.includes('Loading chunk') ||
        errorMessage.includes('ChunkLoadError')) {
      console.warn('检测到代码块加载失败，尝试重新加载页面')
      setTimeout(reloadOnceForChunkError, 1000)
      return
    }
  }
}

// Initialize theme (after pinia is mounted)
import { useThemeStore } from './stores/theme'
const themeStore = useThemeStore()
themeStore.init()

// Load public config
import { useConfigStore } from './stores/config'
const configStore = useConfigStore()
configStore.loadPublicConfig().then(() => {
  const logoUrl = configStore.brandLogoUrl?.trim() || '/incudal_logo.webp'
  const icon = document.querySelector('link[rel="icon"]') as HTMLLinkElement | null
  const appleTouchIcon = document.querySelector('link[rel="apple-touch-icon"]') as HTMLLinkElement | null
  if (icon) {
    icon.href = logoUrl
  }
  if (appleTouchIcon) {
    appleTouchIcon.href = logoUrl
  }
  applySeoTracking({
    enabled: configStore.seoTrackingEnabled,
    scriptUrl: configStore.seoTrackingScriptUrl,
    trackingId: configStore.seoTrackingId
  })
})

// 预加载用户选择的语言（zh-CN 用户无额外开销，非默认语言异步加载对应 chunk）
initLocale().finally(() => {
  document.documentElement.lang = getLocale()
  app.mount('#app')

})
