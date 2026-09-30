// Retire the legacy static-asset Service Worker. The app does not cache HTML
// for offline use, so the worker only duplicated the browser's HTTP cache.
self.addEventListener('install', (event) => {
  event.waitUntil(self.skipWaiting())
})

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    const names = await caches.keys()
    await Promise.all(names
      .filter(name => name.startsWith('incudal-cache-'))
      .map(name => caches.delete(name)))
    await self.registration.unregister()
  })())
})
