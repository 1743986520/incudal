const TRACKING_SCRIPT_SELECTOR = 'script[data-incudal-seo-tracking="true"]'

interface TrackingOptions {
  enabled: boolean
  scriptUrl: string
  trackingId: string | null
}

interface TrackingWindow extends Window {
  dataLayer?: unknown[]
  gtag?: (...args: unknown[]) => void
}

/**
 * Load a configurable gtag-compatible tracker without allowing arbitrary
 * inline script content from the administrator settings.
 */
export function applySeoTracking(options: TrackingOptions): void {
  if (typeof window === 'undefined' || typeof document === 'undefined') return

  document.querySelectorAll(TRACKING_SCRIPT_SELECTOR).forEach(element => element.remove())

  const trackingId = options.trackingId?.trim()
  if (!options.enabled || !trackingId) return

  let scriptUrl: URL
  try {
    scriptUrl = new URL(options.scriptUrl, window.location.origin)
    if (!['http:', 'https:'].includes(scriptUrl.protocol)) return
  } catch {
    return
  }

  const trackingWindow = window as TrackingWindow
  trackingWindow.dataLayer = trackingWindow.dataLayer || []
  trackingWindow.gtag = function gtag() {
    trackingWindow.dataLayer?.push(arguments)
  }
  trackingWindow.gtag('js', new Date())
  trackingWindow.gtag('config', trackingId)

  scriptUrl.searchParams.set('id', trackingId)
  const script = document.createElement('script')
  script.async = true
  script.src = scriptUrl.toString()
  script.dataset.incudalSeoTracking = 'true'
  document.head.appendChild(script)
}
