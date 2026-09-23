const DEFAULT_SITE_URL = 'https://incudal.di0.uk'
const DEFAULT_SITEMAP_PATH = '/sitemap.xml'

const configuredSiteUrl = (process.env.SITE_URL || DEFAULT_SITE_URL).replace(/\/+$/, '')

async function loadPublicSeoConfig() {
  try {
    const response = await fetch(`${configuredSiteUrl}/api/system-config/public`)
    if (!response.ok) return null
    return await response.json()
  } catch {
    return null
  }
}

function log(message) {
  process.stdout.write(`${message}\n`)
}

try {
  const publicConfig = await loadPublicSeoConfig()
  const siteUrl = (process.env.SITE_URL || publicConfig?.seoSiteUrl || configuredSiteUrl).replace(/\/+$/, '')
  const sitemapPath = process.env.SITEMAP_PATH || publicConfig?.seoSitemapPath || DEFAULT_SITEMAP_PATH
  const indexNowKey = process.env.INDEXNOW_KEY || publicConfig?.seoIndexNowKey || ''
  const endpoint = process.env.INDEXNOW_ENDPOINT || publicConfig?.seoIndexNowEndpoint || ''
  if (!indexNowKey || !endpoint) {
    log('IndexNow skipped: configure seo_indexnow_key and seo_indexnow_endpoint first')
    process.exit(0)
  }

  const sitemapUrl = new URL(sitemapPath, `${siteUrl}/`).toString()
  const keyLocation = new URL(`/${indexNowKey}.txt`, `${siteUrl}/`).toString()

  const sitemapResponse = await fetch(sitemapUrl)
  if (!sitemapResponse.ok) {
    log(`IndexNow skipped: sitemap returned HTTP ${sitemapResponse.status} (${sitemapUrl})`)
    process.exit(0)
  }

  const sitemapXml = await sitemapResponse.text()
  const urls = [...sitemapXml.matchAll(/<loc>\s*([^<]+?)\s*<\/loc>/g)]
    .map(match => match[1].trim())
    .filter(Boolean)
    .slice(0, 10_000)

  if (urls.length === 0) {
    log('IndexNow skipped: sitemap contains no URLs')
    process.exit(0)
  }

  const response = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
    body: JSON.stringify({
      host: new URL(siteUrl).host,
      key: indexNowKey,
      keyLocation,
      urlList: urls
    })
  })

  if (!response.ok) {
    throw new Error(`IndexNow returned HTTP ${response.status}`)
  }

  log(`IndexNow submitted ${urls.length} URL(s) for ${siteUrl}`)
} catch (error) {
  console.error(`IndexNow notification failed: ${error instanceof Error ? error.message : String(error)}`)
  process.exitCode = 1
}
