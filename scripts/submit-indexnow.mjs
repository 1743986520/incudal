const DEFAULT_SITE_URL = 'https://incudal.di0.uk'
const DEFAULT_INDEXNOW_KEY = '6d5f0c0e9be241a5b35e5d2c6f6a49d1'

const siteUrl = (process.env.SITE_URL || DEFAULT_SITE_URL).replace(/\/+$/, '')
const indexNowKey = process.env.INDEXNOW_KEY || DEFAULT_INDEXNOW_KEY
const sitemapUrl = `${siteUrl}/sitemap.xml`
const keyLocation = `${siteUrl}/${indexNowKey}.txt`

function log(message) {
  process.stdout.write(`${message}\n`)
}

try {
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

  const response = await fetch('https://api.indexnow.org/IndexNow', {
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
