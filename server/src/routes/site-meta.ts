/**
 * Search-engine discovery endpoints.
 *
 * These endpoints intentionally expose only public, crawlable pages. Authenticated
 * dashboards, admin screens, API endpoints, and user-specific resources must not
 * appear in the sitemap.
 */

import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { getHelpArticles, getSystemConfig } from '../db/index.js'

const DEFAULT_SITE_URL = 'https://incudal.di0.uk'
const DEFAULT_SITEMAP_PATH = '/sitemap.xml'
const BUILT_IN_HELP_SLUGS = [
  'platform-overview',
  'getting-started',
  'instance-management',
  'networking-basics',
  'hosting-tutorial',
  'hosting-publish',
  'hosting-earnings',
  'billing-basics',
  'common-issues'
] as const

interface SeoRuntimeSettings {
  siteUrl: string
  sitemapPath: string
  verificationPath: string
  verificationContent: string
  indexNowKey: string
}

let runtimeSettingsCache: { value: SeoRuntimeSettings; expiresAt: number } | null = null

function normalizeSiteUrl(value: string | null): string {
  if (!value) return DEFAULT_SITE_URL

  try {
    const url = new URL(value.trim())
    if (!['http:', 'https:'].includes(url.protocol)) return DEFAULT_SITE_URL
    url.hash = ''
    url.search = ''
    return url.toString().replace(/\/+$/, '')
  } catch {
    return DEFAULT_SITE_URL
  }
}

function normalizePath(value: string | null, fallback: string, allowEmpty = false): string {
  const path = (value || '').trim()
  if (allowEmpty && path === '') return ''
  if (
    !path.startsWith('/') ||
    path.startsWith('//') ||
    path.includes('..') ||
    path.includes('?') ||
    path.includes('#') ||
    path.startsWith('/api/') ||
    path.length > 200
  ) {
    return fallback
  }
  return path
}

function normalizeIndexNowKey(value: string | null): string {
  const key = (value || '').trim()
  return /^[A-Za-z0-9._-]{1,256}$/.test(key) ? key : ''
}

async function getSeoRuntimeSettings(): Promise<SeoRuntimeSettings> {
  if (runtimeSettingsCache && runtimeSettingsCache.expiresAt > Date.now()) {
    return runtimeSettingsCache.value
  }

  const [siteUrl, sitemapPath, verificationPath, verificationContent, indexNowKey] = await Promise.all([
    getSystemConfig('seo_site_url'),
    getSystemConfig('seo_sitemap_path'),
    getSystemConfig('seo_verification_path'),
    getSystemConfig('seo_verification_content'),
    getSystemConfig('seo_indexnow_key')
  ])

  const value = {
    siteUrl: normalizeSiteUrl(siteUrl),
    sitemapPath: normalizePath(sitemapPath, DEFAULT_SITEMAP_PATH),
    verificationPath: normalizePath(verificationPath, '', true),
    verificationContent: verificationContent || '',
    indexNowKey: normalizeIndexNowKey(indexNowKey)
  }
  runtimeSettingsCache = { value, expiresAt: Date.now() + 15_000 }
  return value
}

function escapeXml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&apos;')
}

function formatLastModified(value: string | undefined): string | null {
  if (!value) return null

  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? null : date.toISOString()
}

function buildUrlEntry(url: string, lastModified?: string): string {
  const lastmod = formatLastModified(lastModified)
  return [
    '  <url>',
    `    <loc>${escapeXml(url)}</loc>`,
    ...(lastmod ? [`    <lastmod>${lastmod}</lastmod>`] : []),
    '  </url>'
  ].join('\n')
}

async function buildSitemapBody(siteUrl: string): Promise<string> {
  const entries = new Map<string, string | undefined>([
    [`${siteUrl}/`, undefined],
    [`${siteUrl}/market`, undefined],
    [`${siteUrl}/help`, undefined]
  ])

  for (const slug of BUILT_IN_HELP_SLUGS) {
    entries.set(`${siteUrl}/help/${slug}`, undefined)
  }

  try {
    let page = 1
    let totalPages = 1

    do {
      const result = await getHelpArticles({
        page,
        pageSize: 1000,
        publishedOnly: true
      })

      for (const article of result.items) {
        entries.set(`${siteUrl}/help/${encodeURIComponent(article.slug)}`, article.updated_at)
      }

      totalPages = result.totalPages
      page += 1
    } while (page <= totalPages)
  } catch (error) {
    // The base sitemap remains useful during a database outage. Do not make
    // all search-engine discovery fail just because dynamic help content is
    // temporarily unavailable.
    console.warn('[SEO] Unable to load dynamic help articles for sitemap', error)
  }

  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
    ...Array.from(entries, ([url, lastModified]) => buildUrlEntry(url, lastModified)),
    '</urlset>',
    ''
  ].join('\n')
}

async function sendSitemap(reply: FastifyReply, settings: SeoRuntimeSettings): Promise<void> {
  reply
    .type('application/xml; charset=utf-8')
    .header('Cache-Control', 'public, max-age=900')
    .send(await buildSitemapBody(settings.siteUrl))
}

/**
 * Handles configured SEO files before the static server or SPA fallback. The
 * app registers this hook at the root level so custom paths work as well.
 */
export async function handleSeoMetaRequest(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  const pathname = request.url.split('?')[0]
  if (!/\.(?:html|txt|xml)$/i.test(pathname)) return

  const settings = await getSeoRuntimeSettings()
  if (settings.verificationPath && pathname === settings.verificationPath) {
    const contentType = pathname.endsWith('.html')
      ? 'text/html; charset=utf-8'
      : 'text/plain; charset=utf-8'
    reply
      .type(contentType)
      .header('Cache-Control', 'public, max-age=3600')
      .send(settings.verificationContent)
    return
  }

  if (settings.indexNowKey && pathname === `/${settings.indexNowKey}.txt`) {
    reply
      .type('text/plain; charset=utf-8')
      .header('Cache-Control', 'public, max-age=3600')
      .send(settings.indexNowKey)
    return
  }

  if (settings.sitemapPath !== DEFAULT_SITEMAP_PATH && pathname === settings.sitemapPath) {
    await sendSitemap(reply, settings)
  }
}

export default async function siteMetaRoutes(fastify: FastifyInstance): Promise<void> {

  fastify.get('/robots.txt', async (_request, reply) => {
    const settings = await getSeoRuntimeSettings()
    const body = [
      'User-agent: *',
      'Allow: /',
      'Disallow: /admin',
      'Disallow: /dashboard',
      'Disallow: /instances',
      'Disallow: /profile',
      'Disallow: /wallet',
      'Disallow: /inbox',
      'Disallow: /terminal',
      'Disallow: /tickets',
      'Disallow: /api/',
      'Disallow: /login',
      'Disallow: /register',
      'Disallow: /forgot-password',
      '',
      `Sitemap: ${new URL(settings.sitemapPath, `${settings.siteUrl}/`).toString()}`,
      ''
    ].join('\n')

    return reply
      .type('text/plain; charset=utf-8')
      .header('Cache-Control', 'public, max-age=3600')
      .send(body)
  })

  fastify.get('/sitemap.xml', async (_request, reply) => {
    return sendSitemap(reply, await getSeoRuntimeSettings())
  })
}
