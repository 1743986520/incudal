/**
 * Search-engine discovery endpoints.
 *
 * These endpoints intentionally expose only public, crawlable pages. Authenticated
 * dashboards, admin screens, API endpoints, and user-specific resources must not
 * appear in the sitemap.
 */

import type { FastifyInstance } from 'fastify'
import { getHelpArticles } from '../db/index.js'

const DEFAULT_SITE_URL = 'https://incudal.di0.uk'
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

function getSiteUrl(): string {
  return (process.env.SITE_URL || DEFAULT_SITE_URL).trim().replace(/\/+$/, '')
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

export default async function siteMetaRoutes(fastify: FastifyInstance): Promise<void> {
  fastify.get('/robots.txt', async (_request, reply) => {
    const siteUrl = getSiteUrl()
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
      `Sitemap: ${siteUrl}/sitemap.xml`,
      ''
    ].join('\n')

    return reply
      .type('text/plain; charset=utf-8')
      .header('Cache-Control', 'public, max-age=3600')
      .send(body)
  })

  fastify.get('/sitemap.xml', async (_request, reply) => {
    const siteUrl = getSiteUrl()
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
      fastify.log.warn({ err: error }, 'Unable to load dynamic help articles for sitemap')
    }

    const body = [
      '<?xml version="1.0" encoding="UTF-8"?>',
      '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
      ...Array.from(entries, ([url, lastModified]) => buildUrlEntry(url, lastModified)),
      '</urlset>',
      ''
    ].join('\n')

    return reply
      .type('application/xml; charset=utf-8')
      .header('Cache-Control', 'public, max-age=900')
      .send(body)
  })
}
