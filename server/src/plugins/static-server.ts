/**
 * 静态文件服务插件
 * 处理前端静态文件托管和 SPA 路由回退
 *
 * SEO：对公开可收录页面（/、/market、/help、/help/:slug）在服务端注入
 * 每路由的 title/description/OG/canonical/JSON-LD，让不执行 JS 的爬虫和
 * 消息预览 bot 也能拿到每页专属的元数据。SPA 客户端导航则由 usePageSeo 接管。
 */

import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify'
import fastifyStatic from '@fastify/static'
import { readFile } from 'fs/promises'
import { join } from 'path'
import { getHelpArticleBySlug } from '../db/help.js'
import { getSystemConfig } from '../db/system-config.js'

interface StaticServerOptions {
  clientDistPath: string
}

const SEO_SITE_URL_FALLBACK = 'https://incudal.di0.uk'
const SEO_HTML_CACHE_TTL_MS = 5 * 60 * 1000
const SEO_HTML_CACHE_MAX = 200

interface SeoRouteMeta {
  title: string
  description: string
  canonicalPath: string
  jsonLd: object[]
}

let siteUrlCache: { value: string; expiresAt: number } | null = null
let brandNameCache: { value: string; expiresAt: number } | null = null
const seoHtmlCache = new Map<string, { html: string; expiresAt: number }>()

function escapeHtmlText(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
}

async function getSeoSiteUrl(): Promise<string> {
  if (siteUrlCache && siteUrlCache.expiresAt > Date.now()) return siteUrlCache.value
  let value = SEO_SITE_URL_FALLBACK
  try {
    const configured = (await getSystemConfig('seo_site_url') || '').trim()
    if (configured) {
      const parsed = new URL(configured)
      if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
        value = parsed.toString().replace(/\/+$/, '')
      }
    }
  } catch { /* 配置读取失败时退回默认 */ }
  siteUrlCache = { value, expiresAt: Date.now() + 60_000 }
  return value
}

async function getBrandName(): Promise<string> {
  if (brandNameCache && brandNameCache.expiresAt > Date.now()) return brandNameCache.value
  let value = 'Incudal'
  try {
    const configured = (await getSystemConfig('brand_name') || '').trim()
    if (configured) value = configured
  } catch { /* 配置读取失败时退回默认 */ }
  brandNameCache = { value, expiresAt: Date.now() + 60_000 }
  return value
}

/** 去掉 Markdown/HTML 标记并压缩空白，用作 meta 描述 */
function toPlainText(markdown: string): string {
  return markdown
    .replace(/```[\s\S]*?```/g, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/!?\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/[#*_>`~|-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
}

function truncateDescription(text: string, max = 160): string {
  if (text.length <= max) return text
  return `${text.slice(0, max - 1).trimEnd()}…`
}

async function resolveSeoMeta(pathname: string): Promise<SeoRouteMeta | null> {
  const normalized = pathname !== '/' ? pathname.replace(/\/+$/, '') : '/'
  const siteUrl = await getSeoSiteUrl()
  const brand = await getBrandName()
  const baseDescription = '精选全球多节点 LXC / KVM 套餐，配置丰富、方案齐全，持续提供高性价比 NAT VPS 选择。'

  if (normalized === '/') {
    return {
      title: `基于 Incus 的低价 NAT VPS 平台 - ${brand}`,
      description: baseDescription,
      canonicalPath: '/',
      jsonLd: [
        { '@context': 'https://schema.org', '@type': 'WebSite', name: brand, url: `${siteUrl}/` },
        { '@context': 'https://schema.org', '@type': 'Organization', name: brand, url: `${siteUrl}/`, logo: `${siteUrl}/incudal_logo.webp` }
      ]
    }
  }

  if (normalized === '/market') {
    return {
      title: `套餐市场 - 基于 Incus 的低价 NAT VPS 平台 - ${brand}`,
      description: baseDescription,
      canonicalPath: '/market',
      jsonLd: []
    }
  }

  if (normalized === '/help') {
    return {
      title: `帮助中心 - ${brand}`,
      description: 'NAT VPS 使用教程、实例管理、网络配置、计费说明与常见问题解答。',
      canonicalPath: '/help',
      jsonLd: []
    }
  }

  if (normalized.startsWith('/help/')) {
    const slug = decodeURIComponent(normalized.slice('/help/'.length))
    if (!slug || slug.includes('/') || slug.length > 200) return null

    const article = await getHelpArticleBySlug(slug).catch(() => null)
    if (!article) return null

    const description = truncateDescription(toPlainText(article.content))
    const canonical = `${siteUrl}/help/${encodeURIComponent(article.slug)}`
    return {
      title: `${article.title} - ${brand} 帮助中心`,
      description: description || baseDescription,
      canonicalPath: `/help/${encodeURIComponent(article.slug)}`,
      jsonLd: [
        {
          '@context': 'https://schema.org',
          '@type': 'TechArticle',
          headline: article.title,
          description,
          dateModified: article.updated_at ? new Date(article.updated_at).toISOString() : undefined,
          inLanguage: 'zh-CN',
          author: { '@type': 'Organization', name: brand },
          publisher: { '@type': 'Organization', name: brand, logo: { '@type': 'ImageObject', url: `${siteUrl}/incudal_logo.webp` } },
          mainEntityOfPage: canonical
        }
      ]
    }
  }

  return null
}

function applySeoMetaToHtml(html: string, meta: SeoRouteMeta, siteUrl: string): string {
  const canonical = `${siteUrl}${meta.canonicalPath === '/' ? '/' : meta.canonicalPath}`
  let output = html

  // <title>
  output = output.replace(/<title>[\s\S]*?<\/title>/i, `<title>${escapeHtmlText(meta.title)}</title>`)

  // description
  output = output.replace(
    /<meta\s+name="description"\s+content="[^"]*"\s*\/?>/i,
    `<meta name="description" content="${escapeHtmlText(meta.description)}">`
  )

  // og:* / twitter:* / canonical：按属性逐个替换已存在的标签内容
  const ogOverrides: Array<[string, string]> = [
    ['og:title', meta.title],
    ['og:description', meta.description],
    ['og:url', canonical],
    ['og:image', `${siteUrl}/incudal_logo.webp`],
    ['twitter:title', meta.title],
    ['twitter:description', meta.description]
  ]
  for (const [property, content] of ogOverrides) {
    output = output.replace(
      new RegExp(`<meta\\s+property="${property}"\\s+content="[^"]*"\\s*/?>`, 'i'),
      `<meta property="${property}" content="${escapeHtmlText(content)}">`
    )
  }

  output = output.replace(
    /<link\s+rel="canonical"\s+href="[^"]*"\s*\/?>/i,
    `<link rel="canonical" href="${escapeHtmlText(canonical)}">`
  )

  if (meta.jsonLd.length > 0) {
    const jsonLd = meta.jsonLd
      .map(obj => `<script type="application/ld+json">${JSON.stringify(obj).replaceAll('</', '<\\/')}</script>`)
      .join('\n')
    output = output.replace(/<\/head>/i, `${jsonLd}\n</head>`)
  }

  return output
}

async function getEnhancedIndexHtml(pathname: string, baseHtml: string): Promise<string> {
  const cacheKey = pathname.split('?')[0]
  const cached = seoHtmlCache.get(cacheKey)
  if (cached && cached.expiresAt > Date.now()) return cached.html

  let html = baseHtml
  try {
    const meta = await resolveSeoMeta(cacheKey)
    if (meta) {
      html = applySeoMetaToHtml(baseHtml, meta, await getSeoSiteUrl())
    }
  } catch (error) {
    // meta 注入失败时退回原始 index.html，不影响页面可用性
    console.warn('[StaticServer] SEO meta injection failed:', error)
  }

  if (seoHtmlCache.size >= SEO_HTML_CACHE_MAX) {
    const oldest = seoHtmlCache.keys().next().value
    if (oldest !== undefined) seoHtmlCache.delete(oldest)
  }
  seoHtmlCache.set(cacheKey, { html, expiresAt: Date.now() + SEO_HTML_CACHE_TTL_MS })
  return html
}

export async function registerStaticServer(
  fastify: FastifyInstance,
  options: StaticServerOptions
): Promise<void> {
  const { clientDistPath } = options
  const indexHtmlPath = join(clientDistPath, 'index.html')
  let indexHtmlCache: string | null = null

  async function getIndexHtml(): Promise<string> {
    if (indexHtmlCache === null) {
      indexHtmlCache = await readFile(indexHtmlPath, 'utf8')
    }
    return indexHtmlCache
  }

  async function sendAppIndex(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    const baseHtml = await getIndexHtml()
    const pathname = request.url.split('?')[0]
    const html = await getEnhancedIndexHtml(pathname, baseHtml)

    reply
      .type('text/html; charset=utf-8')
      .header('Cache-Control', 'no-cache, must-revalidate')
      .send(html)
  }

  // 忽略 Cloudflare 的特殊路径（在 onRequest hook 中处理）
  fastify.addHook('onRequest', async (request, reply) => {
    if (request.url.startsWith('/cdn-cgi/')) {
      reply.code(204)
      reply.send()
      return reply
    }
  })

  // 显式处理根路径，返回 index.html
  fastify.get('/', async (request, reply) => {
    await sendAppIndex(request, reply)
  })

  // 注册静态文件服务
  await fastify.register(fastifyStatic, {
    root: clientDistPath,
    prefix: '/',
    setHeaders: (res, pathName) => {
      try {
        if (pathName.endsWith('.js')) {
          res.header('Content-Type', 'application/javascript; charset=utf-8')
        } else if (pathName.endsWith('.css')) {
          res.header('Content-Type', 'text/css; charset=utf-8')
        } else if (pathName.endsWith('.html')) {
          res.header('Content-Type', 'text/html; charset=utf-8')
          res.header('Cache-Control', 'no-cache, no-store, must-revalidate')
        }
        if (pathName.endsWith('theme-init.js')) {
          res.header('Cache-Control', 'no-cache, must-revalidate')
        } else if (!pathName.endsWith('.html')) {
          res.header('Cache-Control', 'public, max-age=31536000, immutable')
        }
      } catch (error) {
        // 忽略设置响应头时的错误
      }
    },
    list: false,
    index: false,
    wildcard: true
  })

  // 404 处理器
  fastify.setNotFoundHandler(async (request, reply) => {
    if (request.url.startsWith('/cdn-cgi/')) {
      return reply.code(204).send()
    }

    if (request.url.startsWith('/api/')) {
      return reply.code(404).send({ error: 'API 路由不存在' })
    }

    const hasExtension = /\.[a-zA-Z0-9]+$/.test(request.url.split('?')[0])
    if (hasExtension) {
      return reply.code(404).send({ error: '文件不存在' })
    }

    await sendAppIndex(request, reply)
  })
}
