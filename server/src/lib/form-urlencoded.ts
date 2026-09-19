/**
 * application/x-www-form-urlencoded 请求体解析
 *
 * 易支付（yipay）等支付网关的异步通知普遍使用 form 编码的 POST 回调，
 * 而 Fastify 默认只解析 JSON 与 multipart。此解析器供接收支付回调的
 * 路由插件注册；解析按 form-urlencoded 规范进行（+ 转空格、百分号解码）。
 */

import type { FastifyInstance } from 'fastify'

export function parseFormUrlencodedBody(body: string): Record<string, string> {
  const params = new URLSearchParams(body)
  const parsed: Record<string, string> = {}
  for (const [key, value] of params) {
    parsed[key] = value
  }
  return parsed
}

/**
 * 在当前（插件封装）作用域内注册 form 解析器。
 * 只应在接收支付回调的路由插件中调用，避免全局扩大 API 接受的请求体类型。
 */
export function registerFormUrlencodedParser(app: FastifyInstance): void {
  app.addContentTypeParser('application/x-www-form-urlencoded', { parseAs: 'string' }, (_request, body, done) => {
    try {
      done(null, parseFormUrlencodedBody(body as string))
    } catch (error) {
      done(error instanceof Error ? error : new Error(String(error)))
    }
  })
}
