/**
 * 支付回调 form-urlencoded 解析器测试
 *
 * 覆盖：易支付 form 通知的解析、+ 与百分号解码规范，
 * 以及解析器仅在注册插件作用域内生效（其余路由仍拒绝 form 请求体）。
 *
 * 运行：pnpm run test:payment-form-callback
 */

import assert from 'node:assert/strict'
import test from 'node:test'
import Fastify from 'fastify'

import {
  parseFormUrlencodedBody,
  registerFormUrlencodedParser
} from '../src/lib/form-urlencoded.js'

test('parseFormUrlencodedBody 解析易支付通知参数', () => {
  const body = 'pid=1001&trade_status=TRADE_SUCCESS&out_trade_no=R20260919001&money=1.00&sign=abc123&sign_type=MD5'
  assert.deepEqual(parseFormUrlencodedBody(body), {
    pid: '1001',
    trade_status: 'TRADE_SUCCESS',
    out_trade_no: 'R20260919001',
    money: '1.00',
    sign: 'abc123',
    sign_type: 'MD5'
  })
})

test('parseFormUrlencodedBody 按 form 规范解码 + 与百分号编码', () => {
  const parsed = parseFormUrlencodedBody('name=%2Bplus+b+space%20s&memo=%E4%B8%AD%E6%96%87')
  assert.equal(parsed.name, '+plus b space s')
  assert.equal(parsed.memo, '中文')
})

test('form 解析器仅在注册插件作用域内生效', async () => {
  const app = Fastify()

  // 外层路由未注册解析器：form 请求保持 415
  app.post('/outside', async request => ({ body: request.body }))

  await app.register(async inner => {
    registerFormUrlencodedParser(inner)
    inner.post('/inside', async request => ({ body: request.body }))
  })

  const outside = await app.inject({
    method: 'POST',
    url: '/outside',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    payload: 'a=1'
  })
  assert.equal(outside.statusCode, 415)

  const insideForm = await app.inject({
    method: 'POST',
    url: '/inside',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    payload: 'out_trade_no=R1&money=1.00'
  })
  assert.equal(insideForm.statusCode, 200)
  assert.deepEqual(insideForm.json().body, { out_trade_no: 'R1', money: '1.00' })

  // 同一路由的 JSON 请求不受影响（默认 JSON 解析器与 form 解析器共存）
  const insideJson = await app.inject({
    method: 'POST',
    url: '/inside',
    headers: { 'content-type': 'application/json' },
    payload: { out_trade_no: 'R1' }
  })
  assert.equal(insideJson.statusCode, 200)
  assert.deepEqual(insideJson.json().body, { out_trade_no: 'R1' })

  await app.close()
})
