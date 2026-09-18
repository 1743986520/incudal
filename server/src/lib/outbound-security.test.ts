import assert from 'node:assert/strict'
import test from 'node:test'

import { isIpPrivateOrReserved } from './outbound-security.js'

test('treats IPv4-mapped IPv6 in hex form as its embedded IPv4 address', () => {
  // ::ffff:c0a8:0101 => 192.168.1.1（私网）
  assert.equal(isIpPrivateOrReserved('::ffff:c0a8:0101'), true)
  // ::ffff:0a00:0001 => 10.0.0.1（私网）
  assert.equal(isIpPrivateOrReserved('::ffff:0a00:0001'), true)
  // ::ffff:7f00:1 => 127.0.0.1（环回）
  assert.equal(isIpPrivateOrReserved('::ffff:7f00:1'), true)
  // 公网映射地址保持放行（点分与十六进制形式一致）
  assert.equal(isIpPrivateOrReserved('::ffff:8.8.8.8'), false)
  assert.equal(isIpPrivateOrReserved('::ffff:0808:0808'), false)
})

test('rejects NAT64 and IPv4-compatible IPv6 ranges', () => {
  // NAT64 前缀内嵌的 IPv4 地址可能指向内网
  assert.equal(isIpPrivateOrReserved('64:ff9b::c0a8:0101'), true)
  assert.equal(isIpPrivateOrReserved('64:ff9b:1::1'), true)
  // ::/96 IPv4-compatible（十六进制与点分形式）
  assert.equal(isIpPrivateOrReserved('::c0a8:0101'), true)
  assert.equal(isIpPrivateOrReserved('::192.168.1.1'), true)
  // 2001::/23（含 Teredo，内嵌 IPv4）
  assert.equal(isIpPrivateOrReserved('2001::1'), true)
})

test('keeps ordinary public and private literal behaviour', () => {
  assert.equal(isIpPrivateOrReserved('8.8.8.8'), false)
  assert.equal(isIpPrivateOrReserved('2606:4700:4700::1111'), false)
  assert.equal(isIpPrivateOrReserved('192.168.1.1'), true)
  assert.equal(isIpPrivateOrReserved('10.0.0.1'), true)
  assert.equal(isIpPrivateOrReserved('169.254.169.254'), true)
  assert.equal(isIpPrivateOrReserved('::1'), true)
  assert.equal(isIpPrivateOrReserved('::'), true)
  assert.equal(isIpPrivateOrReserved('fd00::1'), true)
  assert.equal(isIpPrivateOrReserved('fe80::1'), true)
  assert.equal(isIpPrivateOrReserved('ff02::1'), true)
  // 无法解析的输入按保留地址处理（fail closed）
  assert.equal(isIpPrivateOrReserved('not-an-ip'), true)
})
