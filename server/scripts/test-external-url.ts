import assert from 'node:assert/strict'
import {
  getSafeHttpUrl,
  getSafeTelegramUrl,
  validateHttpUrl,
  validateOptionalHttpUrl,
  validateOptionalTelegramUrl
} from '../src/lib/external-url.js'

function assertInvalid(result: { valid: boolean }): void {
  assert.equal(result.valid, false)
}

for (const value of [
  'javascript:alert(1)',
  'JaVaScRiPt:alert(1)',
  'data:text/html,<script>alert(1)</script>',
  'vbscript:msgbox(1)',
  '//evil.example/path',
  'https://example.com/\njavascript:alert(1)',
  'not a URL',
  'https://'
]) {
  assertInvalid(validateHttpUrl(value))
  assert.equal(getSafeHttpUrl(value), null)
}

assert.deepEqual(validateHttpUrl('  HTTPS://Example.com/status  '), {
  valid: true,
  value: 'https://example.com/status'
})
assert.deepEqual(validateOptionalHttpUrl(null), { valid: true, value: null })
assert.deepEqual(validateOptionalHttpUrl('   '), { valid: true, value: null })

for (const value of [
  'http://t.me/group',
  'https://telegram.me/group',
  'https://t.me.evil.example/group',
  'https://t.me',
  'https://t.me/',
  'javascript:alert(1)'
]) {
  assertInvalid(validateOptionalTelegramUrl(value))
  assert.equal(getSafeTelegramUrl(value), null)
}

assert.deepEqual(validateOptionalTelegramUrl(' HTTPS://T.ME/incudal_com '), {
  valid: true,
  value: 'https://t.me/incudal_com'
})
assert.equal(getSafeTelegramUrl(''), null)

console.log('external-url self-test passed')
