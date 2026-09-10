import assert from 'node:assert/strict'
import test from 'node:test'

import {
  assertAllowedHostUrl,
  certificateFingerprint,
  isPublicHostAddress,
  normalizeCertificatePem,
  resolveIncusTarget
} from './incus-tls.js'

const certificate = `-----BEGIN CERTIFICATE-----
MIIBfTCCASOgAwIBAgIUX39Puj3Yhi5qx/DewM5Bbsme6gkwCgYIKoZIzj0EAwIw
EjEQMA4GA1UEAwwHaW5jdXMtdDAeFw0yNjA5MDkwMDAwMDBaFw0yNzA5MDkwMDAw
MDBaMBIxEDAOBgNVBAMMB2luY3VzLXQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AATiQCMO57K0q2L9Klp6aEwNN7Z4RXz3v4s9s9Ej1OboJt8tXsbmj2qPiFkGTwnc
Z70lxFZGJXSj8bHCsY2F4e4Yo1MwUTAdBgNVHQ4EFgQUUT4g7obKK8WbS4VMmb/y
ELtOAhMwHwYDVR0jBBgwFoAUUT4g7obKK8WbS4VMmb/yELtOAhMwDwYDVR0TAQH/
BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEAjzgIh9NRjcxuXfsIaPqsN5Okn5BT
1xPSJs/nBoIm5JICIFoqAi8Yfqh5ynNboY4X5QyvyJ+8u+ItF7KFKHaD5j+J
-----END CERTIFICATE-----`

test('rejects IPv4-mapped private IPv6 and special ranges', () => {
  for (const address of [
    '::ffff:127.0.0.1',
    '::ffff:0a00:0001',
    '::ffff:c0a8:0101',
    '64:ff9b::7f00:1',
    '2001:db8::1',
    '100.64.0.1',
    '192.0.2.1'
  ]) assert.equal(isPublicHostAddress(address), false, address)
  assert.equal(isPublicHostAddress('8.8.8.8'), true)
  assert.equal(isPublicHostAddress('2606:4700:4700::1111'), true)
})

test('rejects rebinding answers when any resolved address is private', async () => {
  await assert.rejects(
    assertAllowedHostUrl('https://host.example:8443', false, async () => ['8.8.8.8', '127.0.0.1']),
    /publicly routable/
  )
})

test('resolves once and rewrites the connection URL to the pinned address', async () => {
  const target = await resolveIncusTarget('https://host.example:8443', false, async () => ['8.8.8.8'])
  assert.equal(target.url, 'https://8.8.8.8:8443')
  assert.equal(target.servername, 'host.example')
})

test('normalizes certificates and produces stable SHA-256 pins', () => {
  const normalized = normalizeCertificatePem(certificate)
  assert.match(normalized, /^-----BEGIN CERTIFICATE-----/)
  assert.match(certificateFingerprint(normalized), /^[a-f0-9]{64}$/)
})
