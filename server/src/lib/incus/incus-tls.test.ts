import assert from 'node:assert/strict'
import { X509Certificate } from 'node:crypto'
import test from 'node:test'

import {
  assertAllowedHostUrl,
  buildIncusTlsConnectOptions,
  certificateFingerprint,
  isPublicHostAddress,
  normalizeCertificatePem,
  resolveIncusTarget
} from './incus-tls.js'

const certificate = `-----BEGIN CERTIFICATE-----
MIIDITCCAgmgAwIBAgIUbG4wPtA5lVld1pWgfOCOjR+dK3swDQYJKoZIhvcNAQEL
BQAwFTETMBEGA1UEAwwKaW5jdXMtdGVzdDAeFw0yNjA5MTIxMTQ2MDBaFw0zNjA5
MDkxMTQ2MDBaMBUxEzARBgNVBAMMCmluY3VzLXRlc3QwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCzE55lb0+c4NGQj0aWSoMq9A/m6VznVbdgbECxmAXl
Ue+wmcULUljv6k5ZkHF0GulTMX4+zNHKtvaGfT6jECxXKRiug7wxUyzZh6JpJJK0
Aw85cNL8/IYI/wXQofPfEZJ1bUPSZ2FRo3DvAh+nXAtP8hcaPgFAX0egzjxOrzje
W4QC3k6NRAhdwTJfRCq1VCVrfiUuAFENA/+C23qN5HsTDdVoYt0QrUp1qUYzQPyc
HLU1nz3Pkh0CLYSMeTnrVWoBX3gxrIuj3/tywiI+mRvmJOOUkwVsjUcm6XSAiSR6
O4ptz9tkCYLYIKuciQxIqUx2aXIh7sOaWKx/04+wTqKrAgMBAAGjaTBnMB0GA1Ud
DgQWBBQUf4W4x7iUu/Jrov0H+NOBSzFsCjAfBgNVHSMEGDAWgBQUf4W4x7iUu/Jr
ov0H+NOBSzFsCjAPBgNVHRMBAf8EBTADAQH/MBQGA1UdEQQNMAuCCWxvY2FsaG9z
dDANBgkqhkiG9w0BAQsFAAOCAQEAUu0Dh5Aklk63rKfGTJsmyIaemUZMCeoO/HCc
e8+SiSzadDoMjdqOrrU7drOhgwwy2CHUDkITo6CxlICwmBPph6JKC5mhat/jd7d1
F9tsrSyq8yVuLFFKe5cxWmULfjt2fkqWukRGpvBzlOxJmyUO897RsS+uXJPiVJdC
fmG7Yr2X/pODxP1eofOPlRzJ6++fZYUtcKGqG2IDxu7QjRnZMKxvMs5D7TEuyYd2
25efYhOB6S28lSvyJq0Avzc8syQvyLu4cJ6T//gKbKDSQYeMhYXy8213AxhX7uBl
Sn11mwPdzEspwCNivdob4/JpR5QqpYw/ZAIiVXec9xKy5OroCA==
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

test('accepts a pinned peer certificate even when its hostname does not match its SAN', () => {
  const fingerprint = certificateFingerprint(certificate)
  const options = buildIncusTlsConnectOptions({ ca: certificate, fingerprint })
  const checkServerIdentity = options.checkServerIdentity
  assert.ok(checkServerIdentity)

  const raw = new X509Certificate(certificate).raw
  assert.equal(checkServerIdentity('management.example', { raw } as never), undefined)
  assert.match(
    checkServerIdentity('management.example', { raw: Buffer.from('different certificate') } as never)?.message || '',
    /does not match/
  )
})
