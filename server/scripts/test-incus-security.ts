import assert from 'node:assert/strict'
import test from 'node:test'

import {
  assertAllowedHostUrl,
  assertServerManagedCertificatePaths,
  buildIncusTlsConnectOptions,
  panelCertificatePaths
} from '../src/lib/incus/incus-tls.js'

test('ordinary host creators cannot target loopback or private addresses', async () => {
  for (const url of [
    'https://127.0.0.1:8443',
    'https://[::1]:8443',
    'https://10.0.0.2:8443',
    'https://172.16.0.2:8443',
    'https://192.168.1.2:8443',
    'https://169.254.169.254:8443'
  ]) {
    await assert.rejects(() => assertAllowedHostUrl(url, false), /publicly routable/)
  }
})

test('ordinary host creators cannot use DNS names resolving to private addresses', async () => {
  await assert.rejects(
    () => assertAllowedHostUrl('https://internal.example:8443', false, async () => ['127.0.0.1']),
    /publicly routable/
  )
})

test('admins may explicitly register internal hosts', async () => {
  await assert.doesNotReject(() => assertAllowedHostUrl('https://127.0.0.1:8443', true))
})

test('certificate paths are limited to the server-managed panel certificate pair', () => {
  const managed = panelCertificatePaths()
  assert.doesNotThrow(() => assertServerManagedCertificatePaths(managed.certPath, managed.keyPath))
  assert.throws(() => assertServerManagedCertificatePaths('/etc/passwd', managed.keyPath), /server-managed/)
  assert.throws(() => assertServerManagedCertificatePaths(managed.certPath, '/tmp/attacker.key'), /server-managed/)
})

test('Incus TLS verifies peers by default', () => {
  const options = buildIncusTlsConnectOptions()
  assert.equal(options.rejectUnauthorized, true)
  assert.equal(options.checkServerIdentity, undefined)
})

test('explicit CA trust keeps self-signed Incus nodes usable', () => {
  const options = buildIncusTlsConnectOptions({ ca: Buffer.from('trusted-ca') })
  assert.equal(options.rejectUnauthorized, true)
  assert.deepEqual(options.ca, Buffer.from('trusted-ca'))
})
