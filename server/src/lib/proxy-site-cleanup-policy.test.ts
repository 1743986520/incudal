import assert from 'node:assert/strict'
import test from 'node:test'
import { canCleanupTransferredSite, canUpdateSyncedSite } from './proxy-site-cleanup-policy.js'

const timestamp = new Date('2026-01-01T00:00:00.000Z')
const site = {
  id: 7, instanceId: 10, hostId: 20, domain: 'example.test', updatedAt: timestamp,
  status: 'active', enabled: true, instance: { status: 'running', hostId: 20, ipv4: '10.0.0.2' }
}
const transferred = { id: 7, instanceId: 10, hostId: 20, domain: 'example.test', updatedAt: timestamp.toISOString() }
const synced = { id: 7, instanceId: 10, hostId: 20, domain: 'example.test', ipv4: '10.0.0.2' }

test('transfer cleanup refuses changed ownership, replacement and new-owner edits', () => {
  assert.equal(canCleanupTransferredSite(site, transferred), true)
  assert.equal(canCleanupTransferredSite(null, transferred), false)
  assert.equal(canCleanupTransferredSite({ ...site, id: 8 }, transferred), false)
  assert.equal(canCleanupTransferredSite({ ...site, updatedAt: new Date(timestamp.getTime() + 1) }, transferred), false)
  assert.equal(canCleanupTransferredSite({ ...site, hostId: 21 }, transferred), false)
  assert.equal(canCleanupTransferredSite({ ...site, instance: { ...site.instance, status: 'deleting' } }, transferred), false)
})

test('stale sync cannot recreate a moved, changed, disabled or deleting site', () => {
  assert.equal(canUpdateSyncedSite(site, synced), true)
  assert.equal(canUpdateSyncedSite({ ...site, domain: 'other.test' }, synced), false)
  assert.equal(canUpdateSyncedSite({ ...site, enabled: false }, synced), false)
  assert.equal(canUpdateSyncedSite({ ...site, instance: { ...site.instance, ipv4: '10.0.0.3' } }, synced), false)
  assert.equal(canUpdateSyncedSite({ ...site, instance: { ...site.instance, status: 'deleting' } }, synced), false)
})
