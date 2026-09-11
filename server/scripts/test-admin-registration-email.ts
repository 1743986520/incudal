import assert from 'node:assert/strict'
import { resolveRegistrationRole } from '../src/lib/registration-role.js'

assert.equal(resolveRegistrationRole({
  email: 'owner@example.com',
  adminRegistrationEmails: '@example.com',
  emailVerified: false
}), 'user')

assert.equal(resolveRegistrationRole({
  email: 'owner@example.com',
  adminRegistrationEmails: '@example.com',
  emailVerified: true
}), 'admin')

assert.equal(resolveRegistrationRole({
  email: 'user@other.example.com',
  adminRegistrationEmails: '@example.com',
  emailVerified: true
}), 'user')

assert.equal(resolveRegistrationRole({
  email: 'user@notexample.com',
  adminRegistrationEmails: 'example.com',
  emailVerified: true
}), 'user')

assert.equal(resolveRegistrationRole({
  email: 'USER@EXAMPLE.COM',
  adminRegistrationEmails: 'example.com; @second.example',
  emailVerified: true
}), 'admin')

// Legacy full-address entries must not silently become domain-wide grants.
assert.equal(resolveRegistrationRole({
  email: 'another@example.com',
  adminRegistrationEmails: 'owner@example.com',
  emailVerified: true
}), 'user')

console.log('admin registration email security: ok')
