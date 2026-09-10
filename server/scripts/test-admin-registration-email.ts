import assert from 'node:assert/strict'
import { resolveRegistrationRole } from '../src/lib/registration-role.js'

assert.equal(resolveRegistrationRole({
  email: 'owner@example.com',
  adminRegistrationEmails: 'owner@example.com',
  emailVerified: false
}), 'user')

assert.equal(resolveRegistrationRole({
  email: 'owner@example.com',
  adminRegistrationEmails: 'owner@example.com',
  emailVerified: true
}), 'admin')

assert.equal(resolveRegistrationRole({
  email: 'user@example.com',
  adminRegistrationEmails: 'owner@example.com',
  emailVerified: true
}), 'user')

console.log('admin registration email security: ok')
