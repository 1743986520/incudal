import assert from 'node:assert/strict'
import { assertDatabaseResetAllowed, DATABASE_RESET_CONFIRMATION_TOKEN } from '../src/lib/database-reset-guard.js'

assert.throws(
  () => assertDatabaseResetAllowed({
    shouldReset: true,
    nodeEnv: 'production',
    confirmation: undefined
  }),
  /RESET_DATABASE_CONFIRMATION/
)

assert.throws(
  () => assertDatabaseResetAllowed({
    shouldReset: true,
    nodeEnv: 'production',
    confirmation: 'yes'
  }),
  /RESET_DATABASE_CONFIRMATION/
)

assert.doesNotThrow(() => assertDatabaseResetAllowed({
  shouldReset: true,
  nodeEnv: 'production',
  confirmation: DATABASE_RESET_CONFIRMATION_TOKEN
}))

assert.doesNotThrow(() => assertDatabaseResetAllowed({
  shouldReset: true,
  nodeEnv: 'development',
  confirmation: undefined
}))

assert.doesNotThrow(() => assertDatabaseResetAllowed({
  shouldReset: false,
  nodeEnv: 'production',
  confirmation: undefined
}))

console.log('database reset guard: ok')
