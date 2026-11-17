import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

const router = readFileSync(new URL('../src/router/index.ts', import.meta.url), 'utf8')
const route = router.match(/\{\s*\/\/ 敏感操作邮件确认链接落地页[\s\S]*?\n {2}\}/)?.[0]
assert.ok(route, 'confirmation route exists')
assert.match(route, /name: 'confirm-operation'/)
assert.doesNotMatch(route, /guest:\s*true|requiresAuth:\s*true/, 'confirmation links must work for both signed-in and signed-out users')
const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
assert.match(app, /noLayoutRoutes[^\n]*'confirm-operation'/, 'confirmation page must not be wrapped in the authenticated layout')
console.log('confirmation route regression checks passed')
