import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'

const source = await readFile(new URL('../src/routes/hosts.ts', import.meta.url), 'utf8')
const start = source.indexOf("  // 批量同步实例状态（仅节点所有者）")
const end = source.indexOf("  //", source.indexOf('  })', source.indexOf('const absence = client ?', start)) + 4)
assert.ok(start >= 0 && end > start)
const route = source.slice(start, end)
assert.match(route, /reconcileMissingInstanceStatus\(instance, client, err\)/)
const absenceBranch = route.slice(route.indexOf('const absence = client ?'))
assert.doesNotMatch(absenceBranch, /rollbackResources\(|closeHourlyBilling\(|status: 'deleted'/)
console.log('host sync confirmed-absence fail-closed guard passed')
