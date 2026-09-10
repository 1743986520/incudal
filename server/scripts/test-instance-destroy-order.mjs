import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'

async function section(file, startToken, endToken) {
  const source = await readFile(new URL(`../${file}`, import.meta.url), 'utf8')
  const start = source.indexOf(startToken)
  assert.notEqual(start, -1, `${file}: missing section start`)
  const end = source.indexOf(endToken, start)
  assert.notEqual(end, -1, `${file}: missing section end`)
  return source.slice(start, end)
}

function position(source, token, label) {
  const index = source.indexOf(token)
  assert.notEqual(index, -1, `${label}: missing ${token}`)
  return index
}

function assertRemoteFirst(source, label) {
  const remoteDelete = position(source, 'await deleteInstance(', label)
  for (const [token, action] of [
    ['balance: { increment:', 'refund'],
    ['prisma.snapshot.deleteMany', 'related data cleanup'],
    ['db.rollbackResources(', 'quota/resource release']
  ]) {
    const actionPosition = source.indexOf(token)
    if (actionPosition !== -1) {
      assert.ok(remoteDelete < actionPosition, `${label}: ${action} must happen after Incus deletion`)
    }
  }
}

const userBatch = await section(
  'src/routes/instance-destroy.ts',
  'async function executeDestroyForUser(',
  'export default async function instanceDestroyRoutes'
)
assertRemoteFirst(userBatch, 'batch user destroy')
assert.match(userBatch, /if \(!host\) \{\s*throw new Error\('Host not found'\)/)
assert.match(userBatch, /catch \(error\) \{[\s\S]*?restoreClaimedInstanceStatus/)

const userSingle = await section(
  'src/routes/instance-destroy.ts',
  "fastify.post<{ Params: { id: string }; Querystring: { feeWaiver?: string } }>('/:id/destroy'",
  '\n  })\n}'
)
assertRemoteFirst(userSingle, 'single user destroy')
assert.match(userSingle, /if \(!host\) \{\s*throw new Error\('Host not found'\)/)
assert.match(userSingle, /catch \(error\) \{[\s\S]*?restoreClaimedInstanceStatus/)

const genericDelete = await section(
  'src/routes/instances.ts',
  '  // 删除实例\n',
  '  // 添加端口映射'
)
assertRemoteFirst(genericDelete, 'generic user/admin DELETE')
assert.doesNotMatch(genericDelete, /catch \(incusError\) \{[\s\S]{0,300}?Incus 删除实例失败[\s\S]{0,100}?\}\s*\}\s*\n\s*\/\/ ===== 8/)
assert.match(genericDelete, /if \(!incusDeleted\) \{[\s\S]*?status: instance\.status/)

const adminDelete = await section(
  'src/routes/admin-billing.ts',
  '// POST /api/admin/instances/:id/delete-and-refund',
  '// ==================== 管理员应用AFF优惠码'
)
assertRemoteFirst(adminDelete, 'admin delete-and-refund')
assert.match(adminDelete, /if \(!host\) \{[\s\S]*?Host not found/)

const hostBatchDelete = await section(
  'src/routes/hosts.ts',
  'const results: { id: number; name: string; success: boolean; error?: string; refundAmount?: number }[] = []',
  '// 删除宿主机（管理员或节点所有者）'
)
const hostRemoteDelete = position(hostBatchDelete, 'await incusInstanceOperations.deleteInstance(', 'host batch delete')
assert.ok(hostRemoteDelete < position(hostBatchDelete, 'await deleteProxySite(', 'host batch delete'), 'host batch delete: related data cleanup must happen after Incus deletion')
assert.ok(hostRemoteDelete < position(hostBatchDelete, 'await db.rollbackResources(', 'host batch delete'), 'host batch delete: quota/resource release must happen after Incus deletion')
assert.ok(hostRemoteDelete < position(hostBatchDelete, 'balance: { increment:', 'host batch delete'), 'host batch delete: refund must happen after Incus deletion')
assert.match(hostBatchDelete, /if \(!databaseOnly\) \{\s*if \(!client \|\| !incusInstanceOperations\) \{[\s\S]*?throw new Error/)

console.log('instance destroy ordering regression test passed')
