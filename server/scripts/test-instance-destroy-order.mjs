import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'

async function section(file, startToken, endToken) {
  const source = (await readFile(new URL(`../${file}`, import.meta.url), 'utf8')).replace(/\r\n/g, '\n')
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
  // Routes now use the stronger helper that confirms Incus returns 404 before
  // settling billing. Keep the legacy direct-delete token for older paths.
  const remoteDelete = ['await ensureInstanceDeleted(', 'await deleteInstance(']
    .map(token => source.indexOf(token))
    .filter(index => index !== -1)
    .sort((a, b) => a - b)[0]
  assert.notEqual(remoteDelete, undefined, `${label}: missing confirmed Incus deletion`)
  for (const [token, action] of [
    ['balance: { increment:', 'refund'],
    ['await db.settleUserDestroyBilling(', 'user destroy billing settlement'],
    ['await db.settlePrivilegedDeletionBilling(', 'privileged deletion billing settlement'],
    ['await closeHourlyBilling(', 'hourly billing closure'],
    ['prisma.snapshot.deleteMany', 'related data cleanup'],
    ['db.rollbackResources(', 'quota/resource release']
  ]) {
    const actionPosition = source.indexOf(token)
    if (actionPosition !== -1) {
      assert.ok(remoteDelete < actionPosition, `${label}: ${action} must happen after Incus deletion`)
    }
  }
}

const userBatch = await section('src/routes/instance-destroy.ts', 'async function executeDestroyForUser(', 'export default async function instanceDestroyRoutes')
assert.match(userBatch, /queueOfflinePaidDestroy/)
assert.doesNotMatch(userBatch, /ensureInstanceDeleted|rollbackResources|settleUserDestroyBilling/)
const userSingle = await section('src/routes/instance-destroy.ts', "fastify.post<{ Params: { id: string }; Querystring: { feeWaiver?: string } }>('/:id/destroy'", '\n  })\n}')
assert.match(userSingle, /queueOfflinePaidDestroy/)
assert.doesNotMatch(userSingle, /ensureInstanceDeleted|rollbackResources|settleUserDestroyBilling/)
const genericDelete = await section('src/routes/instances.ts', '  // 删除实例\n', '  // 添加端口映射')
assert.match(genericDelete, /processPendingInstanceDeletion/)
assert.match(genericDelete, /status: 'deleting'/)
const adminDelete = await section('src/routes/admin-billing.ts', '// POST /api/admin/instances/:id/delete-and-refund', '// ==================== 管理员应用AFF优惠码')
assert.match(adminDelete, /if \(!databaseOnly\) \{[\s\S]*?claimInstanceForAdminDelete[\s\S]*?processPendingInstanceDeletion/)
const hostBatchDelete = await section('src/routes/hosts.ts', '// The ordinary batch path uses', '// 删除宿主机（管理员或节点所有者）')
assert.match(hostBatchDelete, /pending: \{[\s\S]*?requestedById/)
const expiredDelete = await section('src/services/billing-scheduler.ts', 'async function processExpiryDelete(', '// ==================== 到期提醒')
assert.match(expiredDelete, /claimExpiredInstanceForDeletion/)
assert.match(expiredDelete, /processPendingInstanceDeletion/)
assert.doesNotMatch(expiredDelete, /restoreExpiredInstanceDeletionClaim|rollbackResources/)
const worker = await section('src/services/pending-instance-deletion.ts', 'export async function processPendingInstanceDeletion(', 'export async function runPendingInstanceDeletionRecovery')
assert.ok(position(worker, 'await remote.ensureDeleted(', 'pending worker') < position(worker, 'await decrementHostResourceCounters(', 'pending worker'))
assert.match(worker, /deletionRemoteDeleted: true/)
assert.match(worker, /reservationBefore.state === 'unknown'/)
console.log('instance destroy ordering regression test passed')
