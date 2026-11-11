import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { spawn } from 'node:child_process'
import { PrismaClient } from '@prisma/client'
import { PrismaPg } from '@prisma/adapter-pg'

const url = new URL(process.env.DATABASE_URL ?? '')
if (url.hostname !== 'incudal-refund-pg16-1110' || url.pathname !== '/incudal_deletion_test' || process.env.INSTANCE_DELETION_TEST_ALLOW !== '1') throw new Error('Requires isolated refund fixture database')
const prisma = new PrismaClient({ adapter: new PrismaPg({ connectionString: url.toString() }) })
const script = await readFile('/fixtures/operator-refund-retired.mjs', 'utf8')
const source = 'a'.repeat(64)
const invoke = async args => new Promise((resolve, reject) => {
  const p = spawn(process.execPath, ['--input-type=module', '-', `--source=${source}`, '--count=2', ...args], { cwd: '/app/server', env: process.env })
  let out = '', err = ''
  p.stdout.on('data', b => { out += b })
  p.stderr.on('data', b => { err += b })
  p.on('close', code => code ? reject(new Error(err)) : resolve(JSON.parse(out)))
  p.stdin.end(script)
})
const tag = String(Date.now())
const admin = await prisma.user.create({ data: { username: `refund_admin_${tag}`, passwordHash: 'fixture', role: 'admin' } })
const user = await prisma.user.create({ data: { username: `refund_user_${tag}`, passwordHash: 'fixture', balance: 10 } })
const host = await prisma.host.create({ data: { userId: admin.id, name: `refund_${tag}`, countryCode: 'zz', url: 'https://127.0.0.1:1', status: 'offline' } })
const ids = []
try {
  for (let n = 0; n < 2; n++) {
    const i = await prisma.instance.create({ data: { userId: user.id, hostId: host.id, name: `refund_${tag}_${n}`, incusId: `refund_${tag}_${n}`, image: 'fixture', cpu: 1, memory: 128, disk: 128, status: 'deleted', deletionRequestedAt: new Date('2026-01-06T00:00:00Z'), expiresAt: new Date('2026-01-11T00:00:00Z'), deletionBillingPending: true, deletionBillingMode: 'manual_retired_host', deletionRemoteDeleted: false } })
    ids.push(i.id)
    await prisma.retiredInstanceTombstone.create({ data: { instanceId: i.id, hostId: host.id, sourceDigest: source, retirementDigest: 'b'.repeat(64), originalBillingMode: 'privileged_delete' } })
    await prisma.instanceBillingRecord.create({ data: { instanceId: i.id, userId: user.id, type: 'newPurchase', amount: '10.01', periodStart: new Date('2026-01-01T00:00:00Z'), periodEnd: new Date('2026-01-11T00:00:00Z') } })
  }
  const preview = await invoke([])
  assert.equal(preview.total, '1002')
  assert.equal(String((await prisma.user.findUniqueOrThrow({ where: { id: user.id } })).balance), '10')
  await prisma.$executeRawUnsafe(`CREATE FUNCTION fixture_refund_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action = 'instance.retired_prorated_refund' THEN RAISE EXCEPTION 'fixture failure'; END IF; RETURN NEW; END $$`)
  await prisma.$executeRawUnsafe('CREATE TRIGGER fixture_refund_failure BEFORE INSERT ON logs FOR EACH ROW EXECUTE FUNCTION fixture_refund_failure()')
  await assert.rejects(invoke([`--apply=${preview.digest}`]), /fixture failure/)
  assert.equal(String((await prisma.user.findUniqueOrThrow({ where: { id: user.id } })).balance), '10')
  assert.equal(await prisma.instanceBillingRecord.count({ where: { instanceId: { in: ids }, type: 'refund' } }), 0)
  await prisma.$executeRawUnsafe('DROP TRIGGER fixture_refund_failure ON logs')
  await prisma.$executeRawUnsafe('DROP FUNCTION fixture_refund_failure()')
  const concurrent = await Promise.allSettled([invoke([`--apply=${preview.digest}`]), invoke([`--apply=${preview.digest}`])])
  assert.equal(concurrent.filter(r => r.status === 'fulfilled').length, 1)
  assert.equal(String((await prisma.user.findUniqueOrThrow({ where: { id: user.id } })).balance), '20.02')
  assert.equal(await prisma.instanceBillingRecord.count({ where: { instanceId: { in: ids }, type: 'refund' } }), 2)
  assert.equal(await prisma.instance.count({ where: { id: { in: ids }, deletionRemoteDeleted: false, deletionBillingPending: false } }), 2)
  await assert.rejects(invoke([`--apply=${preview.digest}`]))
  console.log('isolated retired refund transaction tests passed')
} finally { await prisma.$disconnect() }
