import assert from 'node:assert/strict'
import { test } from 'node:test'
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import Fastify from 'fastify'
import { registerStaticServer } from './static-server.js'

test('static cache headers keep worker and HTML fresh without pinning assets for a year', async () => {
  const root = await mkdtemp(join(tmpdir(), 'incudal-static-'))
  const app = Fastify()
  try {
    await mkdir(join(root, 'assets'))
    await writeFile(join(root, 'index.html'), '<!doctype html><title>Incudal</title>')
    await writeFile(join(root, 'sw.js'), 'self.addEventListener("activate", () => {})')
    await writeFile(join(root, 'theme-init.js'), 'void 0')
    await writeFile(join(root, 'assets', 'abcdefgh.js'), 'void 0')
    await writeFile(join(root, 'logo.svg'), '<svg xmlns="http://www.w3.org/2000/svg"/>')
    await registerStaticServer(app, { clientDistPath: root })
    await app.ready()

    const expected = new Map([
      ['/', 'no-cache, no-store, must-revalidate'],
      ['/sw.js', 'no-cache, no-store, must-revalidate'],
      ['/theme-init.js', 'no-cache, must-revalidate'],
      ['/assets/abcdefgh.js', 'public, max-age=604800, immutable'],
      ['/logo.svg', 'public, max-age=3600, must-revalidate']
    ])
    for (const [path, cacheControl] of expected) {
      const response = await app.inject({ method: 'GET', url: path })
      assert.equal(response.statusCode, 200, path)
      assert.equal(response.headers['cache-control'], cacheControl, path)
    }
  } finally {
    await app.close()
    await rm(root, { recursive: true, force: true })
  }
})
