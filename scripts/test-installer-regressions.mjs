import assert from 'node:assert/strict'
import test from 'node:test'
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, rmSync, readdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'

const root = new URL('../', import.meta.url)
const source = path => readFileSync(new URL(path, root), 'utf8')
function fn(path, name) {
  const text = source(path)
  const start = text.indexOf(`${name}() {`)
  assert.ok(start >= 0)
  return text.slice(start, text.indexOf('\n}', start) + 2)
}
const logStubs = 'log() { :; }; info() { :; }; step() { :; }; error() { echo "$*" >&2; };\n'
function bash(code, env = {}) {
  return spawnSync('bash', ['-eu', '-o', 'pipefail', '-c', code], { encoding: 'utf8', env: { ...process.env, BASH_ENV: '', ...env } })
}
function temporary(run) {
  const dir = mkdtempSync(join(tmpdir(), 'incudal-installer-test-'))
  try { return run(dir) } finally { rmSync(dir, { recursive: true, force: true }) }
}

test('Docker fresh install mounts certificates at entrypoint source directory', () => temporary(dir => {
  const result = bash(logStubs + fn('scripts/install-docker.sh', 'migrate_certificate_mount') + '\n' + fn('scripts/install-docker.sh', 'generate_compose') + '\ngenerate_compose', { COMPOSE_FILE: join(dir, 'compose.yml') })
  assert.equal(result.status, 0, result.stderr)
  const compose = readFileSync(join(dir, 'compose.yml'), 'utf8')
  assert.match(compose, /\.\/server\/certs:\/run\/incudal-certs:ro/)
  assert.match(source('server/docker-entrypoint.sh'), /CERT_SOURCE_DIR=\/run\/incudal-certs/)
  assert.doesNotMatch(compose, /:\/app\/server\/certs:ro/)
}))

test('Docker existing install migrates mount, retains custom settings and original backup, and is idempotent', () => temporary(dir => {
  const file = join(dir, 'compose.yml')
  const original = 'services:\n  app:\n    image: custom/image:pinned\n    volumes:\n      - ./server/certs:/app/server/certs:ro\n      - ./data:/custom\n'
  writeFileSync(file, original)
  const code = logStubs + fn('scripts/install-docker.sh', 'migrate_certificate_mount') + '\n' + fn('scripts/install-docker.sh', 'generate_compose') + '\ngenerate_compose\ngenerate_compose'
  const result = bash(code, { COMPOSE_FILE: file })
  assert.equal(result.status, 0, result.stderr)
  assert.equal(readFileSync(file, 'utf8'), original.replace('/app/server/certs', '/run/incudal-certs'))
  assert.equal(readFileSync(file + '.before-cert-migration', 'utf8'), original)
  assert.match(fn('scripts/install-docker.sh', 'do_upgrade'), /migrate_certificate_mount/)
}))

test('native installer creates systemd writable directories before service reload', () => temporary(dir => {
  const code = logStubs + `
install() { printf 'install %s\\n' "$*" >> "$TRACE"; }
mkdir() { printf 'mkdir %s\\n' "$*" >> "$TRACE"; }
systemctl() { printf 'systemctl %s\\n' "$*" >> "$TRACE"; }
` + fn('scripts/install-panel.sh', 'ensure_service_directories') + '\n' + fn('scripts/install-panel.sh', 'create_service') + '\ncreate_service'
  const result = bash(code, { TRACE: join(dir, 'trace'), SERVICE_FILE: join(dir, 'service'), SERVICE_NAME: 'incudal', INSTALL_DIR: dir, ENV_FILE: join(dir, '.env'), RUN_USER: 'incudal', GITHUB_REPO: '1743986520/incudal' })
  assert.equal(result.status, 0, result.stderr)
  const trace = readFileSync(join(dir, 'trace'), 'utf8')
  assert.ok(trace.indexOf('/var/lib/incudal/web-updates') < trace.indexOf('systemctl daemon-reload'))
  assert.ok(trace.indexOf('/server/certs') < trace.indexOf('systemctl daemon-reload'))
  assert.match(fn('scripts/install-panel.sh', 'configure_web_update_service'), /ensure_service_directories/)
}))

for (const exitCode of [0, 7]) {
  test(`bootstrap removes downloaded payload and preserves child exit ${exitCode}`, { skip: process.getuid?.() !== 0 }, () => temporary(dir => {
    mkdirSync(join(dir, 'bin'))
    // Stub only download and temp-file location; the downloaded child runs as a real bash process.
    writeFileSync(join(dir, 'fixture.sh'), `#!/bin/bash
printf '%s\\n' "$*" > "$ARGS_OUT"
exit ${exitCode}
`)
    writeFileSync(join(dir, 'bin', 'curl'), '#!/bin/bash\nwhile [[ $# -gt 0 ]]; do if [[ "$1" == -o ]]; then cp "$PAYLOAD_FIXTURE" "$2"; exit 0; fi; shift; done\nexit 1\n', { mode: 0o755 })
    writeFileSync(join(dir, 'bin', 'mktemp'), '#!/bin/bash\nexec /usr/bin/mktemp "$PAYLOAD_DIR/payload.XXXXXX.sh"\n', { mode: 0o755 })
    const script = source('server/templates/install.sh').replace('INJECT_PANEL_URL=""', 'INJECT_PANEL_URL="https://panel.example.test"').replace('INJECT_TOKEN=""', 'INJECT_TOKEN="test-token"')
    writeFileSync(join(dir, 'bootstrap.sh'), script)
    const result = spawnSync('bash', [join(dir, 'bootstrap.sh'), '--mode', 'nat', '--storage-source', '/example/path'], { encoding: 'utf8', env: { ...process.env, BASH_ENV: '', PAYLOAD_FIXTURE: join(dir, 'fixture.sh'), PATH: join(dir, 'bin') + ':' + process.env.PATH, PAYLOAD_DIR: dir, ARGS_OUT: join(dir, 'args') } })
    assert.equal(result.status, exitCode, result.stderr)
    assert.equal(readdirSync(dir).filter(name => name.startsWith('payload.')).length, 0)
    assert.equal(readFileSync(join(dir, 'args'), 'utf8').trim(), '--mode nat --storage-source /example/path')
  }))
}

test('node installer rejects missing option values with a clear error before system changes', { skip: process.getuid?.() !== 0 }, () => {
  for (const option of ['--mode', '--token', '--ipv6-subnet', '--ipv6-iface', '--port', '-p', '--pps-limit']) {
    const code = logStubs + 'show_banner() { :; }; detect_system() { :; };\n' + fn('server/templates/install/main.sh', 'main') + '\nmain "$OPTION"'
    const result = bash(code, { OPTION: option })
    assert.equal(result.status, 1)
    assert.match(result.stderr, /缺少参数/)
    assert.doesNotMatch(result.stderr, /unbound variable/)
  }
})
