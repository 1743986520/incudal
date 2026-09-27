import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, mkdtempSync, rmSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { spawnSync } from 'node:child_process'
const root = new URL('../', import.meta.url)
const source = path => readFileSync(new URL(path, root), 'utf8')
function fn(path, name) {
  const text = source(path), start = text.indexOf(`${name}() {`)
  assert.ok(start >= 0)
  return name === 'init_incus' ? text.slice(start) : text.slice(start, text.indexOf('\n}', start) + 2)
}
const stubs = 'info() { :; }; step() { :; }; log() { :; }; warn() { :; }; error() { echo "$*" >&2; };\n'
function run(code, env = {}) {
  return spawnSync('bash', ['-eu', '-o', 'pipefail', '-c', code], { encoding: 'utf8', env: { ...process.env, BASH_ENV: '', ...env } })
}
function temp(callback) {
  const dir = mkdtempSync(join(tmpdir(), 'incudal-node-test-'))
  try { callback(dir) } finally { rmSync(dir, { recursive: true, force: true }) }
}
for (const existing of ['yes', 'no']) {
  test(`Incus initialization with existing bridge=${existing}`, () => temp(dir => {
    const code = stubs + `
prepare_incus_dnsmasq() { :; }
ensure_selected_storage_pool() { :; }
ensure_default_profile() { :; }
incus() {
  printf '%s\\n' "$*" >> "$TRACE"
  case "$1 $2" in
    'network show') [[ "$EXISTING" == yes ]] ;;
    'admin init') [[ $# == 3 && "$3" == --preseed ]] || return 17; cat > "$CAPTURE" ;;
    'config set') [[ "$3" == core.https_address && "$4" == '[::]:10001' ]] ;;
    *) return 19 ;;
  esac
}
` + fn('server/templates/install/incus.sh', 'init_incus') + '\ninit_incus'
    const result = run(code, { EXISTING: existing, TRACE: join(dir, 'trace'), CAPTURE: join(dir, 'capture'), PRESEED_FILE: join(dir, 'preseed'), BRIDGE_NAME: 'incusbr0', BRIDGE_SUBNET: '10.10.0.1/22', LISTEN_PORT: '10001', MODE: 'nat', IS_PURE_IPV6: 'false', STORAGE_DRIVER: 'none' })
    assert.equal(result.status, 0, result.stderr)
    if (existing === 'yes') assert.match(readFileSync(join(dir, 'trace'), 'utf8'), /config set core.https_address \[::\]:10001/)
    else assert.match(readFileSync(join(dir, 'capture'), 'utf8'), /core.https_address: '\[::\]:10001'/)
  }))
}
test('existing pool with a different driver fails without recreating data', () => {
  const code = stubs + source('server/templates/install/storage.sh') + `
incus() { [[ "$1 $2" == 'storage show' ]] || exit 88; printf 'driver: zfs\\n'; }
ensure_selected_storage_pool
`
  const result = run(code, { STORAGE_DRIVER: 'dir', STORAGE_POOL_NAME: 'default' })
  assert.equal(result.status, 1)
  assert.match(result.stderr, /不符/)
})
test('storage loop size rejects zero and accepts valid nonzero sizes', () => {
  const code = source('server/templates/install/storage.sh') + '\nnormalize_storage_size "$SIZE"'
  for (const value of ['0', '000', '0GiB', '000MB']) assert.equal(run(code, { SIZE: value }).status, 1)
  for (const value of ['1', '60GiB', '100GB']) assert.equal(run(code, { SIZE: value }).status, 0)
})
test('explicit storage options survive interactive terminal invocation', () => temp(dir => {
  const script = join(dir, 'test.sh')
  writeFileSync(script, 'set -euo pipefail\n' + stubs + source('server/templates/install/storage.sh') + '\nprompt_storage_pool\n[[ "$STORAGE_DRIVER" == zfs && "$STORAGE_POOL_NAME" == data && "$STORAGE_SIZE" == 20GiB ]]\n')
  const result = spawnSync('script', ['-qec', 'bash "$TEST_SCRIPT"', '/dev/null'], { input: '', encoding: 'utf8', timeout: 5000, env: { ...process.env, BASH_ENV: '', TEST_SCRIPT: script, STORAGE_OPTION_EXPLICIT: 'true', STORAGE_DRIVER: 'zfs', STORAGE_POOL_NAME: 'data', STORAGE_SIZE: '20GiB' } })
  assert.equal(result.status, 0, result.stderr + result.stdout)
}))
test('certificate import uses exact certificate fingerprint, not a panel name', () => temp(dir => {
  const cert = join(dir, 'cert.pem'), key = join(dir, 'key.pem')
  const generated = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert, '-days', '1', '-subj', '/CN=test'], { encoding: 'utf8' })
  assert.equal(generated.status, 0, generated.stderr)
  const fingerprint = spawnSync('openssl', ['x509', '-in', cert, '-noout', '-fingerprint', '-sha256'], { encoding: 'utf8' }).stdout.trim().split('=')[1].replaceAll(':', '').toLowerCase()
  const code = stubs + `
curl() { cp "$CERT" "\${@: -1}"; }
incus() {
  if [[ "$1 $2 $3" == 'config trust list' ]]; then printf '%s\\n' "$TRUSTED";
  elif [[ "$1 $2 $3" == 'config trust add-certificate' ]]; then printf 'added\\n' >> "$TRACE";
  else return 1; fi
}
` + fn('server/templates/install/agent.sh', 'import_cert') + '\nimport_cert'
  for (const [trusted, added] of [['panel', true], [fingerprint, false]]) {
    const trace = join(dir, 'trace'); writeFileSync(trace, '')
    const result = run(code, { CERT: cert, TRUSTED: trusted, TRACE: trace, PANEL_URL: 'https://panel.example.test', TOKEN: 'test-token' })
    assert.equal(result.status, 0, result.stderr)
    assert.equal(readFileSync(trace, 'utf8').includes('added'), added)
  }
}))
test('Agent binary download failure does not consume install token; custom binary directory exists before manifest download', () => temp(dir => {
  mkdirSync(join(dir, 'bin'))
  const trace = join(dir, 'trace')
  writeFileSync(join(dir, 'bin', 'curl'), `#!/bin/bash
printf '%s\\n' "$*" >> "$TRACE"
[[ -d "$EXPECTED_DIR" ]] || exit 33
exit 7
`, { mode: 0o755 })
  const result = spawnSync('bash', [new URL('server/templates/agent-install.sh', root).pathname], { encoding: 'utf8', env: { ...process.env, BASH_ENV: '', PATH: join(dir, 'bin') + ':' + process.env.PATH, TRACE: trace, EXPECTED_DIR: join(dir, 'custom'), INCUDAL_AGENT_BIN: join(dir, 'custom', 'agent'), INCUDAL_PANEL_URL: 'https://panel.example.test', INCUDAL_AGENT_INSTALL_TOKEN: 'test-token' } })
  assert.equal(result.status, 7, result.stderr)
  const calls = readFileSync(trace, 'utf8')
  assert.match(calls, /manifest.json/)
  assert.doesNotMatch(calls, /install-config/)
}))

test('rerun retains the existing bridge subnet without selecting a new network', () => {
  const code = stubs + fn('server/templates/install/prelude.sh', 'select_bridge_subnet') + `
incus() { printf '10.20.0.1/22\\n'; }
ip() { exit 91; }
select_bridge_subnet
[[ "$BRIDGE_SUBNET" == 10.20.0.1/22 ]]
`
  const result = run(code, { BRIDGE_NAME: 'incusbr0', BRIDGE_SUBNET: '10.10.0.1/22' })
  assert.equal(result.status, 0, result.stderr)
})
