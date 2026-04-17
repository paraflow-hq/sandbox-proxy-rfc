/**
 * Shared test helpers for RFC validation tests.
 *
 * All tests run in real E2B sandboxes — no mocking.
 */

const { Sandbox } = require('@e2b/code-interpreter')

// Read API key from env or CLI arg
function getApiKey() {
  const key = process.env.E2B_API_KEY || process.argv[2]
  if (!key) {
    console.error('E2B_API_KEY required. Set via env var or pass as first argument.')
    process.exit(1)
  }
  return key
}

// Test result tracking
class TestSuite {
  constructor(name) {
    this.name = name
    this.results = []
  }

  record(name, passed, detail) {
    this.results.push({ name, passed, detail })
    console.log(`  ${passed ? '✅' : '❌'} ${name}`)
    if (detail) console.log(`     ${detail}`)
  }

  summary() {
    const passed = this.results.filter(r => r.passed).length
    const total = this.results.length
    console.log(`\n  ${passed}/${total} passed`)
    if (passed === total) {
      console.log(`  ✅ ${this.name}: ALL PASSED\n`)
    } else {
      console.log(`  ❌ ${this.name}: SOME FAILED\n`)
    }
    return passed === total
  }
}

// Execute command in sandbox with error handling
async function exec(sandbox, cmd, timeout = 60000) {
  try {
    const r = await sandbox.commands.run(cmd, { timeoutMs: timeout, user: 'root' })
    return { ok: true, stdout: r.stdout.trim(), stderr: r.stderr.trim() }
  } catch (e) {
    return {
      ok: false,
      stdout: e.stdout?.trim() || '',
      stderr: e.stderr?.trim() || '',
      code: e.exitCode,
      msg: e.message,
    }
  }
}

// Standard sandbox setup: install deps, create mitmproxy user, start proxy, load nft rules
async function setupSandbox(apiKey) {
  console.log('  Creating sandbox...')
  const sandbox = await Sandbox.create({ apiKey, timeoutMs: 10 * 60 * 1000 })
  console.log(`  Sandbox: ${sandbox.sandboxId}`)

  console.log('  Installing dependencies...')
  await exec(sandbox, 'apt-get update -qq 2>/dev/null && apt-get install -y -qq nftables curl netcat-openbsd 2>/dev/null')
  await exec(sandbox, 'useradd -r -M -s /usr/sbin/nologin mitmproxy 2>/dev/null; echo OK')

  return sandbox
}

// Start proxy as mitmproxy user
async function startProxy(sandbox) {
  const proxyPy = require('fs').readFileSync(require('path').join(__dirname, '..', 'fixtures', 'proxy.py'), 'utf-8')
  await sandbox.files.write('/opt/proxy.py', proxyPy)
  await exec(sandbox, 'sh -c "nohup sudo -u mitmproxy python3 /opt/proxy.py > /tmp/proxy.log 2>&1 &"')
  await exec(sandbox, 'sleep 2')

  const h = await exec(sandbox, 'curl -s http://127.0.0.1:18080/__health')
  if (!h.stdout.includes('"ok"')) {
    throw new Error('Proxy failed to start: ' + h.stdout + ' ' + h.stderr)
  }
  console.log(`  Proxy: ${h.stdout}`)
}

// Load nft rules
async function loadNftRules(sandbox) {
  const rules = require('fs').readFileSync(require('path').join(__dirname, '..', 'fixtures', 'nft-rules.conf'), 'utf-8')
  await sandbox.files.write('/tmp/rules.conf', rules)
  const r = await exec(sandbox, 'nft -f /tmp/rules.conf')
  if (!r.ok) throw new Error('nft load failed: ' + r.stderr)
  console.log('  nft rules loaded')
}

// Snapshot and restore
async function snapshotRestore(sandbox, apiKey) {
  const sid = sandbox.sandboxId
  console.log('  Pausing (snapshot)...')
  await Sandbox.betaPause(sid, { apiKey })
  console.log('  Resuming (restore)...')
  const restored = await Sandbox.connect(sid, { apiKey, timeoutMs: 60000 })
  await new Promise(r => setTimeout(r, 3000))
  console.log('  Restored')
  return restored
}

// Kill sandbox
async function killSandbox(sandbox, apiKey) {
  try {
    await Sandbox.kill(sandbox.sandboxId, { apiKey })
    console.log('  [cleanup] Sandbox killed')
  } catch { /* ignore */ }
}

// Write a Node.js test script into sandbox from local fixture
async function writeNodeScript(sandbox, localPath, remotePath) {
  const content = require('fs').readFileSync(localPath, 'utf-8')
  await sandbox.files.write(remotePath, content)
}

// Write the TCP connect helper script to sandbox (replacement for nc)
async function writeTcpConnect(sandbox) {
  const content = require('fs').readFileSync(require('path').join(__dirname, '..', 'fixtures', 'tcp-connect.py'), 'utf-8')
  await sandbox.files.write('/tmp/tcp-connect.py', content)
}

// TCP connect test: returns stdout from python3 tcp-connect.py
async function tcpConnect(sandbox, host, port, opts = {}) {
  return await exec(sandbox, `python3 /tmp/tcp-connect.py ${host} ${port}`, opts.timeout || 15000)
}

// Run as mitmproxy user
async function tcpConnectAsMitmproxy(sandbox, host, port) {
  return await exec(sandbox, `sudo -u mitmproxy python3 /tmp/tcp-connect.py ${host} ${port}`, 15000)
}

module.exports = {
  getApiKey, TestSuite, exec, setupSandbox, startProxy, loadNftRules,
  snapshotRestore, killSandbox, writeNodeScript, Sandbox,
  writeTcpConnect, tcpConnect, tcpConnectAsMitmproxy,
}
