/**
 * Test Suite 3: Gap Coverage
 *
 * Tests specific scenarios NOT covered by component or lifecycle tests:
 *   - Node.js fetch() (undici) — the actual failure surface
 *   - HTTPS :443 REDIRECT to :18443
 *   - mitmproxy user HTTPS outbound (P0 self-loop via fetch)
 */

const path = require('path')
const {
  getApiKey, TestSuite, exec, setupSandbox, startProxy,
  loadNftRules, snapshotRestore, killSandbox, writeNodeScript,
} = require('./helpers.cjs')

async function run() {
  const apiKey = getApiKey()
  const suite = new TestSuite('03-gap-coverage')

  console.log('╔═══════════════════════════════════════════════╗')
  console.log('║  Test 03: Gap Coverage                        ║')
  console.log('╚═══════════════════════════════════════════════╝\n')

  let sandbox
  try {
    sandbox = await setupSandbox(apiKey)
    await startProxy(sandbox)
    await loadNftRules(sandbox)
    sandbox = await snapshotRestore(sandbox, apiKey)

    // Write Node.js test scripts
    const fixturesDir = path.join(__dirname, '..', 'fixtures')
    await writeNodeScript(sandbox, path.join(fixturesDir, 'attack-selfloop.mjs'), '/tmp/selfloop.mjs')
    await writeNodeScript(sandbox, path.join(fixturesDir, 'attack-concurrent.mjs'), '/tmp/concurrent.mjs')

    console.log('\n--- Node.js fetch() tests ---\n')

    // GAP: Node.js fetch to HTTP (redirected)
    {
      await sandbox.files.write('/tmp/fetch-http.mjs', [
        'const c = new AbortController();',
        'const t = setTimeout(() => c.abort(), 5000);',
        'try {',
        '  const r = await fetch("http://198.18.0.1/node-fetch-test", {signal: c.signal});',
        '  clearTimeout(t);',
        '  const txt = await r.text();',
        '  console.log(txt);',
        '} catch(e) {',
        '  clearTimeout(t);',
        '  console.log("ERR:" + e.name);',
        '}',
      ].join('\n'))
      const r = await exec(sandbox, 'node /tmp/fetch-http.mjs', 15000)
      suite.record('Node.js fetch() HTTP → intercepted by proxy',
        r.stdout.includes('OK path=/node-fetch-test'), r.stdout)
    }

    // GAP: Node.js fetch concurrent
    {
      const r = await exec(sandbox, 'node /tmp/concurrent.mjs', 20000)
      let res = {}
      try { res = JSON.parse(r.stdout) } catch {}
      suite.record('Node.js 10 concurrent fetch() → all intercepted',
        res.ok === 10 && res.errors?.length === 0,
        `${res.ok}/10 ok, ${res.errors?.length || '?'} errors`)
    }

    // GAP: HTTPS :443 REDIRECT (use python3 socket instead of nc for reliability)
    {
      await sandbox.files.write('/tmp/tls_test.py', [
        'import socket, sys',
        'try:',
        '    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)',
        '    s.settimeout(3)',
        '    s.connect(("198.18.0.1", 443))',
        '    data = s.recv(1024)',
        '    s.close()',
        '    print(data.decode("utf-8", errors="replace"))',
        'except Exception as e:',
        '    print(f"ERR:{e}")',
      ].join('\n'))
      const r = await exec(sandbox, 'python3 /tmp/tls_test.py')
      suite.record('HTTPS :443 → REDIRECT to :18443',
        r.stdout.includes('TLS_PASSTHROUGH_REACHED'),
        r.stdout)
    }

    // GAP: mitmproxy user fetch HTTPS (P0 scenario with Node.js)
    {
      const r = await exec(sandbox, 'sudo -u mitmproxy node /tmp/selfloop.mjs', 20000)
      let res = []
      try { res = JSON.parse(r.stdout) } catch {}
      const allDirect = res.length === 3 && res.every(x =>
        x.timeout || x.code === 'ECONNREFUSED' || x.code === 'ETIMEDOUT')
      suite.record('mitmproxy user fetch("https://...") → no self-loop',
        allDirect,
        `${res.length} requests: ${res.map(x => x.code || x.name).join(', ')}`)
    }

  } catch (e) {
    console.error('FATAL:', e.message)
  } finally {
    if (sandbox) await killSandbox(sandbox, apiKey)
  }

  return suite.summary()
}

run().then(ok => process.exit(ok ? 0 : 1))
