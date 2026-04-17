/**
 * Test Suite 6: Passthrough PoC Validation
 *
 * Tests the Node.js proof-of-concept proxy that implements the RFC's
 * passthrough mode + hot-switch, under real nft rules in E2B sandbox.
 *
 * PoC-1: HTTP passthrough relay (not intercept — actually forwards to upstream)
 * PoC-2: HTTPS TCP tunnel (SNI-based, actual TLS data to real upstream)
 * PoC-3: Hot-switch via POST /__activate-mitm
 * PoC-4: After switch, HTTPS connections get MITM marker
 * PoC-5: All of above after snapshot/restore
 * PoC-6: Node.js fetch through passthrough HTTP relay
 * PoC-7: mitmproxy user UID exempt (outbound not looped)
 */

const path = require('path')
const {
  getApiKey, TestSuite, exec, setupSandbox,
  loadNftRules, snapshotRestore, killSandbox,
  writeTcpConnect, tcpConnect,
} = require('./helpers.cjs')

async function run() {
  const apiKey = getApiKey()
  const suite = new TestSuite('06-passthrough-poc')

  console.log('╔═══════════════════════════════════════════════════╗')
  console.log('║  Test 06: Passthrough PoC Validation              ║')
  console.log('╚═══════════════════════════════════════════════════╝\n')

  let sandbox
  try {
    sandbox = await setupSandbox(apiKey)

    // Upload PoC proxy
    const pocContent = require('fs').readFileSync(
      path.join(__dirname, '..', 'fixtures', 'proxy-passthrough-poc.mjs'), 'utf-8'
    )
    await sandbox.files.write('/opt/proxy-poc.mjs', pocContent)

    // Start as mitmproxy user
    await exec(sandbox, 'sh -c "nohup sudo -u mitmproxy node /opt/proxy-poc.mjs > /tmp/poc.log 2>&1 &"')
    await exec(sandbox, 'sleep 3')

    const health = await exec(sandbox, 'curl -s http://127.0.0.1:18080/__health')
    suite.record('Setup: PoC proxy starts as mitmproxy user',
      health.stdout.includes('"ok"') && health.stdout.includes('passthrough'),
      health.stdout)

    // Load nft rules
    await loadNftRules(sandbox)
    await writeTcpConnect(sandbox)

    // ================================================================
    console.log('\n--- PoC-1: HTTP passthrough relay to real upstream ---\n')
    // ================================================================
    {
      // This tests REAL relay — proxy forwards to httpbin.org, not just "OK path=..."
      const r = await exec(sandbox, 'curl -s --connect-timeout 5 --max-time 8 http://httpbin.org/ip 2>&1', 15000)
      const realRelay = r.stdout.includes('"origin"')
      suite.record('PoC-1: HTTP passthrough relays to real upstream (httpbin.org)',
        realRelay,
        realRelay ? 'received real httpbin JSON' : r.stdout.substring(0, 80))
    }

    // ================================================================
    console.log('\n--- PoC-2: HTTPS TCP tunnel with real TLS ---\n')
    // ================================================================
    {
      // Root HTTPS to real host → nft redirect to :18443 → PoC SNI tunnel → upstream
      // If tunnel works, Python SSL handshake with real server succeeds
      await sandbox.files.write('/tmp/tls_tunnel.py', [
        'import socket, ssl',
        'try:',
        '    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)',
        '    s.settimeout(8)',
        '    s.connect(("example.com", 443))',
        '    ctx = ssl.create_default_context()',
        '    wrapped = ctx.wrap_socket(s, server_hostname="example.com")',
        '    cert = wrapped.getpeercert()',
        '    cn = dict(x[0] for x in cert["subject"])["commonName"]',
        '    wrapped.send(b"GET / HTTP/1.1\\r\\nHost: example.com\\r\\nConnection: close\\r\\n\\r\\n")',
        '    data = wrapped.recv(512)',
        '    wrapped.close()',
        '    print(f"TLS_OK:{cn}:{data[:30]}")',
        'except Exception as e:',
        '    print(f"ERR:{e}")',
      ].join('\n'))

      const r = await exec(sandbox, 'python3 /tmp/tls_tunnel.py', 20000)
      const tunnelOk = r.stdout.includes('TLS_OK')
      suite.record('PoC-2: HTTPS TCP tunnel → real TLS handshake with example.com',
        tunnelOk,
        r.stdout.substring(0, 100))
    }

    // ================================================================
    console.log('\n--- PoC-3: Node.js fetch through passthrough HTTP relay ---\n')
    // ================================================================
    {
      await sandbox.files.write('/tmp/fetch_relay.mjs', [
        'const c = new AbortController();',
        'const t = setTimeout(() => c.abort(), 8000);',
        'try {',
        '  const r = await fetch("http://httpbin.org/headers", {signal: c.signal});',
        '  clearTimeout(t);',
        '  const j = await r.json();',
        '  console.log("FETCH_OK:" + JSON.stringify(j.headers.Host || "no-host"));',
        '} catch(e) {',
        '  clearTimeout(t);',
        '  console.log("FETCH_ERR:" + e.name + ":" + (e.cause ? e.cause.code : e.message).substring(0,40));',
        '}',
      ].join('\n'))

      const r = await exec(sandbox, 'node /tmp/fetch_relay.mjs', 15000)
      const fetchOk = r.stdout.includes('FETCH_OK')
      suite.record('PoC-3: Node.js fetch HTTP → passthrough relay → httpbin.org',
        fetchOk,
        r.stdout.substring(0, 80))
    }

    // ================================================================
    console.log('\n--- PoC-4: mitmproxy user UID exempt ---\n')
    // ================================================================
    {
      const r = await exec(sandbox,
        'sudo -u mitmproxy curl -s --connect-timeout 5 -o /dev/null -w "%{http_code}" https://httpbin.org/status/200', 15000)
      suite.record('PoC-4: mitmproxy user HTTPS bypasses proxy (UID exempt)',
        r.stdout.includes('200'),
        `status: ${r.stdout}`)
    }

    // ================================================================
    console.log('\n--- PoC-5: Snapshot/restore ---\n')
    // ================================================================
    sandbox = await snapshotRestore(sandbox, apiKey)

    {
      const h = await exec(sandbox, 'curl -s http://127.0.0.1:18080/__health')
      suite.record('PoC-5a: PoC proxy survives snapshot',
        h.stdout.includes('"ok"'), h.stdout)
    }
    {
      const r = await exec(sandbox, 'curl -s --connect-timeout 5 --max-time 8 http://httpbin.org/ip 2>&1', 15000)
      suite.record('PoC-5b: HTTP relay works after snapshot',
        r.stdout.includes('"origin"'))
    }
    {
      await sandbox.files.write('/tmp/tls_after.py', [
        'import socket, ssl',
        'try:',
        '    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)',
        '    s.settimeout(8)',
        '    s.connect(("example.com", 443))',
        '    ctx = ssl.create_default_context()',
        '    w = ctx.wrap_socket(s, server_hostname="example.com")',
        '    cn = dict(x[0] for x in w.getpeercert()["subject"])["commonName"]',
        '    w.close()',
        '    print(f"TLS_OK:{cn}")',
        'except Exception as e:',
        '    print(f"ERR:{e}")',
      ].join('\n'))

      const r = await exec(sandbox, 'python3 /tmp/tls_after.py', 20000)
      suite.record('PoC-5c: HTTPS TCP tunnel works after snapshot',
        r.stdout.includes('TLS_OK'), r.stdout.substring(0, 80))
    }

    // ================================================================
    console.log('\n--- PoC-6: Hot-switch passthrough → MITM ---\n')
    // ================================================================
    {
      const act = await exec(sandbox, 'curl -s -X POST http://127.0.0.1:18080/__activate-mitm')
      suite.record('PoC-6a: Hot-switch activation succeeds',
        act.stdout.includes('activated'), act.stdout)
    }
    {
      const h = await exec(sandbox, 'curl -s http://127.0.0.1:18080/__health')
      suite.record('PoC-6b: Mode changed to mitm',
        h.stdout.includes('"mitm"'), h.stdout)
    }
    {
      // HTTP relay should still work after switch
      const r = await exec(sandbox, 'curl -s --connect-timeout 5 --max-time 8 http://httpbin.org/ip 2>&1', 15000)
      suite.record('PoC-6c: HTTP relay still works after switch to MITM',
        r.stdout.includes('"origin"'))
    }
    {
      // HTTPS should now get MITM marker (PoC sends "MITM_MODE_ACTIVE")
      const r = await tcpConnect(sandbox, 'example.com', 443)
      suite.record('PoC-6d: HTTPS now in MITM mode after switch',
        r.stdout.includes('MITM_MODE_ACTIVE'), r.stdout.substring(0, 60))
    }

  } catch (e) {
    console.error('FATAL:', e.message)
    if (e.stack) console.error(e.stack)
  } finally {
    if (sandbox) await killSandbox(sandbox, apiKey)
  }

  return suite.summary()
}

run().then(ok => process.exit(ok ? 0 : 1))
