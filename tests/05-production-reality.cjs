/**
 * Test Suite 5: Production Reality Check
 *
 * Previous tests used fake IPs (198.18.0.1) and local proxy simulators.
 * This suite tests REAL production scenarios:
 *
 * REALITY 1: Does `flush ruleset` break E2B's own networking?
 *   - After loading our nft rules (which flush all existing rules),
 *     can the sandbox still resolve DNS and reach the internet?
 *
 * REALITY 2: DNS resolution works under nft rules
 *   - DNS uses UDP :53, our rules only redirect TCP.
 *   - But if E2B has internal nft rules we flushed, DNS could break.
 *
 * REALITY 3: Real external HTTP request through proxy
 *   - Root user curl to a real public URL → must be intercepted by proxy
 *     AND the proxy must be able to forward the request externally.
 *
 * REALITY 4: Process UID preserved after snapshot/restore
 *   - The mitmproxy user UID must be exactly the same after restore.
 *   - If UID changes, nft skuid rule stops matching.
 *
 * REALITY 5: Port 8443 redirect (used by some services)
 *
 * REALITY 6: Proxy crash recovery — what happens if proxy dies?
 *
 * REALITY 7: E2B internal operations still work after nft rules
 *   - E2B SDK commands.run uses internal envd communication.
 *   - If our flush breaks envd, all subsequent tests would fail silently.
 */

const path = require('path')
const {
  getApiKey, TestSuite, exec, setupSandbox, startProxy,
  loadNftRules, snapshotRestore, killSandbox,
  writeTcpConnect, tcpConnect, writeNodeScript,
} = require('./helpers.cjs')

async function run() {
  const apiKey = getApiKey()
  const suite = new TestSuite('05-production-reality')

  console.log('╔═══════════════════════════════════════════════════╗')
  console.log('║  Test 05: Production Reality Check                ║')
  console.log('╚═══════════════════════════════════════════════════╝\n')

  let sandbox
  try {
    sandbox = await setupSandbox(apiKey)

    // ================================================================
    console.log('━━━ REALITY 1: Check E2B baseline before any nft changes ━━━\n')
    // ================================================================
    {
      // Record baseline: what nft rules exist BEFORE we touch anything?
      const r = await exec(sandbox, 'nft list ruleset 2>&1')
      const hasExistingRules = r.stdout.trim().length > 0
      suite.record('R1a: Baseline — check existing nft rules',
        true, // informational
        hasExistingRules ? `existing rules found:\n${r.stdout.trim().substring(0, 200)}` : 'no existing rules')

      // Baseline DNS
      const dns = await exec(sandbox, 'python3 -c "import socket; print(socket.getaddrinfo(\'google.com\', 80)[0][4][0])" 2>&1 || echo DNS_FAIL')
      suite.record('R1b: Baseline DNS works before nft changes',
        dns.stdout.length > 0 && !dns.stdout.includes('DNS_FAIL'),
        dns.stdout.substring(0, 100))

      // Baseline external HTTP
      const http = await exec(sandbox, 'curl -s --connect-timeout 5 -o /dev/null -w "%{http_code}" http://httpbin.org/status/200 2>&1', 15000)
      suite.record('R1c: Baseline external HTTP works',
        http.stdout.includes('200'),
        `status: ${http.stdout}`)
    }

    // ================================================================
    console.log('\n━━━ Start proxy + load nft rules (including flush ruleset) ━━━\n')
    // ================================================================
    await startProxy(sandbox)
    await loadNftRules(sandbox)
    await writeTcpConnect(sandbox)

    // ================================================================
    console.log('\n━━━ REALITY 2: DNS still works after flush ruleset ━━━\n')
    // ================================================================
    {
      const r = await exec(sandbox, 'python3 -c "import socket; print(socket.getaddrinfo(\'google.com\', 80)[0][4][0])" 2>&1 || echo DNS_FAIL')
      suite.record('R2: DNS resolution works after nft flush+reload',
        r.stdout.length > 0 && !r.stdout.includes('DNS_FAIL'),
        r.stdout.substring(0, 100))
    }

    // ================================================================
    console.log('\n━━━ REALITY 3: E2B SDK operations still work ━━━\n')
    // ================================================================
    {
      // If flush ruleset broke E2B internal comms, this would fail
      const r = await exec(sandbox, 'echo "E2B_COMMS_OK"')
      suite.record('R3a: E2B commands.run works after nft flush',
        r.stdout === 'E2B_COMMS_OK')

      // File operations
      try {
        await sandbox.files.write('/tmp/e2b_test.txt', 'E2B_FILE_OK')
        const content = await sandbox.files.read('/tmp/e2b_test.txt')
        suite.record('R3b: E2B files.write/read works after nft flush',
          content === 'E2B_FILE_OK')
      } catch (e) {
        suite.record('R3b: E2B files.write/read works after nft flush',
          false, e.message)
      }
    }

    // ================================================================
    console.log('\n━━━ REALITY 4: Real external HTTP through proxy ━━━\n')
    // ================================================================
    {
      // Root user HTTP to real external URL — nft redirects to proxy :18080
      // Proxy intercepts and responds with "OK path=..." (doesn't forward externally)
      // This proves: DNS resolution → TCP connect → nft REDIRECT → proxy receives
      const r = await exec(sandbox, 'curl -s --connect-timeout 5 http://httpbin.org/get 2>&1', 15000)
      const intercepted = r.stdout.includes('OK path=')
      suite.record('R4a: Real external HTTP request intercepted by proxy',
        intercepted,
        intercepted ? r.stdout.substring(0, 80) : `raw: ${r.stdout.substring(0, 100)}`)

      // mitmproxy user HTTP to same URL — should bypass proxy, reach real server
      const exempt = await exec(sandbox, 'sudo -u mitmproxy curl -s --connect-timeout 5 http://httpbin.org/get 2>&1', 15000)
      const reachedReal = exempt.stdout.includes('"url"') || exempt.stdout.includes('httpbin')
      suite.record('R4b: mitmproxy user HTTP request bypasses proxy (reaches real server)',
        reachedReal,
        reachedReal ? 'reached httpbin.org' : `got: ${exempt.stdout.substring(0, 100)}`)
    }

    // ================================================================
    console.log('\n━━━ REALITY 5: Real external HTTPS through proxy ━━━\n')
    // ================================================================
    {
      // Root user HTTPS to real URL → redirected to :18443 (TLS passthrough)
      const r = await tcpConnect(sandbox, 'httpbin.org', 443)
      const intercepted = r.stdout.includes('TLS_PASSTHROUGH_REACHED')
      suite.record('R5a: Real HTTPS to httpbin.org:443 → intercepted by proxy :18443',
        intercepted, r.stdout.substring(0, 60))

      // mitmproxy user HTTPS — should bypass, reach real server
      // Use curl to verify actual TLS handshake succeeds
      const exempt = await exec(sandbox,
        'sudo -u mitmproxy curl -s --connect-timeout 5 -o /dev/null -w "%{http_code}" https://httpbin.org/status/200 2>&1', 15000)
      suite.record('R5b: mitmproxy user HTTPS bypasses proxy (real TLS to httpbin.org)',
        exempt.stdout.includes('200'),
        `status: ${exempt.stdout}`)
    }

    // ================================================================
    console.log('\n━━━ REALITY 6: Port 8443 redirect ━━━\n')
    // ================================================================
    {
      const r = await tcpConnect(sandbox, '198.18.0.1', 8443)
      suite.record('R6: Port 8443 REDIRECT to :18443 works',
        r.stdout.includes('TLS_PASSTHROUGH_REACHED'), r.stdout.substring(0, 60))
    }

    // ================================================================
    console.log('\n━━━ REALITY 7: Process UID after snapshot ━━━\n')
    // ================================================================

    // Get UID before snapshot
    const uidBefore = await exec(sandbox, 'id -u mitmproxy')
    const psBefore = await exec(sandbox, 'ps -o uid,pid,comm -p $(pgrep -f proxy.py) 2>/dev/null | tail -1')

    sandbox = await snapshotRestore(sandbox, apiKey)

    {
      // Verify UID unchanged
      const uidAfter = await exec(sandbox, 'id -u mitmproxy')
      suite.record('R7a: mitmproxy UID unchanged after snapshot',
        uidBefore.stdout === uidAfter.stdout,
        `before: ${uidBefore.stdout}, after: ${uidAfter.stdout}`)

      // Verify process UID unchanged
      const psAfter = await exec(sandbox, 'ps -o uid,pid,comm -p $(pgrep -f proxy.py) 2>/dev/null | tail -1')
      suite.record('R7b: Proxy process UID unchanged after snapshot',
        psBefore.stdout.trim().split(/\s+/)[0] === psAfter.stdout.trim().split(/\s+/)[0],
        `before: ${psBefore.stdout.trim()}, after: ${psAfter.stdout.trim()}`)

      // Verify nft skuid still matches after restore
      await exec(sandbox, 'nft reset counters 2>/dev/null')
      await exec(sandbox, 'sudo -u mitmproxy curl -s --connect-timeout 2 http://198.18.0.1/uid-test > /dev/null 2>&1; true')
      await exec(sandbox, 'sleep 1')
      const counters = await exec(sandbox, 'nft list ruleset | grep "meta skuid"')
      const match = counters.stdout.match(/counter packets (\d+)/)
      const pkts = match ? parseInt(match[1]) : 0
      suite.record('R7c: nft skuid counter increments after restore (rule still matching)',
        pkts > 0, `skuid packets: ${pkts}`)
    }

    // ================================================================
    console.log('\n━━━ REALITY 8: Proxy crash and detection ━━━\n')
    // ================================================================
    {
      // Kill proxy
      await exec(sandbox, 'pkill -f proxy.py')
      await exec(sandbox, 'sleep 1')

      // Proxy is dead — health check fails
      const dead = await exec(sandbox, 'curl -s --connect-timeout 2 http://127.0.0.1:18080/__health 2>&1 || echo DEAD')
      suite.record('R8a: Proxy death is detectable (health check fails)',
        dead.stdout.includes('DEAD') || dead.stdout.includes('refused') || dead.stdout === '',
        dead.stdout.substring(0, 60) || 'no response')

      // HTTP requests to external hosts now fail (proxy dead, but REDIRECT still active)
      const fail = await exec(sandbox, 'curl -s --connect-timeout 2 http://198.18.0.1/should-fail 2>&1 || echo CONN_REFUSED')
      suite.record('R8b: Redirected traffic fails when proxy is dead (not silently dropped)',
        fail.stdout.includes('CONN_REFUSED') || fail.stdout.includes('refused') || fail.stdout === '',
        fail.stdout.substring(0, 60) || 'connection refused')

      // Restart proxy (simulates parent-process recovery)
      // Wait for port release after kill
      await exec(sandbox, 'sleep 2')
      await exec(sandbox, 'sh -c "nohup sudo -u mitmproxy python3 /opt/proxy.py > /tmp/proxy2.log 2>&1 &"')
      await exec(sandbox, 'sleep 3')

      const alive = await exec(sandbox, 'curl -s --connect-timeout 5 http://127.0.0.1:18080/__health')
      suite.record('R8c: Proxy can be restarted after crash',
        alive.stdout.includes('"ok"'), alive.stdout)

      // Traffic works again
      const works = await exec(sandbox, 'curl -s --connect-timeout 3 http://198.18.0.1/recovery-test')
      suite.record('R8d: Traffic resumes after proxy restart',
        works.stdout.includes('OK path=/recovery-test'), works.stdout)
    }

    // ================================================================
    console.log('\n━━━ REALITY 9: UDP traffic unaffected (DNS under nft) ━━━\n')
    // ================================================================
    {
      // Our nft rules only match TCP. UDP (DNS) should pass through normally.
      // Verify by doing DNS lookup after proxy is back up
      const r = await exec(sandbox, 'python3 -c "import socket; print(socket.getaddrinfo(\'google.com\', 80)[0][4][0])" 2>&1 || echo DNS_FAIL')
      suite.record('R9: UDP traffic (DNS) unaffected by TCP-only nft rules',
        r.stdout.length > 0 && !r.stdout.includes('DNS_FAIL') && !r.stdout.includes('timed out'),
        r.stdout.substring(0, 80))
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
