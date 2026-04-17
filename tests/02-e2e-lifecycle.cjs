/**
 * Test Suite 2: End-to-End Lifecycle
 *
 * Simulates the complete RFC production lifecycle:
 *   Phase A (image layer): proxy + nft rules → snapshot
 *   Phase B (runtime): prep requests → activate MITM → verify
 */

const {
  getApiKey, TestSuite, exec, setupSandbox, startProxy,
  loadNftRules, snapshotRestore, killSandbox,
  writeTcpConnect, tcpConnect, tcpConnectAsMitmproxy,
} = require('./helpers.cjs')

async function run() {
  const apiKey = getApiKey()
  const suite = new TestSuite('02-e2e-lifecycle')

  console.log('╔═══════════════════════════════════════════════╗')
  console.log('║  Test 02: End-to-End Lifecycle                ║')
  console.log('╚═══════════════════════════════════════════════╝\n')

  let sandbox
  try {
    sandbox = await setupSandbox(apiKey)
    await startProxy(sandbox)
    await loadNftRules(sandbox)
    await writeTcpConnect(sandbox)

    // Phase A → snapshot
    console.log('\n--- Phase A: Image layer → snapshot ---\n')
    sandbox = await snapshotRestore(sandbox, apiKey)

    // Phase B: runtime
    console.log('\n--- Phase B: Sandbox instance (after restore) ---\n')

    // B1: proxy alive
    {
      const r = await exec(sandbox, 'curl -s http://127.0.0.1:18080/__health')
      suite.record('B1: Proxy alive after restore (passthrough mode)',
        r.stdout.includes('"ok"') && r.stdout.includes('passthrough'), r.stdout)
    }

    // B2: prep phase — root requests go through proxy
    {
      const r = await exec(sandbox, 'curl -s --connect-timeout 3 http://198.18.0.1/prep-datadog-log')
      suite.record('B2: Prep request (simulating Datadog) → intercepted by proxy',
        r.stdout.includes('OK') && r.stdout.includes('passthrough'), r.stdout)
    }
    {
      const r = await exec(sandbox, 'curl -s --connect-timeout 3 http://198.18.0.1/prep-git-clone')
      suite.record('B3: Prep request (simulating git clone) → intercepted by proxy',
        r.stdout.includes('OK'), r.stdout)
    }

    // B3: proxy outbound NOT looped (P0 scenario)
    {
      const h1 = await exec(sandbox, 'curl -s http://127.0.0.1:18080/__health')
      const before = JSON.parse(h1.stdout || '{}').tls_conns || 0

      await tcpConnectAsMitmproxy(sandbox, '198.18.0.1', 443)

      const h2 = await exec(sandbox, 'curl -s http://127.0.0.1:18080/__health')
      const after = JSON.parse(h2.stdout || '{}').tls_conns || 0

      suite.record('B4: Proxy HTTPS outbound NOT looped (TLS conn count unchanged)',
        after === before, `TLS connections: before=${before} after=${after}`)
    }

    // B4: activate MITM
    {
      const r = await exec(sandbox, 'curl -s -X POST http://127.0.0.1:18080/__activate-mitm')
      suite.record('B5: MITM activation succeeds',
        r.stdout.includes('activated'), r.stdout)
    }

    // B5: post-activation, proxy works in mitm mode
    {
      const r = await exec(sandbox, 'curl -s --connect-timeout 3 http://198.18.0.1/post-mitm-request')
      suite.record('B6: Post-MITM request → intercepted (mitm mode)',
        r.stdout.includes('OK') && r.stdout.includes('mitm'), r.stdout)
    }

    // B6: post-activation, HTTPS still redirected
    {
      const r = await tcpConnect(sandbox, '198.18.0.1', 443)
      suite.record('B7: HTTPS REDIRECT still works after MITM activation',
        r.stdout.includes('TLS_PASSTHROUGH_REACHED'), r.stdout)
    }

    // B7: post-activation, proxy outbound still exempt
    {
      const r = await tcpConnectAsMitmproxy(sandbox, '198.18.0.1', 443)
      suite.record('B8: Proxy outbound still exempt after MITM activation',
        !r.stdout.includes('TLS_PASSTHROUGH_REACHED'), r.stdout)
    }

    // B8: nft counters
    {
      await exec(sandbox, 'nft reset counters 2>/dev/null')
      await exec(sandbox, 'curl -s --connect-timeout 2 http://198.18.0.1/counter-root > /dev/null 2>&1; true')
      await exec(sandbox, 'sudo -u mitmproxy curl -s --connect-timeout 2 http://198.18.0.1/counter-proxy > /dev/null 2>&1; true')
      await exec(sandbox, 'sleep 1')
      const r = await exec(sandbox, 'nft list ruleset')
      const skuidMatch = r.stdout.match(/meta skuid \d+ counter packets (\d+)/)
      const redirectMatch = r.stdout.match(/tcp dport 80 counter packets (\d+)/)
      const skuidPkts = skuidMatch ? parseInt(skuidMatch[1]) : -1
      const redirectPkts = redirectMatch ? parseInt(redirectMatch[1]) : -1
      suite.record('B9: nft counters confirm traffic split',
        skuidPkts > 0 && redirectPkts > 0,
        `skuid(exempt): ${skuidPkts} pkts, redirect(root): ${redirectPkts} pkts`)
    }

  } catch (e) {
    console.error('FATAL:', e.message)
  } finally {
    if (sandbox) await killSandbox(sandbox, apiKey)
  }

  return suite.summary()
}

run().then(ok => process.exit(ok ? 0 : 1))
