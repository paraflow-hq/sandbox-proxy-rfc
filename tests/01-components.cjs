/**
 * Test Suite 1: Component Validation
 *
 * Validates that each building block of the RFC design works in E2B:
 *   - nft meta skuid available in E2B kernel
 *   - iptables REDIRECT works
 *   - UID exemption works
 *   - Proxy starts as mitmproxy user with nologin shell
 *   - Both :18080 and :18443 ports listen
 *   - All of the above survive Firecracker snapshot/restore
 */

const {
  getApiKey, TestSuite, exec, setupSandbox, startProxy,
  loadNftRules, snapshotRestore, killSandbox,
  writeTcpConnect, tcpConnect, tcpConnectAsMitmproxy,
} = require('./helpers.cjs')

async function run() {
  const apiKey = getApiKey()
  const suite = new TestSuite('01-components')

  console.log('╔═══════════════════════════════════════════════╗')
  console.log('║  Test 01: Component Validation                ║')
  console.log('╚═══════════════════════════════════════════════╝\n')

  let sandbox
  try {
    sandbox = await setupSandbox(apiKey)

    // Test: nft meta skuid available
    console.log('\n--- nft kernel support ---\n')
    {
      const r = await exec(sandbox,
        'nft add table ip _test && ' +
        'nft add chain ip _test output "{ type nat hook output priority -100; policy accept; }" && ' +
        'nft add rule ip _test output meta skuid "mitmproxy" accept && ' +
        'nft list chain ip _test output && ' +
        'nft delete table ip _test')
      suite.record('nft meta skuid supported in E2B kernel',
        r.ok && r.stdout.includes('meta skuid'),
        r.ok ? 'rule created and listed' : r.stderr)

      if (!r.ok) {
        console.error('\nFATAL: nft meta skuid not supported. Cannot proceed.')
        return
      }
    }

    // Test: mitmproxy user config
    console.log('\n--- mitmproxy user ---\n')
    {
      const r = await exec(sandbox, 'getent passwd mitmproxy')
      suite.record('mitmproxy user exists with nologin shell',
        r.stdout.includes('nologin'), r.stdout)
    }

    // Start proxy + load rules + write tcp-connect helper
    console.log('\n--- proxy + nft rules ---\n')
    await startProxy(sandbox)
    await loadNftRules(sandbox)
    await writeTcpConnect(sandbox)

    // Test: proxy runs as mitmproxy user
    {
      const r = await exec(sandbox, 'ps aux | grep proxy.py | grep -v grep')
      suite.record('Proxy process runs as mitmproxy user',
        r.stdout.includes('mitmproxy'), r.stdout.split('\n')[0])
    }

    // Test: both ports listening
    {
      const r = await exec(sandbox, 'ss -tlnp | grep -E "18080|18443"')
      suite.record('Proxy listens on :18080 and :18443',
        r.stdout.includes('18080') && r.stdout.includes('18443'))
    }

    // Test: HTTP REDIRECT works (root user)
    {
      const r = await exec(sandbox, 'curl -s --connect-timeout 3 http://198.18.0.1/redirect-test')
      suite.record('Root HTTP :80 traffic REDIRECTED to proxy',
        r.stdout.includes('OK path=/redirect-test'), r.stdout)
    }

    // Test: HTTPS REDIRECT works (root user)
    {
      const r = await tcpConnect(sandbox, '198.18.0.1', 443)
      suite.record('Root HTTPS :443 traffic REDIRECTED to proxy :18443',
        r.stdout.includes('TLS_PASSTHROUGH_REACHED'), r.stdout)
    }

    // Test: UID exemption — mitmproxy user NOT redirected on :80
    {
      await exec(sandbox, 'echo MARKER > /tmp/marker.txt')
      const r = await exec(sandbox,
        'sudo -u mitmproxy curl -s --connect-timeout 2 http://198.18.0.1/marker.txt 2>&1 || echo TIMEOUT')
      suite.record('mitmproxy user HTTP NOT redirected (UID exempt)',
        !r.stdout.includes('MARKER'))
    }

    // Test: UID exemption — mitmproxy user NOT redirected on :443
    {
      const r = await tcpConnectAsMitmproxy(sandbox, '198.18.0.1', 443)
      suite.record('mitmproxy user HTTPS NOT redirected (UID exempt)',
        !r.stdout.includes('TLS_PASSTHROUGH_REACHED'), r.stdout)
    }

    // Snapshot + restore
    console.log('\n--- snapshot/restore ---\n')
    sandbox = await snapshotRestore(sandbox, apiKey)

    // Post-restore checks
    {
      const r = await exec(sandbox, 'nft list ruleset 2>&1 | grep skuid')
      suite.record('nft skuid rules survive snapshot',
        r.stdout.includes('skuid'))
    }
    {
      const r = await exec(sandbox, 'curl -s http://127.0.0.1:18080/__health')
      suite.record('Proxy survives snapshot', r.stdout.includes('"ok"'))
    }
    {
      const r = await exec(sandbox, 'curl -s --connect-timeout 3 http://198.18.0.1/post-restore')
      suite.record('REDIRECT works after restore', r.stdout.includes('OK path=/post-restore'))
    }
    {
      const r = await exec(sandbox,
        'sudo -u mitmproxy curl -s --connect-timeout 2 http://198.18.0.1/exempt-test 2>&1 || echo TIMEOUT')
      suite.record('UID exemption works after restore',
        !r.stdout.includes('OK path=/exempt-test'))
    }

  } catch (e) {
    console.error('FATAL:', e.message)
  } finally {
    if (sandbox) await killSandbox(sandbox, apiKey)
  }

  return suite.summary()
}

run().then(ok => process.exit(ok ? 0 : 1))
