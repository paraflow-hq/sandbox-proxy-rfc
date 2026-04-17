/**
 * Suite 16: setStartCmd template build path validation.
 *
 * This is the ONE remaining gap in the RFC evidence base:
 * All 253 prior tests use runtime setup (apt-get + useradd + start proxy + load nft).
 * Production uses setStartCmd build path (proxy + nft baked into Firecracker snapshot).
 *
 * This suite builds a real E2B template with setStartCmd, creates sandboxes from it,
 * and validates that proxy + nft rules survive the template build → snapshot → restore cycle.
 *
 * Tests:
 *   A. Template build: proxy + nft via setStartCmd
 *   B. Sandbox from template: proxy alive, nft rules present, UID exemption works
 *   C. Snapshot/restore from template-based sandbox
 *   D. Multiple sandboxes from same template (isolation)
 *   E. Full RFC lifecycle on template-built sandbox (passthrough → activate MITM simulation)
 */

const fs = require('fs')
const path = require('path')
const { getApiKey, TestSuite, exec, killSandbox, snapshotRestore, writeTcpConnect, tcpConnect, tcpConnectAsMitmproxy } = require('./helpers.cjs')
const { Template, Sandbox, waitForPort } = require('e2b')

const PROXY_PY = fs.readFileSync(path.join(__dirname, '..', 'fixtures', 'proxy.py'), 'utf-8')
const NFT_RULES = fs.readFileSync(path.join(__dirname, '..', 'fixtures', 'nft-rules.conf'), 'utf-8')

const TEMPLATE_ALIAS = `rfc-setStartCmd-test-${Date.now()}`

async function run() {
  const apiKey = getApiKey()
  const suite = new TestSuite('16-setStartCmd-template-build')
  let templateId = null
  const sandboxes = []

  try {
    // ================================================================
    // SECTION A: Build template with setStartCmd
    // ================================================================
    console.log('\n  === SECTION A: Template build with setStartCmd ===\n')

    // Build a template that:
    // 1. Installs nftables
    // 2. Creates mitmproxy user
    // 3. Copies proxy + nft rules
    // 4. setStartCmd: starts proxy as mitmproxy user + loads nft rules
    console.log('  Building template (this may take 2-5 minutes)...')

    const buildLogs = []
    const template = Template()
      .fromTemplate('base')
      .setUser('root')
      .runCmd('apt-get update -qq && apt-get install -y -qq nftables curl netcat-openbsd ca-certificates python3 2>/dev/null')
      .runCmd('useradd -r -M -s /usr/sbin/nologin mitmproxy')
      .runCmd('mkdir -p /opt/moxt-proxy')
      .runCmd(`cat > /opt/moxt-proxy/proxy.py << 'PYEOF'
${PROXY_PY}
PYEOF`)
      .runCmd(`cat > /opt/moxt-proxy/nft-rules.conf << 'NFTEOF'
${NFT_RULES}
NFTEOF`)
      .runCmd('chmod 644 /opt/moxt-proxy/proxy.py /opt/moxt-proxy/nft-rules.conf')
      .setStartCmd(
        'sh -c "sudo -u mitmproxy python3 /opt/moxt-proxy/proxy.py & sleep 1 && nft -f /opt/moxt-proxy/nft-rules.conf && wait"',
        waitForPort(18080)
      )

    const buildStart = Date.now()
    const buildInfo = await Template.build(template, {
      alias: TEMPLATE_ALIAS,
      apiKey,
      onBuildLogs: (log) => {
        buildLogs.push(log)
        if (log.message) {
          const msg = log.message.trim()
          if (msg && !msg.startsWith('Selecting') && !msg.startsWith('Preparing') && !msg.startsWith('Unpacking')) {
            console.log(`    [build] ${msg.substring(0, 120)}`)
          }
        }
      },
    })
    const buildDuration = ((Date.now() - buildStart) / 1000).toFixed(1)
    templateId = buildInfo.templateId

    suite.record('A1: Template built successfully',
      !!templateId,
      `templateId=${templateId}, alias=${TEMPLATE_ALIAS}, ${buildDuration}s`)

    if (!templateId) {
      console.log('  Template build failed, cannot continue')
      suite.summary()
      return
    }

    // ================================================================
    // SECTION B: Create sandbox from template — verify proxy + nft from birth
    // ================================================================
    console.log('\n  === SECTION B: Sandbox from template (proxy + nft from birth) ===\n')

    console.log(`  Creating sandbox from template ${templateId}...`)
    const sandbox = await Sandbox.create(templateId, { apiKey, timeoutMs: 5 * 60 * 1000 })
    sandboxes.push(sandbox)
    console.log(`  Sandbox: ${sandbox.sandboxId}`)

    // B1: Proxy is running (started by setStartCmd, survived snapshot)
    const proxyCheck = await exec(sandbox, 'ps aux | grep -q "[p]roxy.py" && echo ALIVE || echo DEAD')
    suite.record('B1: Proxy process alive (from setStartCmd snapshot)',
      proxyCheck.stdout.includes('ALIVE'), proxyCheck.stdout.trim())

    // B2: Proxy health check responds
    // Note: socat may intercept 127.0.0.1, use raw socket fallback
    let healthOk = false
    const healthCheck = await exec(sandbox, 'curl -s http://127.0.0.1:18080/__health 2>/dev/null')
    if (healthCheck.stdout.includes('"ok"')) {
      healthOk = true
    } else {
      // socat fallback
      const rawHealth = await exec(sandbox, `python3 -c "
import socket, json
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(('127.0.0.1', 18080))
s.sendall(b'GET /__health HTTP/1.1\\r\\nHost: 127.0.0.1\\r\\nConnection: close\\r\\n\\r\\n')
data=b''
while True:
    try:
        c=s.recv(4096)
        if not c:break
        data+=c
    except:break
s.close()
print(data.decode())
"`, 10000)
      healthOk = rawHealth.stdout.includes('"ok"')
    }
    suite.record('B2: Proxy health check OK', healthOk)

    // B3: Proxy runs as mitmproxy user
    // ps -eo truncates usernames; use stat on /proc/<pid> for real UID
    const proxyUid = await exec(sandbox, `python3 -c "
import subprocess, os
r = subprocess.run(['pgrep', '-f', 'python3 /opt/moxt-proxy/proxy.py'], capture_output=True, text=True)
pids = [p.strip() for p in r.stdout.strip().split() if p.strip()]
for pid in pids:
    try:
        uid = open(f'/proc/{pid}/status').read()
        for line in uid.split('\\\\n'):
            if line.startswith('Uid:'):
                real_uid = line.split()[1]
                import pwd
                user = pwd.getpwuid(int(real_uid)).pw_name
                print(f'PID={pid} UID={real_uid} USER={user}')
    except: pass
"`)
    const mitmproxyLine = proxyUid.stdout.split('\n').find(l => l.includes('USER=mitmproxy'))
    suite.record('B3: Proxy python3 process runs as mitmproxy user',
      !!mitmproxyLine,
      proxyUid.stdout.trim())

    // B4: nft rules are present (from setStartCmd, survived snapshot)
    const nftRules = await exec(sandbox, 'nft list ruleset 2>/dev/null')
    const hasSkuid = nftRules.stdout.includes('skuid')
    const hasRedirect80 = nftRules.stdout.includes('dport 80') && nftRules.stdout.includes('redirect')
    const hasRedirect443 = nftRules.stdout.includes('dport 443') && nftRules.stdout.includes('redirect')
    suite.record('B4: nft rules present (skuid + redirect 80 + redirect 443)',
      hasSkuid && hasRedirect80 && hasRedirect443,
      `skuid=${hasSkuid}, redirect80=${hasRedirect80}, redirect443=${hasRedirect443}`)

    // B5: nft counter shows zero initially (clean from snapshot)
    const counters = await exec(sandbox, 'nft list ruleset 2>/dev/null')
    suite.record('B5: nft counters present in ruleset',
      counters.stdout.includes('counter packets'),
      counters.stdout.match(/counter packets \d+/g)?.join(', ') || 'no counters found')

    // B6: HTTP traffic from root is redirected to proxy
    await writeTcpConnect(sandbox)
    const httpIntercept = await exec(sandbox, 'curl -s http://httpbin.org/get 2>/dev/null', 15000)
    const httpIntercepted = httpIntercept.stdout.includes('OK path=') || httpIntercept.stdout.includes('mode=')
    suite.record('B6: Root HTTP traffic redirected to proxy',
      httpIntercepted, httpIntercept.stdout.substring(0, 100))

    // B7: mitmproxy user traffic is NOT redirected (UID exemption)
    const mitmproxyDirect = await exec(sandbox,
      'sudo -u mitmproxy curl -s --max-time 10 http://httpbin.org/get 2>/dev/null', 15000)
    const isDirectResponse = mitmproxyDirect.stdout.includes('"url"') || mitmproxyDirect.stdout.includes('httpbin')
    const notProxied = !mitmproxyDirect.stdout.includes('OK path=')
    suite.record('B7: mitmproxy user HTTP bypasses proxy (UID exemption)',
      isDirectResponse && notProxied,
      `direct=${isDirectResponse}, notProxied=${notProxied}`)

    // B8: HTTPS traffic from root hits proxy TLS port
    const tlsIntercept = await tcpConnect(sandbox, 'example.com', 443)
    suite.record('B8: Root HTTPS traffic redirected to proxy TLS port',
      tlsIntercept.stdout.includes('TLS_PASSTHROUGH_REACHED'),
      tlsIntercept.stdout.substring(0, 80))

    // B9: mitmproxy user HTTPS bypasses proxy
    const mitmproxyHttps = await exec(sandbox,
      'sudo -u mitmproxy curl -sk --max-time 10 https://httpbin.org/status/200 2>/dev/null; echo EXIT:$?', 15000)
    suite.record('B9: mitmproxy user HTTPS bypasses proxy',
      mitmproxyHttps.stdout.includes('EXIT:0'),
      mitmproxyHttps.stdout.substring(0, 80))

    // B10: nft counters incremented after traffic
    const countersAfter = await exec(sandbox, 'nft list ruleset 2>/dev/null')
    const skuidMatch = countersAfter.stdout.match(/skuid.*counter packets (\d+)/)
    const redirectMatch = countersAfter.stdout.match(/dport 80.*counter packets (\d+)/)
    const skuidPackets = skuidMatch ? parseInt(skuidMatch[1]) : 0
    const redirectPackets = redirectMatch ? parseInt(redirectMatch[1]) : 0
    suite.record('B10: nft counters show traffic (skuid > 0, redirect > 0)',
      skuidPackets > 0 && redirectPackets > 0,
      `skuid=${skuidPackets}, redirect=${redirectPackets}`)

    // ================================================================
    // SECTION C: Snapshot/restore from template-based sandbox
    // ================================================================
    console.log('\n  === SECTION C: Snapshot/restore ===\n')

    const restored = await snapshotRestore(sandbox, apiKey)
    sandboxes.push(restored)

    // C1: Proxy alive after restore
    const proxyAfter = await exec(restored, 'ps aux | grep -q "[p]roxy.py" && echo ALIVE || echo DEAD')
    suite.record('C1: Proxy alive after snapshot/restore',
      proxyAfter.stdout.includes('ALIVE'))

    // C2: nft rules survive restore
    const nftAfter = await exec(restored, 'nft list ruleset 2>/dev/null')
    suite.record('C2: nft rules survive snapshot/restore',
      nftAfter.stdout.includes('skuid') && nftAfter.stdout.includes('redirect'))

    // C3: UID exemption still works after restore
    const interceptAfterRestore = await exec(restored, 'curl -s http://httpbin.org/get 2>/dev/null', 15000)
    suite.record('C3: HTTP interception works after restore',
      interceptAfterRestore.stdout.includes('OK path=') || interceptAfterRestore.stdout.includes('mode='))

    // C4: mitmproxy bypass still works after restore
    const bypassAfterRestore = await exec(restored,
      'sudo -u mitmproxy curl -s --max-time 10 http://httpbin.org/get 2>/dev/null', 15000)
    suite.record('C4: mitmproxy UID exemption works after restore',
      (bypassAfterRestore.stdout.includes('"url"') || bypassAfterRestore.stdout.includes('httpbin'))
      && !bypassAfterRestore.stdout.includes('OK path='))

    // C5: nft counters survived and continue incrementing
    const countersRestore = await exec(restored, 'nft list ruleset 2>/dev/null')
    const skuidAfter = countersRestore.stdout.match(/skuid.*counter packets (\d+)/)
    suite.record('C5: nft counters survived restore',
      skuidAfter && parseInt(skuidAfter[1]) > 0,
      skuidAfter ? `skuid packets=${skuidAfter[1]}` : 'no match')

    // ================================================================
    // SECTION D: Multiple sandboxes from same template (isolation)
    // ================================================================
    console.log('\n  === SECTION D: Multiple sandboxes (isolation) ===\n')

    console.log('  Creating second sandbox from same template...')
    const sandbox2 = await Sandbox.create(templateId, { apiKey, timeoutMs: 5 * 60 * 1000 })
    sandboxes.push(sandbox2)
    console.log(`  Sandbox 2: ${sandbox2.sandboxId}`)

    // D1: Second sandbox has proxy running
    const proxy2 = await exec(sandbox2, 'ps aux | grep -q "[p]roxy.py" && echo ALIVE || echo DEAD')
    suite.record('D1: Second sandbox proxy alive',
      proxy2.stdout.includes('ALIVE'))

    // D2: Second sandbox has nft rules
    const nft2 = await exec(sandbox2, 'nft list ruleset 2>/dev/null')
    suite.record('D2: Second sandbox nft rules present',
      nft2.stdout.includes('skuid') && nft2.stdout.includes('redirect'))

    // D3: Second sandbox HTTP interception works
    const intercept2 = await exec(sandbox2, 'curl -s http://httpbin.org/get 2>/dev/null', 15000)
    suite.record('D3: Second sandbox HTTP interception works',
      intercept2.stdout.includes('OK path=') || intercept2.stdout.includes('mode='))

    // D4: Second sandbox UID exemption works
    const bypass2 = await exec(sandbox2,
      'sudo -u mitmproxy curl -s --max-time 10 http://httpbin.org/get 2>/dev/null', 15000)
    suite.record('D4: Second sandbox UID exemption works',
      (bypass2.stdout.includes('"url"') || bypass2.stdout.includes('httpbin'))
      && !bypass2.stdout.includes('OK path='))

    // D5: Sandboxes are isolated (request to sandbox1 proxy doesn't appear in sandbox2)
    await exec(restored, 'curl -s http://httpbin.org/isolation-test-s1 2>/dev/null', 10000)
    // Check sandbox2 proxy log doesn't have s1's request
    const log2 = await exec(sandbox2, `python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(('127.0.0.1', 18080))
s.sendall(b'GET /__log HTTP/1.1\\r\\nHost: 127.0.0.1\\r\\nConnection: close\\r\\n\\r\\n')
data=b''
while True:
    try:
        c=s.recv(4096)
        if not c:break
        data+=c
    except:break
s.close()
print(data.decode())
"`, 10000)
    suite.record('D5: Sandboxes isolated (s1 request not in s2 log)',
      !log2.stdout.includes('isolation-test-s1'),
      log2.stdout.includes('isolation-test-s1') ? 'LEAKED' : 'isolated')

    // ================================================================
    // SECTION E: Full RFC lifecycle on template-built sandbox
    // ================================================================
    console.log('\n  === SECTION E: RFC lifecycle (passthrough → MITM simulation) ===\n')

    console.log('  Creating fresh sandbox for lifecycle test...')
    const sandbox3 = await Sandbox.create(templateId, { apiKey, timeoutMs: 5 * 60 * 1000 })
    sandboxes.push(sandbox3)
    console.log(`  Sandbox 3: ${sandbox3.sandboxId}`)

    // E1: Simulate prep phase — multiple HTTP requests (like Datadog logs + progress)
    const prepResult = await exec(sandbox3, `node -e "
async function prep() {
  const results = [];
  for (let i = 0; i < 20; i++) {
    try {
      const r = await fetch('http://httpbin.org/get?prep=' + i, { signal: AbortSignal.timeout(10000) });
      results.push({ i, ok: r.ok, status: r.status });
    } catch (e) {
      results.push({ i, error: e.code || e.message });
    }
  }
  console.log(JSON.stringify({ total: results.length, errors: results.filter(r => r.error) }));
}
prep();
"`, 120000)
    let prepParsed
    try { prepParsed = JSON.parse(prepResult.stdout) } catch { prepParsed = null }
    suite.record('E1: Prep phase 20 requests — zero errors',
      prepParsed && prepParsed.errors.length === 0,
      prepResult.stdout.substring(0, 100))

    // E2: Prep phase produces zero ECONNRESET
    const hasEconnreset = prepResult.stdout.includes('ECONNRESET')
    suite.record('E2: Zero ECONNRESET in prep phase',
      !hasEconnreset)

    // E3: Simulate activateMitm — POST to /__activate-mitm
    const activateResult = await exec(sandbox3, `python3 -c "
import socket, json
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(('127.0.0.1', 18080))
body = json.dumps({'caCertPath':'/tmp/ca.crt','caKeyPath':'/tmp/ca.key'})
req = 'POST /__activate-mitm HTTP/1.1\\r\\nHost: 127.0.0.1\\r\\nContent-Type: application/json\\r\\nContent-Length: '+str(len(body))+'\\r\\nConnection: close\\r\\n\\r\\n'+body
s.sendall(req.encode())
data=b''
while True:
    try:
        c=s.recv(4096)
        if not c:break
        data+=c
    except:break
s.close()
print(data.decode())
"`, 10000)
    suite.record('E3: /__activate-mitm succeeds (mode switch)',
      activateResult.stdout.includes('activated'))

    // E4: After activation, proxy reports mitm mode
    const modeCheck = await exec(sandbox3, `python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(('127.0.0.1', 18080))
s.sendall(b'GET /__health HTTP/1.1\\r\\nHost: 127.0.0.1\\r\\nConnection: close\\r\\n\\r\\n')
data=b''
while True:
    try:
        c=s.recv(4096)
        if not c:break
        data+=c
    except:break
s.close()
print(data.decode())
"`, 10000)
    suite.record('E4: Proxy reports mitm mode after activation',
      modeCheck.stdout.includes('"mitm"'))

    // E5: Post-activation HTTP still works
    const postActivation = await exec(sandbox3, 'curl -s http://httpbin.org/get?post_activate=1 2>/dev/null', 15000)
    suite.record('E5: HTTP works after MITM activation',
      postActivation.stdout.includes('OK path=') || postActivation.stdout.includes('mode='))

    // E6: Snapshot/restore after MITM activation
    console.log('  Snapshot/restore after MITM activation...')
    const restored3 = await snapshotRestore(sandbox3, apiKey)
    sandboxes.push(restored3)

    const proxyAfterMitm = await exec(restored3, 'ps aux | grep -q "[p]roxy.py" && echo ALIVE || echo DEAD')
    suite.record('E6: Proxy alive after post-MITM snapshot/restore',
      proxyAfterMitm.stdout.includes('ALIVE'))

    const nftAfterMitm = await exec(restored3, 'nft list ruleset 2>/dev/null')
    suite.record('E7: nft rules survive post-MITM snapshot/restore',
      nftAfterMitm.stdout.includes('skuid') && nftAfterMitm.stdout.includes('redirect'))

    const interceptAfterMitm = await exec(restored3, 'curl -s http://httpbin.org/get?after_mitm=1 2>/dev/null', 15000)
    suite.record('E8: HTTP interception works after post-MITM restore',
      interceptAfterMitm.stdout.includes('OK path=') || interceptAfterMitm.stdout.includes('mode=mitm'))

  } catch (error) {
    console.error(`\n  FATAL: ${error.message}`)
    console.error(error.stack)
    suite.record('FATAL ERROR', false, error.message)
  } finally {
    // Cleanup: kill all sandboxes
    console.log('\n  === Cleanup ===\n')
    for (const sb of sandboxes) {
      await killSandbox(sb, apiKey)
    }

    // Cleanup: delete template via E2B REST API
    if (templateId) {
      try {
        const resp = await fetch(`https://api.e2b.dev/templates/${templateId}`, {
          method: 'DELETE',
          headers: { 'X-API-Key': apiKey },
        })
        if (resp.ok) {
          console.log(`  [cleanup] Template ${templateId} deleted`)
        } else {
          console.log(`  [cleanup] Template delete HTTP ${resp.status} (manual cleanup: ${TEMPLATE_ALIAS})`)
        }
      } catch (e) {
        console.log(`  [cleanup] Template delete failed: ${e.message} (manual cleanup: ${TEMPLATE_ALIAS})`)
      }
    }
  }

  const allPassed = suite.summary()
  process.exit(allPassed ? 0 : 1)
}

run().catch(e => {
  console.error(e)
  process.exit(1)
})
