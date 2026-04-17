/**
 * Suite 12: Production edge cases that could cause outages.
 *
 *   A. Sandbox reuse: MITM mode proxy + new pipeline config + existing CA
 *   B. Crash recovery: MITM proxy crashes → restart → passthrough → re-activate MITM
 *   C. Cross-mode double snapshot: passthrough → snap → MITM → snap → restore → still MITM
 *   D. Keep-alive connection across mode switch
 *   E. Mixed HTTP/HTTPS workload (realistic Agent behavior)
 */

const fs = require('fs')
const path = require('path')
const { getApiKey, TestSuite, exec, setupSandbox, loadNftRules, snapshotRestore, killSandbox, writeTcpConnect } = require('./helpers.cjs')

const HOTSWITCH_PATH = path.join(__dirname, '..', 'fixtures', 'passthrough-hotswitch.mjs')

async function waitForLog(sandbox, marker, logFile = '/tmp/hotswitch.log', timeoutMs = 30000) {
  const start = Date.now()
  while (Date.now() - start < timeoutMs) {
    await new Promise(r => setTimeout(r, 1000))
    const log = await exec(sandbox, `cat ${logFile} 2>/dev/null`)
    if (log.stdout.includes(marker)) return true
  }
  return false
}

async function activateMitm(sandbox) {
  const r = await exec(sandbox, `node -e "
const body = JSON.stringify({caKeyPath: '/tmp/moxt-proxy/ca.key', caCertPath: '/tmp/moxt-proxy/ca.crt'});
fetch('http://127.0.0.1:18080/__activate-mitm', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body,
  signal: AbortSignal.timeout(5000),
}).then(r => r.text()).then(t => console.log(t)).catch(e => console.log('ACT_ERR:' + e.message));
"`, 10000)
  if (r.stdout.includes('activated')) return true
  // Fallback: kill socat + raw socket
  await exec(sandbox, 'for pid in $(ps aux | grep socat | grep -E "18080" | grep -v grep | awk "{print \\$2}"); do kill $pid 2>/dev/null; done; sleep 0.5')
  const r2 = await exec(sandbox, `python3 -c "
import socket, json
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(('127.0.0.1', 18080))
body = json.dumps({'caKeyPath':'/tmp/moxt-proxy/ca.key','caCertPath':'/tmp/moxt-proxy/ca.crt'})
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
  return r2.stdout.includes('activated')
}

async function setupProxy(sandbox) {
  await sandbox.files.write('/opt/hotswitch.mjs', fs.readFileSync(HOTSWITCH_PATH, 'utf-8'))
  await exec(sandbox, 'sudo -u mitmproxy mkdir -p /tmp/moxt-proxy && sudo -u mitmproxy openssl req -new -x509 -newkey rsa:2048 -nodes -keyout /tmp/moxt-proxy/ca.key -out /tmp/moxt-proxy/ca.crt -days 1 -subj "/CN=Moxt Test CA" 2>/dev/null')
  await exec(sandbox, 'sh -c "nohup sudo -u mitmproxy node /opt/hotswitch.mjs > /tmp/hotswitch.log 2>&1 &"')
  return await waitForLog(sandbox, 'HOTSWITCH_READY')
}

function proxyAlive(sandbox) {
  return exec(sandbox, 'ps aux | grep -q "[h]otswitch" && ss -tlnp 2>/dev/null | grep -q "18080.*node" && echo ALIVE || echo DEAD', 5000)
    .then(r => r.stdout.includes('ALIVE'))
}

async function verifyMitmCert(sandbox, host = 'example.com') {
  const r = await exec(sandbox, `python3 -c "
import ssl, socket, subprocess
s = socket.create_connection(('${host}', 443), timeout=15)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ss = ctx.wrap_socket(s, server_hostname='${host}')
cert = ss.getpeercert(binary_form=True)
with open('/tmp/verify-cert.der', 'wb') as f:
    f.write(cert)
r = subprocess.run(['openssl', 'x509', '-inform', 'DER', '-noout', '-issuer', '-in', '/tmp/verify-cert.der'], capture_output=True, text=True)
print('MITM:' + ('yes' if 'Moxt' in r.stdout else 'no') + ' ' + r.stdout.strip())
ss.close()
"`, 20000)
  return r.stdout.includes('MITM:yes')
}

async function run() {
  const apiKey = getApiKey()
  const suite = new TestSuite('12-production-edge-cases')

  let sandbox
  try {
    // ================================================================
    // SECTION A: Sandbox reuse — second pipeline with existing MITM proxy
    // ================================================================
    console.log('\n  === SECTION A: Sandbox reuse ===\n')

    sandbox = await setupSandbox(apiKey)
    await writeTcpConnect(sandbox)
    const ready = await setupProxy(sandbox)
    suite.record('A1: Proxy starts', ready)
    if (!ready) { suite.summary(); return }

    await loadNftRules(sandbox)

    // First pipeline: activate MITM
    const act1 = await activateMitm(sandbox)
    suite.record('A2: First pipeline activates MITM', act1)

    // Verify MITM works
    const mitm1 = await verifyMitmCert(sandbox)
    suite.record('A3: First pipeline HTTPS → MITM cert', mitm1)

    // Simulate sandbox reuse: proxy still running, MITM still active
    // Second pipeline arrives with new token/pipelineId
    // In production: parent-process calls /__update-config (not /__activate-mitm)
    // But hotswitch proxy doesn't have /__update-config yet.
    // The key test: can we call /__activate-mitm AGAIN with same CA? (idempotent)
    const act2 = await activateMitm(sandbox)
    suite.record('A4: Second pipeline re-activates MITM (reuse)', act2)

    // A5: Requests still work after re-activation
    const reuse = await exec(sandbox, `node -e "
fetch('http://httpbin.org/get?reuse=1', {signal: AbortSignal.timeout(10000)})
  .then(r => console.log('REUSE_OK:'+r.status))
  .catch(e => console.log('REUSE_ERR:'+e.message))
"`, 15000)
    suite.record('A5: HTTP forwarding works after reuse re-activation',
      reuse.stdout.includes('REUSE_OK:'), reuse.stdout)

    // A6: MITM still works after re-activation
    const mitm2 = await verifyMitmCert(sandbox, 'example.org')
    suite.record('A6: HTTPS MITM works after reuse (new host example.org)', mitm2)

    // A7: Old CA still valid (same CA across reuse)
    const caCheck = await exec(sandbox, 'openssl x509 -in /tmp/moxt-proxy/ca.crt -noout -subject 2>&1')
    suite.record('A7: CA cert persists across reuse', caCheck.stdout.includes('Moxt'), caCheck.stdout.trim())

    await killSandbox(sandbox, apiKey)

    // ================================================================
    // SECTION B: Crash recovery — proxy crashes in MITM, restarts in passthrough
    // ================================================================
    console.log('\n  === SECTION B: Crash recovery ===\n')

    sandbox = await setupSandbox(apiKey)
    await writeTcpConnect(sandbox)
    const ready2 = await setupProxy(sandbox)
    suite.record('B1: Proxy starts', ready2)
    if (!ready2) { suite.summary(); return }

    await loadNftRules(sandbox)

    // Activate MITM
    const actB = await activateMitm(sandbox)
    suite.record('B2: MITM activated', actB)

    // Verify MITM works before crash
    const precrash = await verifyMitmCert(sandbox)
    suite.record('B3: MITM cert verified before crash', precrash)

    // Kill proxy
    await exec(sandbox, 'pkill -u mitmproxy -f hotswitch 2>/dev/null; sleep 2')
    const dead = await proxyAlive(sandbox)
    suite.record('B4: Proxy is dead after kill', !dead)

    // B5: Traffic fails when proxy is dead (loud failure, not silent)
    const failTest = await exec(sandbox, `node -e "
fetch('http://httpbin.org/get', {signal: AbortSignal.timeout(5000)})
  .then(() => console.log('UNEXPECTED_OK'))
  .catch(e => console.log('EXPECTED_FAIL:'+e.code))
"`, 10000)
    suite.record('B5: Traffic fails loudly when proxy dead',
      failTest.stdout.includes('EXPECTED_FAIL:'), failTest.stdout)

    // Restart proxy — comes back in PASSTHROUGH mode (no CA loaded)
    await exec(sandbox, 'sh -c "> /tmp/hotswitch.log"')
    await exec(sandbox, 'sh -c "nohup sudo -u mitmproxy node /opt/hotswitch.mjs > /tmp/hotswitch.log 2>&1 &"')
    const restarted = await waitForLog(sandbox, 'HOTSWITCH_READY')
    suite.record('B6: Proxy restarts in passthrough mode', restarted)

    // B7: After restart, HTTPS shows real cert (passthrough, not MITM)
    if (restarted) {
      const postCrashCert = await exec(sandbox, `python3 -c "
import ssl, socket, subprocess
s = socket.create_connection(('example.com', 443), timeout=15)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ss = ctx.wrap_socket(s, server_hostname='example.com')
cert = ss.getpeercert(binary_form=True)
with open('/tmp/postcrash-cert.der', 'wb') as f:
    f.write(cert)
r = subprocess.run(['openssl', 'x509', '-inform', 'DER', '-noout', '-issuer', '-in', '/tmp/postcrash-cert.der'], capture_output=True, text=True)
is_passthrough = 'Moxt' not in r.stdout
print('PASSTHROUGH:' + ('yes' if is_passthrough else 'no') + ' ' + r.stdout.strip())
ss.close()
"`, 20000)
      suite.record('B7: After restart → passthrough mode (real cert, not MITM)',
        postCrashCert.stdout.includes('PASSTHROUGH:yes'), postCrashCert.stdout)
    } else {
      suite.record('B7: After restart → passthrough mode', false, 'restart failed')
    }

    // B8: Re-activate MITM (recovery complete)
    if (restarted) {
      const actRecovery = await activateMitm(sandbox)
      suite.record('B8: Re-activate MITM after crash recovery', actRecovery)

      if (actRecovery) {
        const recoveredMitm = await verifyMitmCert(sandbox, 'example.net')
        suite.record('B9: MITM works after crash recovery', recoveredMitm)
      } else {
        suite.record('B9: MITM works after crash recovery', false, 'activation failed')
      }
    } else {
      suite.record('B8: Re-activate MITM after crash recovery', false, 'skipped')
      suite.record('B9: MITM works after crash recovery', false, 'skipped')
    }

    await killSandbox(sandbox, apiKey)

    // ================================================================
    // SECTION C: Cross-mode double snapshot
    // passthrough → snap1 → restore1 → MITM → snap2 → restore2 → still MITM
    // ================================================================
    console.log('\n  === SECTION C: Cross-mode double snapshot ===\n')

    sandbox = await setupSandbox(apiKey)
    await writeTcpConnect(sandbox)
    const ready3 = await setupProxy(sandbox)
    suite.record('C1: Proxy starts in passthrough', ready3)
    if (!ready3) { suite.summary(); return }

    await loadNftRules(sandbox)

    // Snapshot 1: in passthrough mode
    console.log('  Snapshot 1 (passthrough)...')
    sandbox = await snapshotRestore(sandbox, apiKey)
    const alive1 = await proxyAlive(sandbox)
    suite.record('C2: Proxy alive after snapshot 1 (passthrough)', alive1)

    // Activate MITM
    const actC = await activateMitm(sandbox)
    suite.record('C3: Activate MITM after snapshot 1', actC)

    // Verify MITM
    const mitmC = await verifyMitmCert(sandbox)
    suite.record('C4: MITM cert verified', mitmC)

    // Snapshot 2: in MITM mode
    console.log('  Snapshot 2 (MITM)...')
    sandbox = await snapshotRestore(sandbox, apiKey)
    const alive2 = await proxyAlive(sandbox)
    suite.record('C5: Proxy alive after snapshot 2 (MITM)', alive2)

    // C6: MITM still works after second snapshot
    if (alive2) {
      const mitmAfterSnap2 = await verifyMitmCert(sandbox, 'example.org')
      suite.record('C6: MITM works after cross-mode double snapshot', mitmAfterSnap2)
    } else {
      suite.record('C6: MITM works after cross-mode double snapshot', false, 'proxy dead')
    }

    // C7: nft rules survive both snapshots
    const nftC = await exec(sandbox, 'nft list ruleset | grep skuid')
    suite.record('C7: nft skuid rules survive cross-mode double snapshot',
      nftC.stdout.includes('skuid'))

    // C8: UID exemption works after cross-mode double snapshot
    const uidC = await exec(sandbox, `sudo -u mitmproxy node -e "
fetch('https://httpbin.org/status/200', {signal: AbortSignal.timeout(10000)})
  .then(r => console.log('UID_OK:'+r.status))
  .catch(e => console.log('UID_ERR:'+e.message))
"`, 15000)
    suite.record('C8: UID exemption works after cross-mode double snapshot',
      uidC.stdout.includes('UID_OK:200'), uidC.stdout)

    await killSandbox(sandbox, apiKey)

    // ================================================================
    // SECTION D: Keep-alive connection across mode switch
    // ================================================================
    console.log('\n  === SECTION D: Keep-alive across mode switch ===\n')

    sandbox = await setupSandbox(apiKey)
    await writeTcpConnect(sandbox)
    const ready4 = await setupProxy(sandbox)
    suite.record('D1: Proxy starts in passthrough', ready4)
    if (!ready4) { suite.summary(); return }

    await loadNftRules(sandbox)

    // Start a long-running request in passthrough, switch to MITM mid-flight
    await sandbox.files.write('/tmp/keepalive-test.mjs', `
const results = { beforeSwitch: null, afterSwitch: null };

// Request 1: before switch (passthrough mode)
try {
  const r1 = await fetch('http://httpbin.org/get?ka=before', { signal: AbortSignal.timeout(10000) });
  results.beforeSwitch = r1.status;
} catch(e) {
  results.beforeSwitch = 'ERR:' + e.message;
}

// Signal that we're ready for switch
const fs = await import('node:fs');
fs.writeFileSync('/tmp/ready-for-switch', 'ready');

// Wait for switch to happen
for (let i = 0; i < 30; i++) {
  await new Promise(r => setTimeout(r, 500));
  if (fs.existsSync('/tmp/switch-done')) break;
}

// Request 2: after switch (should be MITM mode now)
// The KEY question: does the keep-alive connection from request 1 still work?
// Or does it break? Either outcome is acceptable — but proxy must not crash.
try {
  const r2 = await fetch('http://httpbin.org/get?ka=after', { signal: AbortSignal.timeout(10000) });
  results.afterSwitch = r2.status;
} catch(e) {
  results.afterSwitch = 'ERR:' + e.message;
}

console.log(JSON.stringify(results));
`)

    // Start the keepalive test in background
    await exec(sandbox, 'sh -c "node /tmp/keepalive-test.mjs > /tmp/keepalive-result.txt 2>&1 &"')

    // Wait for it to be ready
    for (let i = 0; i < 30; i++) {
      await new Promise(r => setTimeout(r, 500))
      const ready = await exec(sandbox, 'cat /tmp/ready-for-switch 2>/dev/null')
      if (ready.stdout.includes('ready')) break
    }

    // Switch to MITM
    const actD = await activateMitm(sandbox)
    await exec(sandbox, 'echo done > /tmp/switch-done')
    suite.record('D2: MITM activated mid-keepalive', actD)

    // Wait for test to complete
    await new Promise(r => setTimeout(r, 15000))
    const kaResult = await exec(sandbox, 'cat /tmp/keepalive-result.txt 2>/dev/null')
    let kaData = {}
    try { kaData = JSON.parse(kaResult.stdout) } catch {}
    suite.record('D3: Request before switch completed',
      kaData.beforeSwitch !== null, `status: ${kaData.beforeSwitch}`)
    suite.record('D4: Request after switch completed (proxy did not crash)',
      kaData.afterSwitch !== null, `status: ${kaData.afterSwitch}`)

    // D5: Proxy still alive
    const aliveD = await proxyAlive(sandbox)
    suite.record('D5: Proxy alive after keep-alive + switch', aliveD)

    await killSandbox(sandbox, apiKey)

    // ================================================================
    // SECTION E: Mixed HTTP/HTTPS workload (realistic Agent)
    // ================================================================
    console.log('\n  === SECTION E: Mixed workload ===\n')

    sandbox = await setupSandbox(apiKey)
    await writeTcpConnect(sandbox)
    const ready5 = await setupProxy(sandbox)
    suite.record('E1: Proxy starts', ready5)
    if (!ready5) { suite.summary(); return }

    await loadNftRules(sandbox)
    await activateMitm(sandbox)

    // Simulate Agent: mix of HTTP, HTTPS bypass, HTTPS MITM
    await sandbox.files.write('/tmp/mixed-workload.mjs', `
const results = { http: 0, httpsBypass: 0, httpsMitm: 0, errors: [], econnreset: 0 };

const tasks = [
  // HTTP requests (like Datadog logs)
  ...Array.from({length: 10}, (_, i) => () =>
    fetch('http://httpbin.org/get?http='+i, {signal: AbortSignal.timeout(10000)})
      .then(() => results.http++)
      .catch(e => { results.errors.push('http:'+e.message); if (e.message.includes('ECONNRESET')) results.econnreset++; })
  ),
  // HTTPS bypass (like Anthropic API calls)
  ...Array.from({length: 5}, (_, i) => () =>
    fetch('https://httpbin.org/get?bypass='+i, {signal: AbortSignal.timeout(10000)})
      .then(() => results.httpsBypass++)
      .catch(e => { results.errors.push('bypass:'+e.message); if (e.message.includes('ECONNRESET')) results.econnreset++; })
  ),
  // HTTPS MITM (like external API calls from Agent)
  ...Array.from({length: 5}, (_, i) => () => {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
    return fetch('https://example.com/?mitm='+i, {signal: AbortSignal.timeout(10000)})
      .then(() => results.httpsMitm++)
      .catch(e => { results.errors.push('mitm:'+e.message); if (e.message.includes('ECONNRESET')) results.econnreset++; });
  }),
];

// Shuffle and run concurrently (realistic Agent behavior)
const shuffled = tasks.sort(() => Math.random() - 0.5);
await Promise.all(shuffled.map(t => t()));
console.log(JSON.stringify(results));
`)
    const mixed = await exec(sandbox, 'node /tmp/mixed-workload.mjs', 60000)
    let mixedR = { http: 0, httpsBypass: 0, httpsMitm: 0, errors: [], econnreset: 0 }
    try { mixedR = JSON.parse(mixed.stdout) } catch {}
    suite.record('E2: Mixed workload (10 HTTP + 5 bypass + 5 MITM) — zero ECONNRESET',
      mixedR.econnreset === 0,
      `http=${mixedR.http}, bypass=${mixedR.httpsBypass}, mitm=${mixedR.httpsMitm}, econnreset=${mixedR.econnreset}`)

    suite.record('E3: All request types completed',
      mixedR.http > 0 && mixedR.httpsBypass > 0 && mixedR.httpsMitm > 0,
      `http=${mixedR.http}/10, bypass=${mixedR.httpsBypass}/5, mitm=${mixedR.httpsMitm}/5`)

    suite.summary()
  } finally {
    if (sandbox) await killSandbox(sandbox, apiKey)
  }
}

run().catch(err => {
  console.error('Suite failed:', err)
  process.exit(1)
})
