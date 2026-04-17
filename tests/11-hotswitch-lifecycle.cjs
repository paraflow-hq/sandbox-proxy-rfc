/**
 * Suite 11: Hot-switch proxy full lifecycle — the EXACT RFC production sequence.
 *
 * Tests the passthrough-hotswitch.mjs implementation through:
 *   A. Passthrough ECONNRESET proof (RFC core claim)
 *   B. Full lifecycle: passthrough → snapshot → restore → activate MITM → Agent requests
 *   C. Edge cases: idempotent activation, concurrent requests during switch
 */

const fs = require('fs')
const path = require('path')
const { getApiKey, TestSuite, exec, setupSandbox, loadNftRules, snapshotRestore, killSandbox, writeTcpConnect } = require('./helpers.cjs')

const HOTSWITCH_PATH = path.join(__dirname, '..', 'fixtures', 'passthrough-hotswitch.mjs')

async function waitForLog(sandbox, marker, timeoutMs = 30000) {
  const start = Date.now()
  while (Date.now() - start < timeoutMs) {
    await new Promise(r => setTimeout(r, 1000))
    const log = await exec(sandbox, 'cat /tmp/hotswitch.log 2>/dev/null')
    if (log.stdout.includes(marker)) return true
  }
  return false
}

async function activateMitm(sandbox) {
  // Use Node.js fetch inside sandbox — goes through socat → proxy HTTP handler.
  // Proxy's HTTP handler checks req.url === '/__activate-mitm' BEFORE forwarding,
  // so even if socat is in the path, the proxy handles it as an internal endpoint.
  // BUT: socat forwards to proxy as transparent proxy, so Host header is 127.0.0.1:18080
  // and req.url becomes /__activate-mitm — this should be caught by the handler.
  //
  // Fallback: try Python raw socket if Node fetch fails.
  const r = await exec(sandbox, `node -e "
const body = JSON.stringify({caKeyPath: '/tmp/moxt-proxy/ca.key', caCertPath: '/tmp/moxt-proxy/ca.crt'});
fetch('http://127.0.0.1:18080/__activate-mitm', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body,
  signal: AbortSignal.timeout(5000),
}).then(r => r.text()).then(t => console.log(t)).catch(e => console.log('FETCH_ERR:' + e.message));
"`, 10000)

  if (r.stdout.includes('activated')) return true

  // Fallback: kill socat and use Python raw socket
  await exec(sandbox,
    'for pid in $(ps aux | grep socat | grep -E "18080" | grep -v grep | awk "{print \\$2}"); do kill $pid 2>/dev/null; done; sleep 0.5')
  const r2 = await exec(sandbox, `python3 -c "
import socket, json
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(('127.0.0.1', 18080))
body = json.dumps({'caKeyPath': '/tmp/moxt-proxy/ca.key', 'caCertPath': '/tmp/moxt-proxy/ca.crt'})
req = 'POST /__activate-mitm HTTP/1.1\\r\\nHost: 127.0.0.1\\r\\nContent-Type: application/json\\r\\nContent-Length: ' + str(len(body)) + '\\r\\nConnection: close\\r\\n\\r\\n' + body
s.sendall(req.encode())
data = b''
while True:
    try:
        chunk = s.recv(4096)
        if not chunk: break
        data += chunk
    except: break
s.close()
print(data.decode())
"`, 10000)
  return r2.stdout.includes('activated')
}

async function setupHotswitchProxy(sandbox) {
  await sandbox.files.write('/opt/hotswitch.mjs', fs.readFileSync(HOTSWITCH_PATH, 'utf-8'))
  await exec(sandbox, `sudo -u mitmproxy mkdir -p /tmp/moxt-proxy && sudo -u mitmproxy openssl req -new -x509 -newkey rsa:2048 -nodes -keyout /tmp/moxt-proxy/ca.key -out /tmp/moxt-proxy/ca.crt -days 1 -subj "/CN=Moxt Hotswitch Test CA" 2>/dev/null`)
  await exec(sandbox, `sh -c "nohup sudo -u mitmproxy node /opt/hotswitch.mjs > /tmp/hotswitch.log 2>&1 &"`)
  return await waitForLog(sandbox, 'HOTSWITCH_READY')
}

function proxyAlive(sandbox) {
  return exec(sandbox, 'ps aux | grep -q "[h]otswitch" && ss -tlnp 2>/dev/null | grep -q "18080.*node" && echo ALIVE || echo DEAD', 5000)
    .then(r => r.stdout.includes('ALIVE'))
}

async function run() {
  const apiKey = getApiKey()
  const suite = new TestSuite('11-hotswitch-lifecycle')

  let sandbox
  try {
    // ================================================================
    // SECTION A: Passthrough mode ECONNRESET proof
    // ================================================================
    // RFC core claim: "connections go through proxy from the start,
    // so no stale direct connections exist in the pool"
    console.log('\n  === SECTION A: Passthrough ECONNRESET proof ===\n')

    sandbox = await setupSandbox(apiKey)
    await writeTcpConnect(sandbox)
    const ready = await setupHotswitchProxy(sandbox)
    suite.record('A1: Hot-switch proxy starts in passthrough', ready)
    if (!ready) { suite.summary(); return }

    await loadNftRules(sandbox)

    // A2: Build connection pool in passthrough mode (10 requests)
    // → idle 6 seconds (keep-alive timeout window)
    // → reuse pool (10 requests)
    // Under passthrough, ALL connections go through proxy's TCP tunnel.
    // No "direct" connections exist, so idle+reuse cannot cause ECONNRESET.
    await sandbox.files.write('/tmp/passthrough-econnreset.mjs', `
const results = { phase1: 0, phase2: 0, errors: [], econnreset: 0 };

// Phase 1: build pool via passthrough proxy
for (let i = 0; i < 10; i++) {
  try {
    await fetch('http://httpbin.org/get?pt_phase=1&i=' + i, { signal: AbortSignal.timeout(15000) });
    results.phase1++;
  } catch (e) {
    results.errors.push('p1_' + i + ':' + e.message);
    if (e.message.includes('ECONNRESET')) results.econnreset++;
  }
}

// Idle 6 seconds — simulates keep-alive timeout window
await new Promise(r => setTimeout(r, 6000));

// Phase 2: reuse pool
for (let i = 0; i < 10; i++) {
  try {
    await fetch('http://httpbin.org/get?pt_phase=2&i=' + i, { signal: AbortSignal.timeout(15000) });
    results.phase2++;
  } catch (e) {
    results.errors.push('p2_' + i + ':' + e.message);
    if (e.message.includes('ECONNRESET')) results.econnreset++;
  }
}

console.log(JSON.stringify(results));
`)
    const ecrTest = await exec(sandbox, 'node /tmp/passthrough-econnreset.mjs', 120000)
    let ecr = { phase1: 0, phase2: 0, errors: [], econnreset: 0 }
    try { ecr = JSON.parse(ecrTest.stdout) } catch {}
    suite.record('A2: Passthrough pool build (10) → 6s idle → reuse (10) — zero ECONNRESET',
      ecr.econnreset === 0 && ecr.phase1 > 0 && ecr.phase2 > 0,
      `phase1=${ecr.phase1}, phase2=${ecr.phase2}, econnreset=${ecr.econnreset}`)

    // A3: 3-wave pool test in passthrough mode
    await sandbox.files.write('/tmp/passthrough-waves.mjs', `
const results = { waves: [], econnreset: 0 };
for (let w = 0; w < 3; w++) {
  let ok = 0;
  const promises = Array.from({length: 10}, (_, i) =>
    fetch('http://httpbin.org/get?pw=' + w + '&i=' + i, { signal: AbortSignal.timeout(15000) })
      .then(() => ok++)
      .catch(e => { if (e.message.includes('ECONNRESET')) results.econnreset++; })
  );
  await Promise.all(promises);
  results.waves.push(ok);
  if (w < 2) await new Promise(r => setTimeout(r, 4000));
}
console.log(JSON.stringify(results));
`)
    const waves = await exec(sandbox, 'node /tmp/passthrough-waves.mjs', 120000)
    let wavesR = { waves: [], econnreset: 0 }
    try { wavesR = JSON.parse(waves.stdout) } catch {}
    suite.record('A3: 3-wave passthrough (10×3, 4s gaps) — zero ECONNRESET',
      wavesR.econnreset === 0 && wavesR.waves.length === 3,
      `waves=${JSON.stringify(wavesR.waves)}, econnreset=${wavesR.econnreset}`)

    // A4: HTTPS passthrough — real cert from upstream (not MITM)
    const ptCert = await exec(sandbox, `python3 -c "
import ssl, socket, subprocess
s = socket.create_connection(('httpbin.org', 443), timeout=15)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ss = ctx.wrap_socket(s, server_hostname='httpbin.org')
cert = ss.getpeercert(binary_form=True)
with open('/tmp/pt-cert.der', 'wb') as f:
    f.write(cert)
r = subprocess.run(['openssl', 'x509', '-inform', 'DER', '-noout', '-issuer', '-in', '/tmp/pt-cert.der'], capture_output=True, text=True)
print('PT_REAL:' + ('yes' if 'Moxt' not in r.stdout else 'no'))
ss.close()
"`, 20000)
    suite.record('A4: HTTPS in passthrough → real upstream cert',
      ptCert.stdout.includes('PT_REAL:yes'), ptCert.stdout)

    await killSandbox(sandbox, apiKey)

    // ================================================================
    // SECTION B: Full RFC lifecycle with snapshot
    // ================================================================
    console.log('\n  === SECTION B: Full lifecycle with snapshot ===\n')

    sandbox = await setupSandbox(apiKey)
    await writeTcpConnect(sandbox)
    const ready2 = await setupHotswitchProxy(sandbox)
    suite.record('B1: Proxy starts in passthrough', ready2)
    if (!ready2) { suite.summary(); return }

    await loadNftRules(sandbox)

    // B2: Prep phase requests in passthrough (like parent-process prep)
    const prep = await exec(sandbox, `node -e "
let ok = 0;
for (let i = 0; i < 5; i++) {
  try { await fetch('http://httpbin.org/get?prep='+i, {signal: AbortSignal.timeout(10000)}); ok++; } catch {}
}
console.log('PREP_OK:'+ok);
"`, 30000)
    suite.record('B2: Prep requests in passthrough mode',
      prep.stdout.includes('PREP_OK:'), prep.stdout)

    // B3: Snapshot in passthrough mode
    console.log('  Snapshot in passthrough mode...')
    sandbox = await snapshotRestore(sandbox, apiKey)
    const alive3 = await proxyAlive(sandbox)
    suite.record('B3: Proxy survives snapshot (passthrough mode)', alive3)

    // B4: Requests work after restore (still passthrough)
    const postRestore = await exec(sandbox, `node -e "
fetch('http://httpbin.org/get?post_restore=1', {signal: AbortSignal.timeout(10000)})
  .then(r => console.log('RESTORE_OK:'+r.status))
  .catch(e => console.log('RESTORE_ERR:'+e.message))
"`, 15000)
    suite.record('B4: Requests work after restore (passthrough)',
      postRestore.stdout.includes('RESTORE_OK:'), postRestore.stdout)

    // B5: nft rules survive restore
    const nftAfter = await exec(sandbox, 'nft list ruleset | grep skuid')
    suite.record('B5: nft skuid rules survive restore', nftAfter.stdout.includes('skuid'))

    // B6: Activate MITM (Phase 2 of RFC lifecycle)
    const activated = await activateMitm(sandbox)
    suite.record('B6: Activate MITM after restore', activated)

    // B7: HTTPS now gets MITM cert
    if (activated) {
      const mitmCert = await exec(sandbox, `python3 -c "
import ssl, socket, subprocess
s = socket.create_connection(('example.com', 443), timeout=15)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ss = ctx.wrap_socket(s, server_hostname='example.com')
cert = ss.getpeercert(binary_form=True)
with open('/tmp/lifecycle-mitm.der', 'wb') as f:
    f.write(cert)
r = subprocess.run(['openssl', 'x509', '-inform', 'DER', '-noout', '-issuer', '-in', '/tmp/lifecycle-mitm.der'], capture_output=True, text=True)
print('LIFECYCLE_MITM:' + ('yes' if 'Moxt' in r.stdout else 'no') + ' ' + r.stdout.strip())
ss.close()
"`, 20000)
      suite.record('B7: HTTPS gets MITM cert after activation',
        mitmCert.stdout.includes('LIFECYCLE_MITM:yes'), mitmCert.stdout)
    } else {
      suite.record('B7: HTTPS gets MITM cert after activation', false, 'skipped — activation failed')
    }

    // B8: HTTP still works in MITM mode
    const mitmHttp = await exec(sandbox, `node -e "
fetch('http://httpbin.org/get?mitm=1', {signal: AbortSignal.timeout(10000)})
  .then(r => r.json().then(j => console.log('MITM_HTTP:'+j.url)))
  .catch(e => console.log('MITM_ERR:'+e.message))
"`, 15000)
    suite.record('B8: HTTP works in MITM mode', mitmHttp.stdout.includes('MITM_HTTP:'), mitmHttp.stdout)

    await killSandbox(sandbox, apiKey)

    // ================================================================
    // SECTION C: Edge cases
    // ================================================================
    console.log('\n  === SECTION C: Edge cases ===\n')

    sandbox = await setupSandbox(apiKey)
    await writeTcpConnect(sandbox)
    const ready3 = await setupHotswitchProxy(sandbox)
    suite.record('C1: Proxy starts', ready3)
    if (!ready3) { suite.summary(); return }

    await loadNftRules(sandbox)

    // Activate MITM first time
    const act1 = await activateMitm(sandbox)
    suite.record('C2: First activation', act1)

    // C3: Second activation (idempotency)
    const act2 = await activateMitm(sandbox)
    suite.record('C3: Second activation (idempotent)', act2)

    // C4: Requests work after double activation
    const afterDouble = await exec(sandbox, `node -e "
fetch('http://httpbin.org/get?double=1', {signal: AbortSignal.timeout(10000)})
  .then(r => console.log('DOUBLE_OK:'+r.status))
  .catch(e => console.log('DOUBLE_ERR:'+e.message))
"`, 15000)
    suite.record('C4: Requests work after double activation',
      afterDouble.stdout.includes('DOUBLE_OK:'), afterDouble.stdout)

    // C5: Concurrent requests during mode switch
    // Start 10 requests, activate MITM mid-flight, verify no crash
    // First go back to passthrough by restarting proxy
    await exec(sandbox, 'pkill -u mitmproxy -f hotswitch 2>/dev/null; sleep 1')
    await exec(sandbox, `sh -c "nohup sudo -u mitmproxy node /opt/hotswitch.mjs > /tmp/hotswitch.log 2>&1 &"`)
    await waitForLog(sandbox, 'HOTSWITCH_READY')

    await sandbox.files.write('/tmp/concurrent-switch.mjs', `
const results = { completed: 0, errors: 0 };

// Fire 10 concurrent requests (will go through passthrough initially)
const promises = Array.from({length: 10}, (_, i) =>
  fetch('http://httpbin.org/delay/2?switch=' + i, { signal: AbortSignal.timeout(20000) })
    .then(() => results.completed++)
    .catch(() => results.errors++)
);

// Wait 500ms then activate MITM mid-flight
await new Promise(r => setTimeout(r, 500));

// Activation via loopback
try {
  const body = JSON.stringify({caKeyPath: '/tmp/moxt-proxy/ca.key', caCertPath: '/tmp/moxt-proxy/ca.crt'});
  await fetch('http://127.0.0.1:18080/__activate-mitm', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body,
    signal: AbortSignal.timeout(5000),
  });
} catch {}

await Promise.all(promises);
console.log(JSON.stringify(results));
`)
    const switchTest = await exec(sandbox, 'node /tmp/concurrent-switch.mjs', 60000)
    let switchR = { completed: 0, errors: 0 }
    try { switchR = JSON.parse(switchTest.stdout) } catch {}
    // Key: proxy doesn't crash. Some requests may fail (mode transition), but no hang/crash.
    suite.record('C5: Concurrent requests during mode switch — proxy survives',
      (switchR.completed + switchR.errors) === 10,
      `completed=${switchR.completed}, errors=${switchR.errors}, total=${switchR.completed + switchR.errors}`)

    // C6: Proxy still alive after concurrent switch stress
    const aliveAfterStress = await proxyAlive(sandbox)
    suite.record('C6: Proxy alive after concurrent switch stress', aliveAfterStress)

    suite.summary()
  } finally {
    if (sandbox) await killSandbox(sandbox, apiKey)
  }
}

run().catch(err => {
  console.error('Suite failed:', err)
  process.exit(1)
})
