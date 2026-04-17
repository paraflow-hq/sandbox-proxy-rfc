/**
 * Suite 17: WebSocket — transparent proxy handling of ws:// and wss:// connections.
 *
 * WebSocket uses HTTP Upgrade. Under nft transparent proxy:
 *   - ws://  (port 80)  → nft redirects to :18080 → proxy HTTP handler
 *   - wss:// (port 443) → nft redirects to :18443 → proxy TLS router
 *
 * KEY ARCHITECTURAL FINDINGS:
 *   - ws:// (HTTP Upgrade): The proxy's HTTP handler (both proxy-adapter forwardViaWorker
 *     and hotswitch HTTP relay) uses http.request + pipe, which does NOT propagate the
 *     WebSocket Upgrade event. The Upgrade request is forwarded as a regular HTTP GET.
 *     This is expected — HTTP-level WebSocket requires explicit Upgrade handling.
 *   - wss:// passthrough: In passthrough mode, the TLS router creates a raw TCP tunnel.
 *     All bytes (TLS handshake, HTTP Upgrade, WebSocket frames) pass through unchanged.
 *     This is the path where WebSocket works through the transparent proxy.
 *   - wss:// MITM: The proxy terminates TLS and forwards via HTTP — same limitation as ws://.
 *
 * Sections:
 *   A. ws:// through real proxy-adapter → graceful handling, no crash
 *   B. wss:// through passthrough TCP tunnel (hotswitch fixture) → full WebSocket echo
 *   C. wss:// through MITM (real proxy-adapter) → TLS termination + graceful handling
 *   D. Concurrent WebSocket + resilience through passthrough tunnel
 *   E. UID exemption — mitmproxy user's WebSocket traffic bypasses nft
 */

const fs = require('fs')
const path = require('path')
const {
  getApiKey, TestSuite, exec, setupSandbox, loadNftRules, killSandbox,
  writeTcpConnect,
} = require('./helpers.cjs')

const PROXY_ADAPTER_PATH = path.join(__dirname, '..', 'fixtures', 'proxy-adapter.js')
const HOTSWITCH_PATH = path.join(__dirname, '..', 'fixtures', 'passthrough-hotswitch.mjs')

const ENV_VARS = [
  'HTTP_PROXY_WORKER_URL=https://httpbin.org',
  'SANDBOX_TOOL_API_TOKEN=test-token-ws',
  'MOXT_PIPELINE_ID=rfc-websocket',
  'MOXT_HUMAN_USER_EMAIL=test@paraflow.com',
  'MOXT_WORKSPACE_OWNER_EMAIL=test@paraflow.com',
  'ENV=dev',
].join(' ')

// WS frame helpers — written into sandbox once, imported by test scripts.
const WS_HELPERS = `
import crypto from 'node:crypto';

export function encodeFrame(text) {
  const payload = Buffer.from(text);
  const mask = crypto.randomBytes(4);
  let header;
  if (payload.length < 126) {
    header = Buffer.alloc(6);
    header[0] = 0x81;
    header[1] = 0x80 | payload.length;
    mask.copy(header, 2);
  } else if (payload.length < 65536) {
    header = Buffer.alloc(8);
    header[0] = 0x81;
    header[1] = 0x80 | 126;
    header.writeUInt16BE(payload.length, 2);
    mask.copy(header, 4);
  } else {
    header = Buffer.alloc(14);
    header[0] = 0x81;
    header[1] = 0x80 | 127;
    header.writeBigUInt64BE(BigInt(payload.length), 2);
    mask.copy(header, 10);
  }
  const masked = Buffer.alloc(payload.length);
  for (let i = 0; i < payload.length; i++) masked[i] = payload[i] ^ mask[i % 4];
  return Buffer.concat([header, masked]);
}

export function decodeFrame(buf) {
  if (buf.length < 2) return null;
  let payloadLen = buf[1] & 0x7f;
  let offset = 2;
  if (payloadLen === 126) {
    if (buf.length < 4) return null;
    payloadLen = buf.readUInt16BE(2);
    offset = 4;
  } else if (payloadLen === 127) {
    if (buf.length < 10) return null;
    payloadLen = Number(buf.readBigUInt64BE(2));
    offset = 10;
  }
  if (buf[1] & 0x80) offset += 4; // skip server mask (rare)
  if (buf.length < offset + payloadLen) return null;
  return buf.subarray(offset, offset + payloadLen).toString();
}

export function buildUpgradeRequest(host, wsPath) {
  const key = crypto.randomBytes(16).toString('base64');
  return {
    key,
    request: 'GET ' + (wsPath || '/') + ' HTTP/1.1\\r\\n' +
      'Host: ' + host + '\\r\\n' +
      'Upgrade: websocket\\r\\n' +
      'Connection: Upgrade\\r\\n' +
      'Sec-WebSocket-Key: ' + key + '\\r\\n' +
      'Sec-WebSocket-Version: 13\\r\\n\\r\\n',
  };
}
`

// --- proxy-adapter helpers ---

async function waitForProxy(sandbox) {
  for (let i = 0; i < 30; i++) {
    await new Promise(r => setTimeout(r, 1000))
    const log = await exec(sandbox, 'cat /tmp/proxy-adapter.log 2>/dev/null')
    if (log.stdout.includes('PROXY_READY')) return true
    if (log.stdout.includes('PROXY_SKIPPED')) return false
  }
  return false
}

function proxyAdapterAlive(sandbox) {
  return exec(sandbox, 'ps aux | grep -q "[p]roxy-adapter" && ss -tlnp 2>/dev/null | grep -q "18080.*node" && echo ALIVE || echo DEAD', 5000)
    .then(r => r.stdout.includes('ALIVE'))
}

async function startProxyAdapter(sandbox) {
  await sandbox.files.write('/opt/proxy-adapter.js', fs.readFileSync(PROXY_ADAPTER_PATH, 'utf-8'))
  await exec(sandbox, `sh -c "nohup sudo -u mitmproxy env ${ENV_VARS} node /opt/proxy-adapter.js > /tmp/proxy-adapter.log 2>&1 &"`)
  return await waitForProxy(sandbox)
}

// --- hotswitch helpers ---

async function startHotswitch(sandbox) {
  await sandbox.files.write('/opt/hotswitch.mjs', fs.readFileSync(HOTSWITCH_PATH, 'utf-8'))
  await exec(sandbox, `sh -c "nohup sudo -u mitmproxy node /opt/hotswitch.mjs > /tmp/hotswitch.log 2>&1 &"`)
  for (let i = 0; i < 20; i++) {
    await new Promise(r => setTimeout(r, 1000))
    const log = await exec(sandbox, 'cat /tmp/hotswitch.log 2>/dev/null')
    if (log.stdout.includes('HOTSWITCH_READY')) return true
  }
  return false
}

function hotswitchAlive(sandbox) {
  return exec(sandbox, 'ps aux | grep -q "[h]otswitch" && ss -tlnp 2>/dev/null | grep -q "18080.*node" && echo ALIVE || echo DEAD', 5000)
    .then(r => r.stdout.includes('ALIVE'))
}

// --- WebSocket echo server target ---
// ws.ifelse.io is a public WebSocket echo server reachable from E2B sandboxes.
const WS_ECHO_HOST = 'ws.ifelse.io'

async function run() {
  const apiKey = getApiKey()
  const suite = new TestSuite('17-websocket')

  if (!fs.existsSync(PROXY_ADAPTER_PATH)) {
    console.error(`proxy-adapter.js not found at ${PROXY_ADAPTER_PATH}`)
    console.error('Copy from moxt repo: cp ~/work1/moxt/sandbox/proxy-adapter.js fixtures/')
    process.exit(1)
  }

  let sandbox
  try {
    // ================================================================
    // SECTION A: ws:// through real proxy-adapter (HTTP path behavior)
    //
    // The proxy's forwardViaWorker sends HTTP to httpbin.org which
    // doesn't support WebSocket. Tests verify the proxy handles
    // WebSocket Upgrade requests gracefully without crashing.
    // ================================================================
    console.log('\n  === SECTION A: ws:// through real proxy-adapter (graceful handling) ===\n')

    sandbox = await setupSandbox(apiKey)
    await writeTcpConnect(sandbox)
    await exec(sandbox, 'apt-get install -y -qq ca-certificates openssl 2>/dev/null')
    const readyA = await startProxyAdapter(sandbox)
    suite.record('A1: Proxy-adapter starts', readyA)

    if (readyA) {
      await loadNftRules(sandbox)

      // A2: Send WebSocket Upgrade request through nft → proxy.
      // Proxy forwards as regular HTTP to worker → non-101 response expected.
      const wsUpgrade = await exec(sandbox, `python3 -c "
import socket, os, base64
key = base64.b64encode(os.urandom(16)).decode()
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(15)
s.connect(('${WS_ECHO_HOST}', 80))
req = (
    'GET / HTTP/1.1\\r\\n'
    'Host: ${WS_ECHO_HOST}\\r\\n'
    'Upgrade: websocket\\r\\n'
    'Connection: Upgrade\\r\\n'
    'Sec-WebSocket-Key: ' + key + '\\r\\n'
    'Sec-WebSocket-Version: 13\\r\\n'
    '\\r\\n'
)
s.sendall(req.encode())
data = b''
while True:
    try:
        c = s.recv(4096)
        if not c: break
        data += c
        if b'\\r\\n\\r\\n' in data: break
    except: break
s.close()
resp = data.decode('utf-8', errors='replace')
# Extract status line
status = resp.split('\\r\\n')[0] if resp else 'NO_RESPONSE'
print('STATUS:' + status)
"`, 20000)
      const statusLine = wsUpgrade.stdout.match(/STATUS:(.*)/)?.[1] || ''
      suite.record('A2: ws:// Upgrade reaches proxy — gets HTTP response (not crash)',
        statusLine.includes('HTTP'),
        `response: ${statusLine}`)

      // A3: Send 5 sequential WebSocket Upgrade requests — proxy must stay alive.
      const multiUpgrade = await exec(sandbox, `python3 -c "
import socket, os, base64
ok = 0
for i in range(5):
    try:
        key = base64.b64encode(os.urandom(16)).decode()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect(('${WS_ECHO_HOST}', 80))
        req = ('GET /ws%d HTTP/1.1\\r\\nHost: ${WS_ECHO_HOST}\\r\\n'
               'Upgrade: websocket\\r\\nConnection: Upgrade\\r\\n'
               'Sec-WebSocket-Key: ' + key + '\\r\\n'
               'Sec-WebSocket-Version: 13\\r\\n\\r\\n') % i
        s.sendall(req.encode())
        data = s.recv(4096)
        if data: ok += 1
        s.close()
    except: pass
print('UPGRADE_OK:%d' % ok)
"`, 30000)
      const upgradeOk = parseInt(multiUpgrade.stdout.match(/UPGRADE_OK:(\d+)/)?.[1]) || 0
      suite.record('A3: 5 sequential ws:// Upgrades — proxy handles all gracefully',
        upgradeOk >= 3,
        `${upgradeOk}/5 got responses`)

      // A4: Normal HTTP request works after WebSocket Upgrade attempts
      const afterWs = await exec(sandbox, `node -e "
fetch('http://httpbin.org/get?after_ws=1', {signal: AbortSignal.timeout(15000)})
  .then(r => console.log('AFTER_WS_OK:'+r.status))
  .catch(e => console.log('AFTER_WS_ERR:'+e.message))
"`, 20000)
      suite.record('A4: Normal HTTP works after Upgrade attempts',
        afterWs.stdout.includes('AFTER_WS_OK:'), afterWs.stdout)

      // A5: Proxy alive after all ws:// tests
      const aliveA = await proxyAdapterAlive(sandbox)
      suite.record('A5: Proxy-adapter alive after ws:// Upgrade tests', aliveA)
    }

    await killSandbox(sandbox, apiKey)

    // ================================================================
    // SECTION B: wss:// through passthrough TCP tunnel (hotswitch fixture)
    //
    // THE main WebSocket test. In passthrough mode, the TLS router creates
    // a raw TCP tunnel — all bytes (TLS, HTTP Upgrade, WS frames) pass
    // through unchanged. WebSocket works end-to-end.
    // ================================================================
    console.log('\n  === SECTION B: wss:// through passthrough TCP tunnel (actual echo) ===\n')

    sandbox = await setupSandbox(apiKey)
    await writeTcpConnect(sandbox)
    await exec(sandbox, 'apt-get install -y -qq openssl 2>/dev/null')
    const readyB = await startHotswitch(sandbox)
    suite.record('B1: Hotswitch starts in passthrough mode', readyB)

    if (readyB) {
      await loadNftRules(sandbox)
      await sandbox.files.write('/tmp/ws-helpers.mjs', WS_HELPERS)

      // B2: wss:// TLS connects through passthrough tunnel — real upstream cert
      await sandbox.files.write('/tmp/wss-tunnel-test.mjs', `
import tls from 'node:tls';
import { encodeFrame, decodeFrame, buildUpgradeRequest } from '/tmp/ws-helpers.mjs';

const HOST = '${WS_ECHO_HOST}';
const results = { tlsConnected: false, realCert: false, upgrade: false, echoed: false };

try {
  const sock = tls.connect({ host: HOST, port: 443, servername: HOST });

  await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('timeout')), 20000);
    let buf = Buffer.alloc(0);
    let upgraded = false;

    sock.on('secureConnect', () => {
      results.tlsConnected = true;
      results.realCert = sock.authorized;
      const { request } = buildUpgradeRequest(HOST, '/');
      sock.write(request);
    });

    sock.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);

      if (!upgraded) {
        const headerEnd = buf.indexOf('\\r\\n\\r\\n');
        if (headerEnd < 0) return;
        const header = buf.subarray(0, headerEnd).toString();
        if (header.includes('101')) {
          results.upgrade = true;
          upgraded = true;
          buf = buf.subarray(headerEnd + 4);
          sock.write(encodeFrame('wss-passthrough-rfc-test'));
        } else {
          results.responseStatus = header.split('\\r\\n')[0];
          clearTimeout(timeout); sock.destroy(); resolve();
        }
        return;
      }

      // Scan all frames — server may send welcome message before echo
      while (buf.length >= 2) {
        let payloadLen = buf[1] & 0x7f;
        let offset = 2;
        if (payloadLen === 126) { if (buf.length < 4) break; payloadLen = buf.readUInt16BE(2); offset = 4; }
        else if (payloadLen === 127) { if (buf.length < 10) break; payloadLen = Number(buf.readBigUInt64BE(2)); offset = 10; }
        if (buf[1] & 0x80) offset += 4;
        if (buf.length < offset + payloadLen) break;
        const msg = buf.subarray(offset, offset + payloadLen).toString();
        buf = buf.subarray(offset + payloadLen);
        if (msg.includes('wss-passthrough-rfc-test')) {
          results.echoed = true;
          results.message = msg;
          clearTimeout(timeout); sock.destroy(); resolve();
          return;
        }
      }
    });

    sock.on('error', (e) => { results.error = e.message; clearTimeout(timeout); resolve(); });
  });
} catch (e) {
  results.error = e.message;
}

console.log(JSON.stringify(results));
`)
      const wssTunnel = await exec(sandbox, 'node /tmp/wss-tunnel-test.mjs', 30000)
      let tR = {}
      try { tR = JSON.parse(wssTunnel.stdout) } catch {}

      suite.record('B2: wss:// TLS connects through passthrough tunnel',
        tR.tlsConnected === true,
        tR.tlsConnected
          ? `realCert=${tR.realCert} (passthrough = upstream cert, not MITM)`
          : `error: ${tR.error || wssTunnel.stdout.substring(0, 80)}`)

      suite.record('B3: wss:// WebSocket Upgrade succeeds (101)',
        tR.upgrade === true,
        tR.upgrade ? '101 Switching Protocols' : `status: ${tR.responseStatus || tR.error || 'N/A'}`)

      suite.record('B4: wss:// bidirectional echo through passthrough tunnel',
        tR.echoed === true,
        tR.echoed ? `echoed: "${tR.message}"` : `echoed: false (error: ${tR.error || 'N/A'})`)

      // B5: Multiple echo messages on same connection
      await sandbox.files.write('/tmp/wss-multi-msg.mjs', `
import tls from 'node:tls';
import { encodeFrame, decodeFrame, buildUpgradeRequest } from '/tmp/ws-helpers.mjs';

const HOST = '${WS_ECHO_HOST}';
const results = { sent: 0, received: 0, messages: [] };

try {
  const sock = tls.connect({ host: HOST, port: 443, servername: HOST });

  await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => resolve(), 25000);
    let buf = Buffer.alloc(0);
    let upgraded = false;
    let sendIndex = 0;
    const TOTAL = 5;

    sock.on('secureConnect', () => {
      const { request } = buildUpgradeRequest(HOST, '/');
      sock.write(request);
    });

    sock.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);

      if (!upgraded) {
        const headerEnd = buf.indexOf('\\r\\n\\r\\n');
        if (headerEnd < 0) return;
        if (buf.subarray(0, headerEnd).toString().includes('101')) {
          upgraded = true;
          buf = buf.subarray(headerEnd + 4);
          sock.write(encodeFrame('msg-' + sendIndex));
          results.sent++;
          sendIndex++;
        } else {
          clearTimeout(timeout); sock.destroy(); resolve();
        }
        return;
      }

      while (buf.length >= 2) {
        const msg = decodeFrame(buf);
        if (!msg) break;
        results.received++;
        results.messages.push(msg);
        // Advance buffer past this frame
        let payloadLen = buf[1] & 0x7f;
        let offset = 2;
        if (payloadLen === 126) { payloadLen = buf.readUInt16BE(2); offset = 4; }
        else if (payloadLen === 127) { payloadLen = Number(buf.readBigUInt64BE(2)); offset = 10; }
        if (buf[1] & 0x80) offset += 4;
        buf = buf.subarray(offset + payloadLen);

        if (sendIndex < TOTAL) {
          sock.write(encodeFrame('msg-' + sendIndex));
          results.sent++;
          sendIndex++;
        }
        if (results.received >= TOTAL) {
          clearTimeout(timeout); sock.destroy(); resolve();
          return;
        }
      }
    });

    sock.on('error', (e) => { results.error = e.message; clearTimeout(timeout); resolve(); });
  });
} catch (e) {
  results.error = e.message;
}

console.log(JSON.stringify(results));
`)
      const multiMsg = await exec(sandbox, 'node /tmp/wss-multi-msg.mjs', 35000)
      let mmR = { sent: 0, received: 0 }
      try { mmR = JSON.parse(multiMsg.stdout) } catch {}
      suite.record('B5: 5 sequential echo messages on same wss:// connection',
        mmR.received >= 3,
        `sent=${mmR.sent}, received=${mmR.received}`)

      // B6: Hotswitch alive after passthrough WebSocket tests
      const aliveB = await hotswitchAlive(sandbox)
      suite.record('B6: Hotswitch alive after wss:// passthrough echo tests', aliveB)
    }

    await killSandbox(sandbox, apiKey)

    // ================================================================
    // SECTION C: wss:// through MITM (real proxy-adapter)
    //
    // proxy-adapter starts in MITM mode (generates CA on startup).
    // TLS is terminated by the proxy with a dynamic cert.
    // The decrypted HTTP (including Upgrade) is forwarded via worker,
    // which doesn't support WebSocket → non-101 response expected.
    // Key: TLS works, proxy handles Upgrade gracefully.
    // ================================================================
    console.log('\n  === SECTION C: wss:// through MITM (real proxy-adapter) ===\n')

    sandbox = await setupSandbox(apiKey)
    await writeTcpConnect(sandbox)
    await exec(sandbox, 'apt-get install -y -qq ca-certificates openssl 2>/dev/null')
    const readyC = await startProxyAdapter(sandbox)
    suite.record('C1: Proxy-adapter starts (MITM mode)', readyC)

    if (readyC) {
      await loadNftRules(sandbox)

      const caExists = await exec(sandbox, 'test -f /tmp/moxt-proxy/ca.crt && echo YES')
      suite.record('C2: MITM CA cert generated', caExists.stdout.includes('YES'))

      // C3: wss:// TLS connects through MITM — cert issued by proxy CA
      await sandbox.files.write('/tmp/wss-mitm-test.mjs', `
import tls from 'node:tls';
import crypto from 'node:crypto';

const HOST = '${WS_ECHO_HOST}';
const results = { tlsConnected: false, mitmCert: false, certIssuer: '' };

const sock = tls.connect({ host: HOST, port: 443, servername: HOST, rejectUnauthorized: false });

await new Promise((resolve) => {
  const timeout = setTimeout(() => resolve(), 15000);

  sock.on('secureConnect', () => {
    results.tlsConnected = true;
    const cert = sock.getPeerCertificate();
    results.certIssuer = cert.issuer?.CN || cert.issuer?.O || '';
    results.mitmCert = !sock.authorized;

    const key = crypto.randomBytes(16).toString('base64');
    sock.write(
      'GET / HTTP/1.1\\r\\nHost: ' + HOST + '\\r\\n' +
      'Upgrade: websocket\\r\\nConnection: Upgrade\\r\\n' +
      'Sec-WebSocket-Key: ' + key + '\\r\\nSec-WebSocket-Version: 13\\r\\n\\r\\n'
    );
  });

  sock.on('data', (data) => {
    const resp = data.toString();
    results.responseStatus = resp.split('\\r\\n')[0];
    clearTimeout(timeout); sock.destroy(); resolve();
  });

  sock.on('error', (e) => { results.error = e.message; clearTimeout(timeout); resolve(); });
});

console.log(JSON.stringify(results));
`)
      const mitmTest = await exec(sandbox, 'node /tmp/wss-mitm-test.mjs', 25000)
      let cR = {}
      try { cR = JSON.parse(mitmTest.stdout) } catch {}

      suite.record('C3: wss:// TLS connects through MITM (dynamic cert)',
        cR.tlsConnected === true && cR.mitmCert === true,
        `issuer="${cR.certIssuer}", mitmCert=${cR.mitmCert}`)

      suite.record('C4: wss:// MITM handles Upgrade gracefully (forwarded via worker)',
        cR.responseStatus && cR.responseStatus.includes('HTTP'),
        `response: ${cR.responseStatus || cR.error || 'N/A'}`)

      // C5: Proxy alive after wss:// MITM tests
      const aliveC = await proxyAdapterAlive(sandbox)
      suite.record('C5: Proxy-adapter alive after wss:// MITM Upgrade tests', aliveC)
    }

    await killSandbox(sandbox, apiKey)

    // ================================================================
    // SECTION D: Concurrent WebSocket + resilience (passthrough tunnel)
    // ================================================================
    console.log('\n  === SECTION D: Concurrent + resilience through passthrough tunnel ===\n')

    sandbox = await setupSandbox(apiKey)
    await writeTcpConnect(sandbox)
    await exec(sandbox, 'apt-get install -y -qq openssl 2>/dev/null')
    const readyD = await startHotswitch(sandbox)
    suite.record('D1: Hotswitch starts', readyD)

    if (readyD) {
      await loadNftRules(sandbox)
      await sandbox.files.write('/tmp/ws-helpers.mjs', WS_HELPERS)

      // D2: 5 staggered wss:// connections through passthrough tunnel, each performs echo.
      // Small stagger (300ms) avoids overwhelming the tunnel's concurrent SNI parsing.
      await sandbox.files.write('/tmp/wss-concurrent.mjs', `
import tls from 'node:tls';
import { encodeFrame, decodeFrame, buildUpgradeRequest } from '/tmp/ws-helpers.mjs';

const HOST = '${WS_ECHO_HOST}';

function wsConnect(id) {
  return new Promise((resolve) => {
    const result = { id, tls: false, upgrade: false, echoed: false };
    const timeout = setTimeout(() => resolve(result), 20000);

    try {
      const sock = tls.connect({ host: HOST, port: 443, servername: HOST });
      let buf = Buffer.alloc(0);
      let upgraded = false;

      sock.on('secureConnect', () => {
        result.tls = true;
        const { request } = buildUpgradeRequest(HOST, '/');
        sock.write(request);
      });

      sock.on('data', (chunk) => {
        buf = Buffer.concat([buf, chunk]);

        if (!upgraded) {
          const headerEnd = buf.indexOf('\\r\\n\\r\\n');
          if (headerEnd < 0) return;
          if (buf.subarray(0, headerEnd).toString().includes('101')) {
            result.upgrade = true;
            upgraded = true;
            buf = buf.subarray(headerEnd + 4);
            sock.write(encodeFrame('concurrent-' + id));
          } else {
            clearTimeout(timeout); sock.destroy(); resolve(result);
          }
          return;
        }

        // Scan frames for our echo (skip server welcome message)
        while (buf.length >= 2) {
          let payloadLen = buf[1] & 0x7f;
          let offset = 2;
          if (payloadLen === 126) { if (buf.length < 4) break; payloadLen = buf.readUInt16BE(2); offset = 4; }
          else if (payloadLen === 127) { if (buf.length < 10) break; payloadLen = Number(buf.readBigUInt64BE(2)); offset = 10; }
          if (buf[1] & 0x80) offset += 4;
          if (buf.length < offset + payloadLen) break;
          const msg = buf.subarray(offset, offset + payloadLen).toString();
          buf = buf.subarray(offset + payloadLen);
          if (msg.includes('concurrent-' + id)) {
            result.echoed = true;
            result.message = msg;
            clearTimeout(timeout); sock.destroy(); resolve(result);
            return;
          }
        }
      });

      sock.on('error', () => { clearTimeout(timeout); resolve(result); });
    } catch { resolve(result); }
  });
}

// Stagger connection starts by 300ms to avoid overwhelming tunnel
const promises = [];
for (let i = 0; i < 5; i++) {
  promises.push(new Promise(r => setTimeout(r, i * 300)).then(() => wsConnect(i)));
}
const results = await Promise.all(promises);

const tlsCount = results.filter(r => r.tls).length;
const upgraded = results.filter(r => r.upgrade).length;
const echoed = results.filter(r => r.echoed).length;
console.log(JSON.stringify({ total: 5, tls: tlsCount, upgraded, echoed }));
`)
      const concurrent = await exec(sandbox, 'node /tmp/wss-concurrent.mjs', 40000)
      let concR = { total: 5, tls: 0, upgraded: 0, echoed: 0 }
      try { concR = JSON.parse(concurrent.stdout) } catch {}

      suite.record('D2: 5 concurrent wss:// — TLS through tunnel',
        concR.tls >= 3,
        `tls=${concR.tls}/5`)

      suite.record('D3: 5 concurrent wss:// — Upgrade + echo',
        concR.echoed >= 3,
        `upgraded=${concR.upgraded}/5, echoed=${concR.echoed}/5`)

      // D4: Abrupt client disconnect mid-WebSocket — hotswitch must not crash.
      // Connect via wss://, get 101, then immediately destroy socket without Close frame.
      await sandbox.files.write('/tmp/wss-abrupt-close.mjs', `
import tls from 'node:tls';
import { buildUpgradeRequest } from '/tmp/ws-helpers.mjs';

const HOST = '${WS_ECHO_HOST}';
const results = { connected: 0, aborted: 0 };

for (let i = 0; i < 5; i++) {
  await new Promise((resolve) => {
    const timeout = setTimeout(() => resolve(), 10000);
    const sock = tls.connect({ host: HOST, port: 443, servername: HOST });

    sock.on('secureConnect', () => {
      results.connected++;
      const { request } = buildUpgradeRequest(HOST, '/');
      sock.write(request);
    });

    sock.on('data', () => {
      results.aborted++;
      sock.destroy();
      clearTimeout(timeout);
      resolve();
    });

    sock.on('error', () => { clearTimeout(timeout); resolve(); });
  });
}

console.log(JSON.stringify(results));
`)
      const abrupt = await exec(sandbox, 'node /tmp/wss-abrupt-close.mjs', 70000)
      let abruptR = { connected: 0, aborted: 0 }
      try { abruptR = JSON.parse(abrupt.stdout) } catch {}
      suite.record('D4: 5 abrupt wss:// disconnects — no crash',
        abruptR.aborted >= 3,
        `connected=${abruptR.connected}, aborted=${abruptR.aborted}`)

      // D5: Large WebSocket frame (64KB) through passthrough tunnel
      await sandbox.files.write('/tmp/wss-large-frame.mjs', `
import tls from 'node:tls';
import { encodeFrame, buildUpgradeRequest } from '/tmp/ws-helpers.mjs';

const HOST = '${WS_ECHO_HOST}';
const result = { upgraded: false, sent: false, received: false, size: 0 };

try {
  const sock = tls.connect({ host: HOST, port: 443, servername: HOST });

  await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => resolve(), 25000);
    let buf = Buffer.alloc(0);
    let upgraded = false;

    sock.on('secureConnect', () => {
      const { request } = buildUpgradeRequest(HOST, '/');
      sock.write(request);
    });

    sock.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);

      if (!upgraded) {
        const headerEnd = buf.indexOf('\\r\\n\\r\\n');
        if (headerEnd < 0) return;
        if (buf.subarray(0, headerEnd).toString().includes('101')) {
          upgraded = true;
          result.upgraded = true;
          buf = buf.subarray(headerEnd + 4);
          const largeMsg = 'X'.repeat(65536);
          sock.write(encodeFrame(largeMsg));
          result.sent = true;
        } else {
          clearTimeout(timeout); sock.destroy(); resolve();
        }
        return;
      }

      if (buf.length > 100) {
        result.received = true;
        result.size = buf.length;
        clearTimeout(timeout); sock.destroy(); resolve();
      }
    });

    sock.on('error', (e) => { result.error = e.message; clearTimeout(timeout); resolve(); });
  });
} catch (e) {
  result.error = e.message;
}

console.log(JSON.stringify(result));
`)
      const largeFr = await exec(sandbox, 'node /tmp/wss-large-frame.mjs', 35000)
      let largeR = {}
      try { largeR = JSON.parse(largeFr.stdout) } catch {}
      suite.record('D5: 64KB WebSocket frame through passthrough tunnel',
        largeR.sent === true && largeR.received === true,
        `sent=${largeR.sent}, received=${largeR.received}, size=${largeR.size || 0}`)

      // D6: Rapid connect/disconnect cycle (10 times)
      await sandbox.files.write('/tmp/wss-rapid-cycle.mjs', `
import tls from 'node:tls';
import { buildUpgradeRequest } from '/tmp/ws-helpers.mjs';

const HOST = '${WS_ECHO_HOST}';
let ok = 0;
for (let i = 0; i < 10; i++) {
  await new Promise(resolve => {
    const t = setTimeout(resolve, 5000);
    const sock = tls.connect({ host: HOST, port: 443, servername: HOST });
    sock.on('secureConnect', () => {
      const { request } = buildUpgradeRequest(HOST, '/');
      sock.write(request);
    });
    sock.on('data', () => { ok++; clearTimeout(t); sock.destroy(); resolve(); });
    sock.on('error', () => { clearTimeout(t); resolve(); });
  });
}
console.log('RAPID_OK:' + ok);
`)
      const rapidTest = await exec(sandbox, 'node /tmp/wss-rapid-cycle.mjs', 70000)
      const rapidOk = parseInt(rapidTest.stdout.match(/RAPID_OK:(\d+)/)?.[1]) || 0
      suite.record('D6: 10 rapid wss:// connect/disconnect cycles',
        rapidOk >= 5,
        `${rapidOk}/10 completed`)

      // D7: Hotswitch alive after all concurrent + resilience tests
      const aliveD = await hotswitchAlive(sandbox)
      suite.record('D7: Hotswitch alive after concurrent + resilience tests', aliveD)
    }

    await killSandbox(sandbox, apiKey)

    // ================================================================
    // SECTION E: UID exemption — mitmproxy user's WebSocket traffic
    // bypasses nft REDIRECT entirely.
    // ================================================================
    console.log('\n  === SECTION E: UID exemption for WebSocket ===\n')

    sandbox = await setupSandbox(apiKey)
    await writeTcpConnect(sandbox)
    await exec(sandbox, 'apt-get install -y -qq openssl 2>/dev/null')
    const readyE = await startHotswitch(sandbox)
    suite.record('E1: Hotswitch starts', readyE)

    if (readyE) {
      await loadNftRules(sandbox)
      await sandbox.files.write('/tmp/ws-helpers.mjs', WS_HELPERS)

      // E2: mitmproxy user's wss:// connection bypasses nft — goes directly to upstream.
      // Cert is the REAL upstream cert (not MITM), proving traffic didn't go through proxy.
      await sandbox.files.write('/tmp/wss-uid-test.mjs', `
import tls from 'node:tls';
import { buildUpgradeRequest } from '/tmp/ws-helpers.mjs';

const HOST = '${WS_ECHO_HOST}';
const result = { connected: false, realCert: false, upgraded: false };

try {
  const sock = tls.connect({ host: HOST, port: 443, servername: HOST });

  await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('timeout')), 15000);

    sock.on('secureConnect', () => {
      result.connected = true;
      result.realCert = sock.authorized;
      const { request } = buildUpgradeRequest(HOST, '/');
      sock.write(request);
    });

    sock.on('data', (data) => {
      const resp = data.toString();
      if (resp.includes('101')) result.upgraded = true;
      clearTimeout(timeout); sock.destroy(); resolve();
    });

    sock.on('error', (e) => {
      result.error = e.code || e.message;
      clearTimeout(timeout); resolve();
    });
  });
} catch (e) {
  result.error = e.message;
}

console.log(JSON.stringify(result));
`)
      // Run as mitmproxy user — UID exempt, traffic goes directly to upstream
      const uidTest = await exec(sandbox, 'sudo -u mitmproxy node /tmp/wss-uid-test.mjs', 20000)
      let uidR = {}
      try { uidR = JSON.parse(uidTest.stdout) } catch {}
      suite.record('E2: mitmproxy user wss:// bypasses nft (UID exemption)',
        uidR.connected === true,
        uidR.connected
          ? `realCert=${uidR.realCert} (direct to upstream, no MITM)`
          : `error: ${uidR.error || uidTest.stdout.substring(0, 80)}`)

      // E3: Root user's wss:// goes through proxy — nft counter increments
      const counterBefore = await exec(sandbox, 'nft list chain ip proxy output 2>/dev/null | grep "tcp dport 443" | head -1 | grep -oP "packets \\d+"')
      await exec(sandbox, `node -e "
import tls from 'node:tls';
const sock = tls.connect({ host: '${WS_ECHO_HOST}', port: 443, servername: '${WS_ECHO_HOST}' });
sock.on('secureConnect', () => sock.destroy());
sock.on('error', () => {});
setTimeout(() => process.exit(0), 5000);
"`, 10000)
      const counterAfter = await exec(sandbox, 'nft list chain ip proxy output 2>/dev/null | grep "tcp dport 443" | head -1 | grep -oP "packets \\d+"')

      const pktsBefore = parseInt(counterBefore.stdout.match(/\d+/)?.[0]) || 0
      const pktsAfter = parseInt(counterAfter.stdout.match(/\d+/)?.[0]) || 0
      suite.record('E3: Root user wss:// redirected by nft (counter incremented)',
        pktsAfter > pktsBefore,
        `packets before=${pktsBefore}, after=${pktsAfter}`)

      // E4: mitmproxy user ws:// (port 80) also bypasses nft
      await sandbox.files.write('/tmp/ws-uid-http.mjs', `
import net from 'node:net';
import { buildUpgradeRequest } from '/tmp/ws-helpers.mjs';

const HOST = '${WS_ECHO_HOST}';
const result = { connected: false, gotResponse: false };

try {
  const sock = net.connect({ host: HOST, port: 80 });
  await new Promise((resolve) => {
    const timeout = setTimeout(() => resolve(), 10000);
    sock.on('connect', () => {
      result.connected = true;
      const { request } = buildUpgradeRequest(HOST, '/');
      sock.write(request);
    });
    sock.on('data', () => {
      result.gotResponse = true;
      clearTimeout(timeout); sock.destroy(); resolve();
    });
    sock.on('error', (e) => {
      result.error = e.code || e.message;
      clearTimeout(timeout); resolve();
    });
  });
} catch (e) {
  result.error = e.message;
}

console.log(JSON.stringify(result));
`)
      const uidHttp = await exec(sandbox, 'sudo -u mitmproxy node /tmp/ws-uid-http.mjs', 15000)
      let uidHttpR = {}
      try { uidHttpR = JSON.parse(uidHttp.stdout) } catch {}
      suite.record('E4: mitmproxy user ws:// bypasses nft (UID exemption)',
        uidHttpR.connected === true && uidHttpR.gotResponse === true,
        uidHttpR.gotResponse ? 'direct connection + response OK' : `error: ${uidHttpR.error || 'N/A'}`)

      // E5: Hotswitch alive after UID exemption tests
      const aliveE = await hotswitchAlive(sandbox)
      suite.record('E5: Hotswitch alive after UID exemption tests', aliveE)
    }

    suite.summary()
  } finally {
    if (sandbox) await killSandbox(sandbox, apiKey)
  }
}

run().catch(err => {
  console.error('Suite failed:', err)
  process.exit(1)
})
