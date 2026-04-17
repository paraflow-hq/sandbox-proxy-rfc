/**
 * Minimal passthrough → MITM hot-switch implementation.
 *
 * Validates the RFC's core new mechanism:
 *   1. Proxy starts in passthrough mode (TCP tunnel all HTTPS, no TLS interception)
 *   2. POST /__activate-mitm switches to MITM mode with provided CA
 *   3. New HTTPS connections after switch get MITM-intercepted
 *   4. HTTP relay works in both modes
 *
 * This is a REAL implementation of the RFC spec, not a mock.
 * Runs as mitmproxy user inside E2B sandbox with nft rules.
 */

import http from 'node:http';
import net from 'node:net';
import tls from 'node:tls';
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';

const HTTP_PORT = 18080;
const TLS_PORT = 18443;

const state = {
  mode: 'passthrough',  // 'passthrough' or 'mitm'
  certManager: null,     // DynamicCertManager equivalent, set on activation
  caKey: null,
  caCert: null,
};

// ========== Minimal DynamicCertManager ==========
function generateDomainCert(hostname, caKeyPath, caCertPath) {
  const certDir = '/tmp/moxt-proxy';
  const safe = hostname.replace(/[^a-zA-Z0-9.-]/g, '_');
  const keyPath = `${certDir}/${safe}.key`;
  const csrPath = `${certDir}/${safe}.csr`;
  const certPath = `${certDir}/${safe}.crt`;
  const extPath = `${certDir}/${safe}.ext`;

  execFileSync('openssl', ['genrsa', '-out', keyPath, '2048'], { stdio: 'pipe' });
  execFileSync('openssl', ['req', '-new', '-key', keyPath, '-out', csrPath, '-subj', `/CN=${hostname}`], { stdio: 'pipe' });
  fs.writeFileSync(extPath, `subjectAltName=DNS:${hostname}\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n`);
  execFileSync('openssl', ['x509', '-req', '-in', csrPath, '-CA', caCertPath, '-CAkey', caKeyPath, '-CAcreateserial', '-out', certPath, '-days', '1', '-extfile', extPath], { stdio: 'pipe' });

  // Cleanup temp files
  for (const f of [csrPath, extPath]) {
    try { fs.unlinkSync(f); } catch {}
  }

  return {
    key: fs.readFileSync(keyPath),
    cert: fs.readFileSync(certPath),
  };
}

const certCache = new Map();
function getSecureContext(hostname) {
  if (certCache.has(hostname)) return certCache.get(hostname);
  const { key, cert } = generateDomainCert(hostname, state.caKey, state.caCert);
  const ctx = tls.createSecureContext({ key, cert });
  certCache.set(hostname, ctx);
  console.log(`[hotswitch] Generated cert for ${hostname}`);
  return ctx;
}

// ========== SNI Parser (from mitm-proxy.ts) ==========
function parseSniHostname(buf) {
  if (buf.length < 43 || buf[0] !== 0x16) return null;
  const recordLength = buf.readUInt16BE(3);
  if (buf.length < 5 + recordLength) return null;
  let offset = 5;
  if (buf[offset] !== 0x01) return null;
  offset += 4 + 2 + 32;
  if (offset >= buf.length) return null;
  offset += 1 + buf.readUInt8(offset);
  if (offset + 2 > buf.length) return null;
  offset += 2 + buf.readUInt16BE(offset);
  if (offset >= buf.length) return null;
  offset += 1 + buf.readUInt8(offset);
  if (offset + 2 > buf.length) return null;
  const extLen = buf.readUInt16BE(offset);
  offset += 2;
  const extEnd = Math.min(offset + extLen, buf.length);
  while (offset + 4 <= extEnd) {
    const extType = buf.readUInt16BE(offset);
    const extDataLen = buf.readUInt16BE(offset + 2);
    offset += 4;
    if (extType === 0x0000) {
      if (offset + 5 > extEnd) return null;
      offset += 2 + 1;
      const nameLen = buf.readUInt16BE(offset);
      offset += 2;
      if (offset + nameLen > buf.length) return null;
      return buf.subarray(offset, offset + nameLen).toString('ascii');
    }
    offset += extDataLen;
  }
  return null;
}

// ========== HTTP Server ==========
const httpServer = http.createServer(async (req, res) => {
  if (req.url === '/__health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, mode: state.mode }));
    return;
  }

  if (req.url === '/__activate-mitm' && req.method === 'POST') {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const body = JSON.parse(Buffer.concat(chunks).toString());

    if (!body.caKeyPath || !body.caCertPath) {
      res.writeHead(400);
      res.end(JSON.stringify({ error: 'caKeyPath and caCertPath required' }));
      return;
    }

    state.caKey = body.caKeyPath;
    state.caCert = body.caCertPath;
    state.mode = 'mitm';

    console.log('[hotswitch] MITM activated with CA: ' + body.caCertPath);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ activated: true, mode: 'mitm' }));
    return;
  }

  // Transparent HTTP relay
  const host = req.headers.host;
  if (!host) { res.writeHead(400); res.end('Missing Host'); return; }
  const [hostname, portStr] = host.split(':');
  const port = parseInt(portStr) || 80;

  try {
    const proxyReq = http.request({ hostname, port, path: req.url, method: req.method, headers: { ...req.headers, host } }, (proxyRes) => {
      res.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.pipe(res);
    });
    proxyReq.on('error', (err) => {
      if (!res.headersSent) { res.writeHead(502); res.end('Proxy error: ' + err.message); }
    });
    req.pipe(proxyReq);
  } catch (err) {
    res.writeHead(502); res.end('Proxy error: ' + err.message);
  }
});

httpServer.listen(HTTP_PORT, '0.0.0.0', () => {
  console.log(`[hotswitch] HTTP on :${HTTP_PORT} (mode: ${state.mode})`);
});

// ========== MITM HTTPS Server (only used after activation) ==========
// MITM HTTPS server — lazily created after MITM activation when CA is available.
// Uses https.createServer (same as real proxy-adapter) for correct TLS termination
// when receiving unshift'd sockets from the TLS router.
import https from 'node:https';

let mitmServer = null;

function ensureMitmServer() {
  if (mitmServer) return mitmServer;
  if (!state.caKey || !state.caCert) return null;

  const fallbackKey = fs.readFileSync(state.caKey);
  const fallbackCert = fs.readFileSync(state.caCert);

  mitmServer = https.createServer({
    key: fallbackKey,
    cert: fallbackCert,
    SNICallback: (hostname, cb) => {
      try { cb(null, getSecureContext(hostname)); }
      catch (e) { cb(e instanceof Error ? e : new Error(String(e))); }
    },
  }, (req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('MITM_INTERCEPTED host=' + req.headers.host);
  });
  return mitmServer;
}

// ========== TLS Router ==========
const tlsRouter = net.createServer((clientSocket) => {
  let buf = Buffer.alloc(0);

  const onData = (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    if (buf.length < 5) return;
    if (buf[0] !== 0x16) { clientSocket.destroy(); return; }
    const recordLength = buf.readUInt16BE(3);
    if (buf.length < 5 + recordLength) return;

    clientSocket.removeListener('data', onData);
    const sni = parseSniHostname(buf);

    if (state.mode === 'passthrough') {
      // Passthrough: TCP tunnel to upstream
      if (!sni) { clientSocket.destroy(); return; }
      const upstream = net.connect({ host: sni, port: 443 }, () => {
        upstream.write(buf);
        clientSocket.pipe(upstream);
        upstream.pipe(clientSocket);
      });
      upstream.on('error', () => clientSocket.destroy());
      clientSocket.on('error', () => upstream.destroy());
      clientSocket.on('close', () => upstream.destroy());
    } else {
      // MITM: terminate TLS (same pattern as real proxy-adapter mitm-proxy.ts:305-314)
      const server = ensureMitmServer();
      if (!server) { clientSocket.destroy(); return; }
      clientSocket.pause();
      clientSocket.unshift(buf);
      server.emit('connection', clientSocket);
    }
  };

  clientSocket.on('data', onData);
  clientSocket.on('error', () => {});
  clientSocket.setTimeout(10000, () => clientSocket.destroy());
});

tlsRouter.listen(TLS_PORT, '0.0.0.0', () => {
  console.log(`[hotswitch] TLS router on :${TLS_PORT} (mode: ${state.mode})`);
  console.log('HOTSWITCH_READY');
});
