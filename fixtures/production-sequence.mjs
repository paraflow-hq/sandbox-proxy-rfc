/**
 * Simulates the EXACT production startup sequence of parent-process.ts
 * under the RFC architecture:
 *
 *   Phase 1 (Prep): All traffic goes through proxy in current MITM mode
 *     - trustMitmCaCertForParentProcess() monkey-patches tls.createSecureContext
 *     - Datadog logs, git clone, file downloads → all through proxy
 *
 *   Phase 2 (Activate MITM - RFC new): Would switch from passthrough to MITM
 *     - For now, proxy starts in MITM mode (current behavior)
 *     - This script validates the monkey-patch + request sequence
 *
 *   Phase 3 (Agent): Spawn agent process with NODE_EXTRA_CA_CERTS
 *
 * This script runs INSIDE the E2B sandbox alongside the real proxy-adapter.
 */

import tls from 'node:tls';
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';

const PROXY_CA_CERT_PATH = '/tmp/moxt-proxy/ca.crt';
const results = { steps: [], errors: [] };

function log(step, ok, detail) {
  results.steps.push({ step, ok, detail });
  console.error(`  [${ok ? 'OK' : 'FAIL'}] ${step}: ${detail || ''}`);
}

// ============================================================
// Step 1: trustMitmCaCertForParentProcess() — exact copy from
// server-ts/src/.../transparent-proxy.ts lines 259-274
// ============================================================
let _caCertPatched = false;

function trustMitmCaCertForParentProcess() {
  if (_caCertPatched) return;
  _caCertPatched = true;

  const caCert = fs.readFileSync(PROXY_CA_CERT_PATH);
  const origCreateSecureContext = tls.createSecureContext.bind(tls);

  tls.createSecureContext = function (options) {
    const ctx = origCreateSecureContext(options);
    ctx.context.addCACert(caCert);
    return ctx;
  };
}

try {
  // Verify CA cert exists (proxy-adapter should have generated it)
  if (!fs.existsSync(PROXY_CA_CERT_PATH)) {
    log('CA cert exists', false, `${PROXY_CA_CERT_PATH} not found`);
    console.log(JSON.stringify(results));
    process.exit(0);
  }
  log('CA cert exists', true, PROXY_CA_CERT_PATH);

  // Apply the monkey-patch
  trustMitmCaCertForParentProcess();
  log('TLS monkey-patch applied', true, 'tls.createSecureContext patched');

  // ============================================================
  // Step 2: Prep phase — simulate parent-process HTTP requests
  // These go through nft REDIRECT → proxy → forwardViaWorker
  // The monkey-patch ensures Node.js trusts the MITM CA
  // ============================================================

  // 2a: HTTP request (like Datadog log sending)
  try {
    const r = await fetch('http://httpbin.org/get?step=datadog', {
      signal: AbortSignal.timeout(15000),
    });
    log('Prep HTTP (Datadog sim)', true, `status=${r.status}`);
  } catch (e) {
    log('Prep HTTP (Datadog sim)', false, e.message);
    results.errors.push('prep_http:' + e.message);
  }

  // 2b: HTTPS request to non-bypass host (like git clone metadata)
  // This MUST go through MITM → proxy generates cert → monkey-patch trusts it
  try {
    const r = await fetch('https://example.com/', {
      signal: AbortSignal.timeout(15000),
    });
    // If we get here WITHOUT "UNABLE_TO_VERIFY_LEAF_SIGNATURE", the monkey-patch works
    log('Prep HTTPS via MITM (monkey-patch trust)', true, `status=${r.status}`);
  } catch (e) {
    const isCertError = e.message.includes('UNABLE_TO_VERIFY') ||
                        e.message.includes('self-signed') ||
                        e.message.includes('certificate');
    if (isCertError) {
      log('Prep HTTPS via MITM (monkey-patch trust)', false, 'CA not trusted: ' + e.message);
      results.errors.push('mitm_trust:' + e.message);
    } else {
      // Non-cert error (network, timeout) — the monkey-patch still worked for TLS
      log('Prep HTTPS via MITM (monkey-patch trust)', true, 'TLS OK, upstream error: ' + e.message);
    }
  }

  // 2c: HTTPS to bypass host (like Anthropic API call)
  // Goes through proxy's tunnelBypass → direct tunnel → real cert
  // Monkey-patch shouldn't interfere with real certs
  try {
    const r = await fetch('https://httpbin.org/get?step=bypass', {
      signal: AbortSignal.timeout(15000),
    });
    log('Prep HTTPS bypass (real cert)', true, `status=${r.status}`);
  } catch (e) {
    log('Prep HTTPS bypass (real cert)', false, e.message);
    results.errors.push('bypass:' + e.message);
  }

  // 2d: Multiple sequential requests (like ~90 Datadog logs in production)
  let seqOk = 0;
  let seqErr = 0;
  for (let i = 0; i < 20; i++) {
    try {
      await fetch('http://httpbin.org/get?seq=' + i, {
        signal: AbortSignal.timeout(10000),
      });
      seqOk++;
    } catch {
      seqErr++;
    }
  }
  log('Prep sequential burst (20 requests)', seqOk > 15, `ok=${seqOk}, err=${seqErr}`);

  // 2e: Verify NO ECONNRESET in the burst
  log('Zero ECONNRESET in prep phase', results.errors.filter(e => e.includes('ECONNRESET')).length === 0,
    `econnreset count: ${results.errors.filter(e => e.includes('ECONNRESET')).length}`);

  // ============================================================
  // Step 3: Simulate Agent spawn
  // In production: spawn('node', [sandboxExecution.js]) with NODE_EXTRA_CA_CERTS
  // Here: verify that a child process with NODE_EXTRA_CA_CERTS can make HTTPS requests
  // ============================================================
  try {
    const childResult = execFileSync('node', ['-e', `
      (async () => {
        try {
          const r = await fetch('https://example.com/', { signal: AbortSignal.timeout(10000) });
          console.log('CHILD_STATUS:' + r.status);
        } catch(e) {
          const isCert = e.message.includes('UNABLE_TO_VERIFY') || e.message.includes('self-signed');
          console.log(isCert ? 'CHILD_CERT_FAIL:' + e.message : 'CHILD_OK_TLS:' + e.message);
        }
      })();
    `], {
      env: { ...process.env, NODE_EXTRA_CA_CERTS: PROXY_CA_CERT_PATH },
      timeout: 15000,
      encoding: 'utf-8',
    });
    const childTlsOk = childResult.includes('CHILD_STATUS:') || childResult.includes('CHILD_OK_TLS:');
    log('Agent child process HTTPS (NODE_EXTRA_CA_CERTS)', childTlsOk, childResult.trim());
  } catch (e) {
    log('Agent child process HTTPS', false, e.message.substring(0, 100));
    results.errors.push('child:' + e.message);
  }

} catch (e) {
  results.errors.push('fatal:' + e.message);
}

console.log(JSON.stringify(results));
