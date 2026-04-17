/**
 * ATTACK 2: Reproduce P0 self-loop.
 *
 * Simulates proxy-adapter's forwardViaWorker calling fetch() to external :443.
 * Must be run as `mitmproxy` user (sudo -u mitmproxy node ...).
 *
 * Without UID exemption: iptables REDIRECT :443 → :18443 → back to proxy → loop.
 * With UID exemption: traffic goes direct (timeout, no server at target IP).
 *
 * Expected: all requests timeout/refused (went direct). No "TLS_PASSTHROUGH_REACHED".
 */

async function main() {
  const results = []

  for (let i = 0; i < 3; i++) {
    const c = new AbortController()
    const t = setTimeout(() => c.abort(), 2000)
    try {
      const r = await fetch("https://198.18.0.1/loop-test-" + i, { signal: c.signal })
      clearTimeout(t)
      const body = await r.text()
      results.push({ i, status: "response", body: body.substring(0, 50) })
    } catch (e) {
      clearTimeout(t)
      results.push({
        i,
        name: e.name,
        timeout: e.name === "AbortError",
        code: e.cause ? e.cause.code : null,
      })
    }
  }

  console.log(JSON.stringify(results))
}

main().catch(e => console.log(JSON.stringify([{ fatal: e.message }])))
