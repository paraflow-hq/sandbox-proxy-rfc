# Independent Analysis: RFC vs Current Architecture

An objective, fact-based comparison of the current Moxt sandbox transparent proxy architecture against the proposed RFC architecture. Each claim below is accompanied by its verifiable source.

## 1. Production Incident Record

| Incident | Date | Duration | Root Cause | Source |
|----------|------|----------|------------|--------|
| ECONNRESET race condition | Ongoing (probabilistic) | Per-request failures | Connection pool spans iptables topology switch | [PR #4378](https://github.com/paraflow-hq/moxt/pull/4378) |
| Proxy self-loop (P0) | 2026-04-10 | **70 minutes** of full agent outage | `forwardViaWorker` fetch() uses OS-assigned ephemeral port outside `--sport 20000:29999` bypass range | [#3784](https://github.com/paraflow-hq/moxt/issues/3784) |

**Fact**: The current architecture has two confirmed production failure modes. The RFC architecture has zero production data (not yet deployed).

## 2. Anti-Loop Mechanism: Port Range vs UID Exemption

### Current: Source Port Range (`--sport 20000:29999`)

- Only protects code paths that **explicitly bind** to ports 20000-29999
- Node.js `fetch()` (undici) uses OS-assigned ephemeral ports (typically 32768-60999) — **not covered**
- Every new outbound code path in proxy-adapter is a potential self-loop if the developer forgets to bind to the bypass range
- P0 incident was caused exactly by this gap: `forwardViaWorker` internally calls `fetch()` without explicit port binding

### RFC: UID Exemption (`nft meta skuid "mitmproxy"`)

- Exempts **all** outbound traffic from the `mitmproxy` user, regardless of port, code path, or calling method
- No developer action required — any code running as the `mitmproxy` user is automatically exempt
- Zero-maintenance: new code paths are protected by default

### Industry Precedent (Verifiable)

| Project | Anti-Loop Mechanism | Source |
|---------|-------------------|--------|
| **Istio** | `iptables -m owner --uid-owner 1337 -j RETURN` | [istio/istio `pkg/iptables`](https://github.com/istio/istio) |
| **Linkerd** | `iptables -m owner --uid-owner 2102 -j RETURN` | [linkerd/linkerd2-proxy-init](https://github.com/linkerd/linkerd2-proxy-init) |
| **mitmproxy** | `iptables -m owner ! --uid-owner mitmproxyuser -j REDIRECT` | [mitmproxy transparent mode docs](https://docs.mitmproxy.org/stable/howto-transparent/) |
| **Squid** | `iptables -m owner --uid-owner squid -j RETURN` | [Squid transparent interception docs](http://wiki.squid-cache.org/ConfigExamples/Intercept/LinuxRedirect) |

**Fact**: No mainstream transparent proxy project uses source port range exemption for anti-loop. All use UID exemption. This is not a matter of preference — port range exemption has a known structural defect (any code path using OS-assigned ports is unprotected).

## 3. Rule Injection Timing: Runtime vs Image Layer

### Current: Runtime Mid-Execution

```
parent-process starts
  → prep phase: ~90 HTTP requests (Datadog logs, progress reports, git clone, etc.)
  → connection pool accumulates keep-alive connections (DIRECT, not through proxy)
  → setupIptablesTransparentProxy()  ← network topology switches HERE
  → subsequent requests may pull stale connections → ECONNRESET
```

The ECONNRESET occurs because connections established **before** iptables are direct, but after iptables they must go through the proxy. Stale direct connections in the pool hit server-side RST.

### RFC: Image Layer (Pre-Snapshot)

```
template build: proxy + nft rules baked into Firecracker snapshot
  → sandbox created from snapshot: proxy running, rules active from time zero
  → parent-process starts: first fetch() already goes through proxy
  → no direct connections ever exist in the pool
  → no topology switch ever happens
```

### Industry Precedent (Verifiable)

| Platform | Rule Timing | Source |
|----------|-------------|--------|
| **Istio** | init container runs **before** application container | [Istio architecture docs](https://istio.io/latest/docs/ops/deployment/architecture/) |
| **Linkerd** | `linkerd-init` container configures iptables **before** application starts | [Linkerd architecture docs](https://linkerd.io/2/reference/architecture/) |
| **AWS App Mesh** | init container sets up iptables **before** Envoy + application | [App Mesh docs](https://docs.aws.amazon.com/app-mesh/latest/userguide/getting-started.html) |
| **E2B** | `setStartCmd` runs at build time, captured in snapshot | [E2B IP Tunneling docs](https://e2b.dev/docs/sandbox/ip-tunneling) |

**Fact**: Every major service mesh and proxy framework establishes network interception rules **before** application code runs. The current Moxt architecture is the only known implementation that sets up transparent proxy rules **mid-execution** after the application has already established network connections.

## 4. Runtime Moving Parts

### Current Architecture: Per-Sandbox Runtime Steps

1. Start proxy-adapter process
2. Execute iptables commands to set up REDIRECT rules
3. Ensure each outbound code path in proxy-adapter binds to bypass port range
4. Maintain consistency between bypass host list and iptables rules

Steps 1-2 happen **after** parent-process has already made network connections. Step 3 is a manual developer discipline. Step 4 failed once (P0 incident).

### RFC Architecture: Per-Sandbox Runtime Steps

1. Sandbox created from snapshot (proxy + nft rules already active — atomic, all-or-nothing)
2. `POST /__activate-mitm` with per-instance CA

**Fact**: The RFC reduces runtime dynamic operations from 4 to 2. Firecracker snapshot restore is atomic — the proxy and rules either both exist or neither does. There is no intermediate state where the proxy is running but rules are not set up, or vice versa.

## 5. Failure Mode Comparison

### Current Architecture Failure Modes

| Failure | Trigger | Probability | Severity | Detection |
|---------|---------|-------------|----------|-----------|
| ECONNRESET | Keep-alive timeout during iptables switch | Medium (probabilistic, timing-dependent) | Medium (per-request) | Hard (intermittent, depends on timing) |
| Self-loop | Any proxy outbound fetch() on OS-assigned port | Low but **has occurred** | **P0** (infinite loop, full outage) | Hard (resembles normal high CPU until investigated) |
| iptables setup failure | Runtime command execution error | Low | High (no proxy protection) | Medium |
| Port range maintenance miss | Developer forgets to bind new code path | Medium (human error) | **P0** (potential self-loop) | **Not detectable until production incident** |

### RFC Architecture Failure Modes

| Failure | Trigger | Probability | Severity | Detection |
|---------|---------|-------------|----------|-----------|
| Proxy process crash | Bug, OOM | Low | High (all redirected traffic fails) | Easy (`health check` returns error; connections refused — not silent) |
| Template build failure | Build error in template.py | Low | Medium (blocks new sandbox creation; existing sandboxes unaffected) | Easy (CI build failure) |
| `flush ruleset` conflict | E2B adds own nft rules in future | Currently zero (E2B has no nft rules — verified in tests) | High if triggered | Medium |
| `/__activate-mitm` failure | Bug in hot-switch endpoint | Low | High (MITM not active for agent) | Easy (HTTP response code) |

### Key Difference

**Current architecture's worst failures are silent and probabilistic** — ECONNRESET depends on timing, self-loop depends on which code path is exercised, port range gaps are invisible until exploited.

**RFC architecture's failures are loud and deterministic** — proxy crash causes immediate connection refused (not silent data loss), template build failures block CI (not production), health check endpoint enables explicit monitoring.

**Fact**: Silent failures are strictly harder to detect, diagnose, and prevent than loud failures. The RFC trades silent failure modes for loud ones.

## 6. Maintenance Burden

### Where the Current Architecture Is Easier to Maintain

- **No template rebuild needed**: Proxy code changes are deployed without rebuilding the E2B template. This gives faster iteration on proxy-adapter logic.
- **No system user management**: No need to maintain a `mitmproxy` system user or understand nft syntax.
- **Simpler mental model**: One proxy mode (always MITM), no passthrough/MITM dual-mode or hot-switch endpoint.

### Where the RFC Architecture Is Easier to Maintain

- **No implicit developer discipline**: UID exemption requires zero ongoing developer attention. Port range exemption requires every developer who touches proxy-adapter outbound code to remember to bind to 20000-29999 — an invisible invariant that produces P0 failures when violated.
- **No iptables timing concerns**: No need to reason about connection pool state relative to iptables setup timing.
- **Simpler diagnostics**: `nft list ruleset` and `nft list counters` show exactly what rules are active and how much traffic each rule has matched. Counter-based debugging was demonstrated in all test suites.
- **No runtime iptables code**: Removes `setupIptablesTransparentProxy()`, `cleanupIptablesTransparentProxy()`, `ensureIptablesTransparentProxy()`, all `execSync`/`execAsync` iptables commands from application code.

### Where the RFC Architecture Is Harder to Maintain

- **Template rebuild for proxy changes**: Any change to proxy-adapter.js requires rebuilding the E2B template (build → test → deploy cycle). RFC argues proxy changes are infrequent; this is historically accurate but adds friction.
- **Dual-mode proxy complexity**: Passthrough → MITM hot-switch adds a state transition to the proxy. More code paths to test and reason about.
- **nft knowledge required**: Operations team needs to understand nftables syntax for debugging, which is less common than iptables knowledge.

### The Critical Distinction

The current architecture's maintenance burden is **runtime** — failures manifest as production incidents (P0 self-loop, ECONNRESET). The RFC architecture's maintenance burden is **build-time** — failures manifest as CI failures or template build errors.

**Fact**: Build-time failures are caught before code reaches production. Runtime failures are caught **by** production. This is the fundamental difference in maintainability between the two approaches.

## 7. E2B Kernel Constraint

**Fact** (verified in E2B sandbox, documented in RFC tests):

```
# /proc/config.gz on E2B kernel 6.1.158
# CONFIG_NETFILTER_XT_MATCH_OWNER is not set    ← iptables -m owner UNAVAILABLE
CONFIG_NF_TABLES=y                               ← nft meta skuid AVAILABLE
```

This means:
- Legacy `iptables -m owner --uid-owner` (used by Istio, Linkerd) is **not available** on E2B
- `nft meta skuid` achieves the same UID-based exemption through nf_tables
- The RFC's choice of nft over iptables is a **technical necessity**, not a preference

Industry context: nftables is the designated successor to iptables in the Linux kernel (merged in Linux 3.13, default in RHEL 8+, Debian 10+). It is not experimental.

## 8. Test Evidence

The RFC includes 49 automated tests running in **real E2B sandboxes** (not mocks), plus application-layer tests with real proxy-adapter.js:

### Attack Reproduction Tests (Adversarial Suite)

| Attack | Test Method | Result | What This Proves |
|--------|-------------|--------|------------------|
| ECONNRESET reproduction | Build connection pool (5 requests) → wait 6s (simulating keep-alive timeout) → 5 more requests | `{"phase1":5,"phase2":5,"errors":[]}` — zero errors | Under RFC architecture, idle period + pool reuse does not cause ECONNRESET because all connections go through proxy from the start |
| P0 self-loop reproduction | Run as `mitmproxy` user → `fetch("https://198.18.0.1/...")` | `AbortError` (timeout, direct connection to non-routable IP) — **not** a redirect loop | UID exemption prevents the kernel from redirecting proxy's own outbound traffic back to itself |

### Real Network Tests (Production Reality Suite)

| Test | Evidence |
|------|----------|
| root HTTP intercepted | `curl httpbin.org/get` → response from proxy (`OK path=/get`) |
| mitmproxy HTTPS bypasses proxy | `curl https://httpbin.org/status/200` → HTTP 200 from real httpbin.org |
| nft counters accurate | `skuid packets: 5` (exempted) vs `redirect packets: N` (redirected) |
| Snapshot survival | Rules, counters, proxy process, UID all survive Firecracker pause/resume |
| Double snapshot (sandbox reuse) | All of the above verified after 2nd snapshot/restore cycle |

**Fact**: These tests demonstrate the architecture works in real E2B environments, not just in theory.

## 9. Summary of Facts

| Dimension | Current Architecture | RFC Architecture |
|-----------|---------------------|------------------|
| Production incidents | 2 confirmed (ECONNRESET + P0 self-loop) | 0 (not deployed) |
| Anti-loop mechanism | Port range (partial coverage, requires developer discipline) | UID (complete coverage, zero maintenance) |
| Industry precedent for anti-loop | None found | Istio, Linkerd, mitmproxy, Squid |
| Rule timing | Runtime mid-execution (after connections exist) | Image layer (before any connection) |
| Industry precedent for rule timing | None found | Istio, Linkerd, AWS App Mesh, E2B official docs |
| Runtime dynamic steps | 4 | 2 |
| Worst failure mode | Silent (probabilistic ECONNRESET, invisible self-loop risk) | Loud (connection refused, CI failure) |
| Maintenance burden location | Runtime (production incidents) | Build-time (CI failures) |
| Proxy iteration speed | Faster (no template rebuild) | Slower (requires template rebuild) |
| System complexity | Lower (single proxy mode) | Higher (dual-mode + hot-switch) |
| Automated test coverage | Not documented | 49 infra tests + app-layer tests in real E2B sandboxes |

## 10. Conclusion

Based strictly on verifiable facts:

1. The current architecture has two structural defects (runtime rule injection, port range anti-loop) that have both produced production incidents.
2. The RFC architecture eliminates both defects using mechanisms (UID exemption, pre-application rule setup) that are standard practice across Istio, Linkerd, mitmproxy, and Squid.
3. The RFC trades faster proxy iteration (no template rebuild) for elimination of two known production failure modes.
4. The RFC's failure modes are deterministic and detectable at build time; the current architecture's failure modes are probabilistic and detectable only at runtime.

Whether this trade-off is worthwhile is a judgment call. The facts above provide the basis for that judgment.
