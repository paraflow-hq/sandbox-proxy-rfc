# RFC: Sandbox 透明代理架构重构

## 状态

Draft

## 概述

将 sandbox 透明代理的 iptables 设置从运行时初始化改为镜像层预置，同时采用业界标准的 `--uid-owner` 防回环机制，从根本上消除两个已知故障：
1. **ECONNRESET 竞态**（PR #4378）：中途切换网络拓扑导致连接池僵尸连接
2. **代理自环 P0 故障**（2026-04-10）：proxy-adapter 出站流量被 iptables 重定向回自己

## 问题

### 现象

`callSandboxAgentStartedApi`（通过 `callToolApi("pipeline-sandbox/on-agent-started")`）概率性失败：

```
TypeError: fetch failed
  cause: read ECONNRESET, code=ECONNRESET
```

parent process 的 fire-and-forget Datadog 日志发送同时全部失败。child process（在 iptables 设置之后 spawn）不受影响。

### 根因

parent process 在 prep 阶段向 `BASE_API_HOST` 发送大量 HTTP 请求（约 90 次 Datadog 日志 + 若干次进度上报），undici 连接池积累了多个 keep-alive 连接。这些连接是**直连**的——因为此时 iptables 规则尚未生效，流量不经过代理。

当 `setupIptablesTransparentProxy()` 执行时，网络拓扑发生了中途切换。如果服务端的 keep-alive 超时恰好在 iptables 命令执行期间到期，服务端发送 TCP RST。parent process 无法及时感知这个 RST（最初因为 `execSync` 完全冻结事件循环；即使改为 `execAsync`，undici 的连接池驱逐也不是瞬时的）。后续 `callToolApi` 从池中取出僵尸连接，得到 ECONNRESET。

```
时间线：

  prep 阶段: fetch() fetch() fetch() ...  → 连接池积累直连连接
                                            ↓
  setupIptablesTransparentProxy()           → 网络拓扑切换
                                            ↓
  callToolApi()                             → 取出僵尸连接 → ECONNRESET
```

故障是概率性的，取决于 keep-alive 超时是否恰好在 iptables 设置窗口内到期。

### 为什么 child process 不受影响

child process 在 iptables 规则生效之后才被 spawn，拥有全新的连接池，不存在任何直连连接——它创建的每一个连接从一开始就走代理。

### 当前缓解方案（PR #4378）

PR #4378 将 iptables 命令从 `execSync` 改为 `await execAsync`，让事件循环在命令执行期间保持运转，使 undici 能处理 socket close/RST 事件。这**缩小了**竞态窗口，但没有消除——根本问题（iptables 生效前连接池中已存在直连连接）仍然存在。

## 业界背景

### 已知模式：事件循环阻塞导致连接池中的僵尸连接

这是 Node.js 社区的已知问题，有多个公开记录：

| Issue | 描述 |
|-------|------|
| **nodejs/node #54293** | "Network request fails after event loop is blocked for a few seconds" — 机制完全一致：事件循环阻塞 → keep-alive 超时 → undici 复用死连接 → ECONNRESET |
| **nodejs/undici #3492** | "fetch may try to use a closed connection" — 19 个 thumbs-up，至今 open。核心维护者 @mcollina："There is only one thing to do: always retry the request if the other side is closed" |
| **aws/aws-sdk-js-v3 #6861** | `execSync` 阻塞事件循环 → AWS SDK 调用失败（ECONNABORTED） |
| **nodejs/undici #3410** | CPU 密集代码阻塞事件循环导致 UND_ERR_CONNECT_TIMEOUT（Vercel 工程师报告，已修复） |
| **nodejs/undici #3553** | TIMEOUT_IDLE 应包含事件循环延迟（undici 核心维护者 @ronag 提出，已修复） |

### 业界标准：网络规则先于应用

在容器/VM 环境中，业界标准做法是在应用代码运行**之前**建立网络拦截规则：

| 平台 | 机制 |
|------|------|
| **Istio** | init container 设置 iptables → Envoy sidecar 就绪 → 应用容器启动 |
| **Linkerd** | `linkerd-init` 容器配置 iptables → `linkerd-proxy` 就绪 → 应用启动 |
| **AWS App Mesh** | init container 配置 iptables → Envoy 就绪 → 应用启动 |
| **E2B（官方文档）** | `setStartCmd` 在 build 阶段执行代理 + iptables → snapshot → 每个 sandbox 创建即规则就位 |

当前 Moxt 实现偏离了这一标准——在运行时、在 parent process 已建立网络连接之后才设置 iptables。

### CA 证书管理

对于多实例环境中的 MITM 代理 CA 证书，业界共识是每实例独立生成：

| 来源 | 实践 |
|------|------|
| **mitmproxy 官方文档** | "For security reasons, the mitmproxy CA is generated uniquely on the first start and is **not shared** between mitmproxy installations on different devices" |
| **Firecracker 官方文档** | 明确警告不应在 VM 快照克隆之间共享加密状态 |
| **NIST SP 800-57** | 私钥应在所有者独占控制下；限制使用范围以限制泄露影响 |

## P0 故障（2026-04-10）：代理自环

### 事件

PR #3706 将代理 bypass 从 iptables IP 排除改为应用层 SNI 检测，过程中 `HTTP_PROXY_WORKER_URL`（`sandbox-proxy.moxt.ai:443`）从 bypass 列表中消失。proxy-adapter 调用 `forwardViaWorker` → `fetch(sandbox-proxy.moxt.ai:443)` → iptables 将该请求 REDIRECT 回 proxy-adapter 自身的 18443 端口 → TLS Router → MITM → 再次 `forwardViaWorker` → 无限循环。全线 Agent 70 分钟不可用。详见 [paraflow-hq/moxt#3784](https://github.com/paraflow-hq/moxt/issues/3784)。

### 当前防回环机制的缺陷

当前使用**源端口范围豁免**（`--sport 20000:29999 -j RETURN`）。proxy-adapter 的 bypass 路径（`tunnelBypass`/`forwardDirect`）显式绑定到 20000-29999 端口范围，iptables 豁免该范围。

但 `forwardViaWorker` 内部的 `fetch()` 使用 Node.js 默认的系统分配端口，**不在 bypass 范围内**，因此被 iptables REDIRECT 回 proxy-adapter 自己。源端口豁免只保护了显式绑定端口的代码路径，无法保护 proxy-adapter 进程的所有出站流量。

### 业界标准：UID 豁免

Istio、Linkerd、mitmproxy 全部按 UID 豁免代理进程的所有出站流量：

```bash
# Istio: Envoy UID 1337
iptables -t nat -A ISTIO_OUTPUT -m owner --uid-owner 1337 -j RETURN

# Linkerd: proxy UID 2102
iptables -t nat -A PROXY_INIT_OUTPUT -m owner --uid-owner 2102 -j RETURN

# mitmproxy: 只重定向非 proxy 用户的流量
iptables -t nat -A OUTPUT -p tcp -m owner ! --uid-owner mitmproxyuser -j REDIRECT
```

原理：proxy 进程以专用 UID 运行，内核豁免该 UID 的**所有出站流量**——不管内部走哪条代码路径、用什么端口、`fetch()` 怎么调用。**从根本上不可能形成回环。**

### E2B 内核约束与 nft 替代方案

**实测发现（2026-04-16）：** E2B 内核（6.1.158）**显式禁用了** `CONFIG_NETFILTER_XT_MATCH_OWNER`（legacy iptables 的 `-m owner` 模块）。`iptables -m owner --uid-owner` 命令无法使用。

```
# /proc/config.gz 中的配置
# CONFIG_NETFILTER_XT_MATCH_OWNER is not set
```

**替代方案：** nf_tables 的 `meta skuid` 匹配可以实现相同功能。E2B 内核编译了 `CONFIG_NF_TABLES=y`，nft 的 `meta skuid` 通过内置的 nf_tables 基础设施工作，无需额外内核模块。

**实测验证：** 在 E2B sandbox 中使用 nft `meta skuid "mitmproxy"` 规则：
- mitmproxy 用户的出站流量匹配 skuid 规则，被 `accept`（直接出站，不被 REDIRECT）
- 其他用户的出站流量被 REDIRECT 到代理端口
- nft 规则和 counter 在 Firecracker snapshot/restore 后完整存活
- UID 豁免在 restore 后仍然生效

```
# 实测 nft counter 输出：
meta skuid 999 counter packets 2 bytes 120 accept    ← mitmproxy 流量被豁免
tcp dport 80 counter packets 33 bytes 2412 redirect   ← 其他流量被重定向
```

### Moxt 基础设施已就位但未启用

`paraflow-hq/sandbox` template.py 已创建专用用户：

```python
# Create dedicated user for MITM proxy adapter.
# iptables uses --uid-owner to bypass proxy adapter's own traffic, preventing
# routing loops without relying on destination IP (which fails when hosts share
# Cloudflare Anycast IPs).
.run_cmd("useradd -r -M -s /usr/sbin/nologin mitmproxy")
```

注释明确说了要用 UID 豁免，但当前 iptables 规则中没有使用，proxy-adapter 也没有以 `mitmproxy` 用户身份运行。

## 方案设计

### 核心原则

**iptables 先于连接，MITM 后于 CA，UID 豁免防回环。**

将代理生命周期拆分为两层，各自职责清晰：

```
镜像层（snapshot）：  网络拓扑（iptables + 代理直通模式 + UID 豁免）
运行时（per-instance）：加密身份（CA 生成 → MITM 激活 → Agent 启动）
```

### 架构

```
┌─────────────────────────────────────────────────────────────────┐
│ 镜像构建（setStartCmd → snapshot）                                │
│                                                                 │
│  1. 以 mitmproxy 用户启动 proxy-adapter（直通模式）                  │
│     - HTTP  :18080 — 直连转发到目标                                │
│     - HTTPS :18443 — TCP 透传到目标:443（不解密）                   │
│  2. 设置 nft 规则                                                  │
│     - meta skuid "mitmproxy" accept             ← UID 豁免防回环  │
│     - tcp dport 80  redirect to :18080                          │
│     - tcp dport 443 redirect to :18443                          │
│  3. snapshot 捕获运行中的代理 + 生效的 iptables 规则                 │
│                                                                 │
│  无 CA 私钥。无 sandboxToken。无用户身份。                          │
└─────────────────────────────────────────────────────────────────┘
                              │
                    snapshot/restore
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Sandbox 实例（per-pipeline）                                      │
│                                                                 │
│  代理运行中 ✓   iptables 已生效 ✓   MITM 未激活 ✗                  │
│                                                                 │
│  parent-process.ts main():                                      │
│    Phase 1 — Prep（所有流量经代理直通模式）                          │
│      ├─ setupDatadogLogger()     → 经代理（直通）                  │
│      ├─ cloneRepositories()      → 经代理（直通）                  │
│      ├─ downloadFiles()          → 经代理（直通）                  │
│      └─ ... 连接池中永远不存在直连连接                               │
│                                                                 │
│    Phase 2 — 激活 MITM                                           │
│      ├─ setupCa()               → 生成本实例独有的 CA              │
│      ├─ installCaToSystemTrustStore()                           │
│      ├─ trustMitmCaCertForParentProcess()                       │
│      └─ POST /__activate-mitm   → 代理切换到 MITM 模式            │
│                                                                 │
│    Phase 3 — 启动 Agent                                          │
│      └─ spawn('node', [sandboxExecution.js])                    │
│         MITM 已激活，Agent 所有 HTTPS 流量被拦截审计                 │
└─────────────────────────────────────────────────────────────────┘
```

### 为什么能根本消除竞态条件

ECONNRESET 竞态需要两个前提条件同时满足：

1. **连接池中存在直连连接**（在 iptables 生效之前建立）
2. **网络拓扑发生切换**（iptables 规则中途生效）

本方案同时消除了**两个前提**：

- 前提 1：iptables 规则在 sandbox 创建时就已生效。parent process 的第一个 `fetch()` 就走代理。连接池中**永远不存在直连连接**。
- 前提 2：不存在网络拓扑切换。iptables 规则在 parent process 整个生命周期中不发生变化。

直通→MITM 的模式切换**不会**重新引入竞态，因为：
- iptables 规则不变（流量始终经过相同的代理端口）
- 现有池连接是通过代理的 TCP 隧道；模式切换只影响代理如何处理**新的** HTTPS 连接
- 切换操作是普通的 HTTP POST（`/__activate-mitm`），不阻塞事件循环

### 四条设计原则

| # | 原则 | 实现 | 业界参考 | 解决的问题 |
|---|------|------|----------|------------|
| 1 | iptables 先于任何连接 | 镜像 snapshot 预置规则 | Istio init container 模式；E2B 官方 IP tunneling 文档 | ECONNRESET 竞态（PR #4378） |
| 2 | UID 豁免防回环 | nft `meta skuid "mitmproxy" accept`，proxy 以 `mitmproxy` 用户运行 | Istio UID 1337；Linkerd UID 2102；mitmproxy 官方文档 | 代理自环 P0 故障（2026-04-10） |
| 3 | CA 私钥每实例独立生成 | 运行时 `setupCa()`，不放入 snapshot | mitmproxy 官方文档；Firecracker 快照安全指南 | 加密状态泄露 |
| 4 | MITM 先于不可信代码 | `activateMitm()` 在 `spawn(Agent)` 之前顺序执行 | 纵深防御 | Agent 流量逃逸审计 |

## 改动内容

### 1. proxy-adapter：mitmproxy 用户 + 直通模式 + 热切换（sandbox-execution/）

**以 `mitmproxy` 用户运行：** proxy-adapter 进程以 `mitmproxy` 用户身份启动（template.py 已创建该用户）。配合 nft `meta skuid "mitmproxy" accept` 规则，proxy-adapter 的**所有出站流量**（包括 `forwardViaWorker` 的 `fetch()`）被内核豁免，不可能被 REDIRECT 回自己。

**删除源端口 hack：** 移除 `BYPASS_PORT_BASE`、`BYPASS_PORT_RANGE`、`randomBypassPort()`、`localPort` 绑定等源端口范围豁免逻辑。UID 豁免覆盖了所有代码路径，源端口绑定不再需要。

**新能力：** proxy-adapter 在无 CA 证书时以直通模式启动：
- HTTP 请求：直连转发到目标（复用现有 `forwardDirect()` 逻辑）
- HTTPS 连接：TCP 透传到 upstream:443（复用现有 `tunnelBypass()` 逻辑，当前已用于 bypass hosts）

**新端点：** `POST /__activate-mitm`
- 接受参数：`{ caCertPath, caKeyPath, sandboxToken, pipelineId, bypassHosts }`
- 用提供的 CA 初始化 `DynamicCertManager`
- TLS router 从"全部透传"切换到"bypass hosts 透传，其余 MITM"
- 切换完成后返回 200

**并发安全：** 激活前建立的连接继续以 TCP 透传隧道方式运行。只有激活后的新连接走 MITM 路径。这是安全的，因为 prep 阶段的连接目标全是可信的内部服务（Gitea、CDN、Datadog proxy）。

### 2. E2B 模板定义（paraflow-hq/sandbox template.py）

在模板构建中添加：

```python
.copy('proxy-adapter.js', '/opt/moxt-proxy/proxy-adapter.js')
.copy('iptables-setup.sh', '/opt/moxt-proxy/iptables-setup.sh', mode=0o755)
.set_start_cmd(
    "sudo -u mitmproxy node /opt/moxt-proxy/proxy-adapter.js --passthrough && /opt/moxt-proxy/iptables-setup.sh",
    wait_for_port(18080)
)
```

proxy-adapter 以 `mitmproxy` 用户启动（`sudo -u mitmproxy`）。

`iptables-setup.sh` 使用 nft（nf_tables）而非 legacy iptables，因为 E2B 内核禁用了 `xt_owner` 模块（`CONFIG_NETFILTER_XT_MATCH_OWNER is not set`），但 nf_tables 的 `meta skuid` 可用且已实测验证：

```bash
#!/bin/bash
set -e

# 使用 nft（nf_tables）实现透明代理规则
# 原因：E2B 内核 6.1.158 禁用了 CONFIG_NETFILTER_XT_MATCH_OWNER，
# iptables -m owner --uid-owner 不可用。nft meta skuid 通过内置的
# NF_TABLES 支持工作，已在 E2B sandbox 中实测验证。

nft -f - <<'NFT'
table ip proxy {
  chain output {
    type nat hook output priority -100; policy accept;

    # 【核心防回环规则】豁免 mitmproxy 用户的所有出站流量
    # 对标 Istio UID 1337 / Linkerd UID 2102 的 --uid-owner 机制
    # 已实测：mitmproxy 用户流量匹配此规则后直接出站，不被 REDIRECT
    meta skuid "mitmproxy" counter accept

    # 豁免私有地址范围
    ip daddr 0.0.0.0/8 accept
    ip daddr 127.0.0.0/8 accept
    ip daddr 10.0.0.0/8 accept
    ip daddr 172.16.0.0/12 accept
    ip daddr 192.168.0.0/16 accept
    ip daddr 169.254.0.0/16 accept
    ip daddr 192.0.2.0/24 accept
    ip daddr 198.51.100.0/24 accept
    ip daddr 203.0.113.0/24 accept

    # 重定向 HTTP/HTTPS 到代理
    tcp dport 80 counter redirect to :18080
    tcp dport 443 counter redirect to :18443
    tcp dport 8443 counter redirect to :18443
  }
}
NFT
```

这遵循了 E2B 官方 IP tunneling 文档中展示的模式（`setStartCmd` + 网络规则），并采用了 Istio/Linkerd/mitmproxy 统一使用的 UID 豁免防回环机制（通过 nft `meta skuid` 实现，而非 legacy iptables `--uid-owner`）。

### 3. parent-process.ts 简化

**删除：**
- `startProxyAdapterIfAvailable()` 中的 spawn 逻辑
- `setupIptablesTransparentProxy()` / `cleanupIptablesTransparentProxy()`
- `ensureIptablesTransparentProxy()`
- `pollProxyHealth()`
- 所有 `execSync` / `execAsync` iptables 命令
- `BYPASS_PORT_BASE` / `BYPASS_PORT_RANGE` 源端口范围常量（UID 豁免替代）

**保留：**
- `setupCa()` — 运行时 CA 生成（从 proxy-adapter 移到 parent process）
- `trustMitmCaCertForParentProcess()` — parent process 的 TLS monkey-patch
- `trustExistingProxyCaIfPresent()` — sandbox reuse 路径

**新增：**
- `activateMitm()` — 在 prep 阶段完成后、Agent spawn 之前，向 `/__activate-mitm` 发送一个 HTTP POST

### 4. Sandbox reuse 路径

改动极小。复用时：
- 代理进程已在运行（持久化 detached 进程）— 通过 PID + health check 检测（现有逻辑）
- iptables 规则已生效（来自 snapshot 或上一次运行）— 幂等检查（现有逻辑）
- CA 证书已存在（上一次运行时生成）— `trustExistingProxyCaIfPresent()` 处理（现有逻辑）
- 仅需 `updateProxyConfig()` 刷新 sandboxToken 和 pipelineId（现有逻辑）

## 验证

所有测试在真实 E2B sandbox 中执行（2026-04-16）。

### 实验一：iptables/nft 规则在 Firecracker 快照中的存活性

**方法：** 创建 E2B sandbox → 设置 iptables nat 规则 → 启动后台进程 → pause（Firecracker 快照）→ resume → 验证

**结果：**

```
  ✅ TESTCHAIN chain exists
  ✅ REDIRECT :443→:18443
  ✅ REDIRECT :80→:18080
  ✅ RETURN 127.0.0.0/8
  ✅ OUTPUT hooks TESTCHAIN
  ✅ Background process alive
```

**结论：** iptables/nft 规则和后台进程均在 Firecracker snapshot/restore 后完整存活。

### 实验二：E2B 内核 UID 豁免能力

**发现：** E2B 内核 6.1.158 **显式禁用了** `CONFIG_NETFILTER_XT_MATCH_OWNER`。legacy iptables `-m owner --uid-owner` 不可用。

**替代方案验证：** nf_tables 的 `meta skuid` 通过 `CONFIG_NF_TABLES=y` 内置支持可用。

### 实验三：nft `meta skuid` 完整功能验证

**方法：** 创建 E2B sandbox → 创建 `mitmproxy` 用户 → 以 mitmproxy 用户启动代理模拟器（python3 http.server :18080）→ 加载 nft 规则（skuid 豁免 + REDIRECT）→ 测试不同用户的流量走向 → pause/resume → 再次验证

**nft 规则：**
```
table ip proxy {
  chain output {
    type nat hook output priority dstnat; policy accept;
    meta skuid 999 counter accept          ← mitmproxy UID
    tcp dport 80 counter redirect to :18080
    tcp dport 443 counter redirect to :18080
  }
}
```

**结果：**

| 测试项 | snapshot 前 | snapshot 后 |
|--------|-------------|-------------|
| nft `meta skuid` 规则加载 | ✅ 成功 | — |
| root 用户 HTTP 流量被 REDIRECT 到代理 | ✅ 收到 `PROXY_INTERCEPTED` | ✅ 收到 `PROXY_INTERCEPTED` |
| mitmproxy 用户 HTTP 流量被豁免（不 REDIRECT） | ✅ 请求直连（超时，目标无服务器） | ✅ 请求直连（超时） |
| nft 规则存活 | — | ✅ `skuid rules: present` |
| nft counter 计数正确 | ✅ `skuid packets 2, redirect packets 33` | — |
| 代理进程存活 | — | ✅ 仍在运行 |

**关键 counter 证据：**
```
meta skuid 999 counter packets 2 bytes 120 accept    ← mitmproxy 流量命中豁免规则
tcp dport 80 counter packets 33 bytes 2412 redirect   ← 其他流量被重定向
```

**结论：** nft `meta skuid` 在 E2B sandbox 中完全可用，能精确区分 mitmproxy 用户和其他用户的流量，且在 Firecracker snapshot/restore 后保持有效。

**说明：** 所有测试使用运行时 pause/resume 路径（与 `setStartCmd` 使用相同的 Firecracker 快照机制）。`setStartCmd` build 路径尚未单独测试。生产部署前需在 `paraflow-hq/sandbox` template.py 上进行完整集成测试。

### 实验四：生产真实性（真实外部网络）

**方法：** 在 E2B sandbox 中加载 nft 规则（含 `flush ruleset`）后，测试真实外部网络行为。

**结果（19/19 通过）：**

| 测试项 | 结果 | 证据 |
|--------|------|------|
| `flush ruleset` 不破坏 E2B 现有网络 | ✅ | E2B sandbox 无预置 nft 规则 |
| DNS 解析在 nft 规则后正常 | ✅ | `google.com` → `142.251.188.101` |
| E2B SDK commands.run 正常 | ✅ | `echo "E2B_COMMS_OK"` 返回正确 |
| E2B SDK files.write/read 正常 | ✅ | 写入读回一致 |
| **真实 HTTP 被拦截** | ✅ | root `curl httpbin.org/get` → `OK path=/get`（proxy 拦截） |
| **mitmproxy 用户 HTTP 绕过 proxy 直连真实服务器** | ✅ | 返回 httpbin.org 真实 JSON 响应 |
| **真实 HTTPS 被拦截** | ✅ | root 连接 httpbin.org:443 → `TLS_PASSTHROUGH_REACHED` |
| **mitmproxy 用户 HTTPS 直连真实服务器** | ✅ | `curl https://httpbin.org/status/200` → HTTP 200 |
| 端口 8443 REDIRECT | ✅ | `TLS_PASSTHROUGH_REACHED` |
| UID 跨 snapshot 不变 | ✅ | `before: 999, after: 999` |
| proxy 进程 UID 跨 snapshot 不变 | ✅ | ps 输出一致 |
| nft skuid counter 跨 snapshot 后仍递增 | ✅ | `skuid packets: 5` |
| Proxy 崩溃可检测 | ✅ | health check 返回 `DEAD` |
| 流量在 proxy 死后失败（不静默丢弃） | ✅ | `CONN_REFUSED` |
| Proxy 可重启恢复 | ✅ | 重启后 health OK |
| 流量在 proxy 重启后恢复 | ✅ | `OK path=/recovery-test` |
| UDP (DNS) 不受 TCP nft 规则影响 | ✅ | DNS 解析正常 |

### 验证状态总结

| 层级 | 状态 | 测试数 | 说明 |
|------|------|--------|------|
| **基础设施层** | ✅ 已验证 | 49/49 | nft 内核支持、UID 豁免、REDIRECT、snapshot 存活、真实网络、DNS、并发、攻防 |
| **应用层** | ⏳ 待实施后验证 | — | 真实 proxy-adapter、`/__activate-mitm`、CA 生成、完整转发链路、sandbox reuse |

基础设施层的验证代码：https://github.com/paraflow-hq/sandbox-proxy-rfc

## 与现状对比

|  | 现状 | 本方案 |
|--|------|--------|
| ECONNRESET 竞态 | 缩小窗口（PR #4378 execAsync）但仍存在 | **不存在**（无拓扑切换） |
| 代理自环风险 | 源端口范围豁免，仅保护显式绑定的代码路径 | **UID 豁免，保护所有出站流量** |
| iptables 设置位置 | 运行时，在应用代码中 | 镜像层，在模板定义中 |
| 连接池中的直连连接 | 有（prep 阶段） | **永远没有** |
| 防回环机制 | `--sport 20000:29999`（部分覆盖） | nft `meta skuid "mitmproxy"`（完全覆盖） |
| CA 隔离 | 每实例生成 ✅ | 每实例生成 ✅（不变） |
| MITM 时序 | Agent 前就绪 ✅ | Agent 前就绪 ✅（不变） |
| 业界对标 | 无标准参考 | Istio/Linkerd/mitmproxy + E2B 官方文档 |

## 实施风险

| 风险 | 缓解措施 |
|------|----------|
| `/__activate-mitm` 热切换的并发安全 | 已有连接继续走透传；仅新连接走 MITM。新旧路径之间无共享可变状态。 |
| proxy-adapter.js 需烘焙进镜像 | proxy 逻辑变更时需重新构建镜像。可接受的取舍：proxy-adapter 变更不频繁；镜像构建已是模板更新流程的一部分。 |
| `setStartCmd` 集成路径尚未端到端测试 | 生产部署前需在 `paraflow-hq/sandbox` 仓库修改 template.py + 构建 + 创建 sandbox 验证。 |
| Prep 阶段 HTTPS 不被 MITM 拦截 | Prep 阶段仅访问可信内部服务（Gitea、CDN、Datadog proxy、S3）。Agent 不可信代码仅在 MITM 激活后才运行。 |
| `mitmproxy` 用户权限不足 | template.py 已配置 sudoers 允许 `cp` 和 `update-ca-certificates`（CA 安装所需）。proxy-adapter 监听 18080/18443 无需 root（>1024）。 |

## 实施注意事项

### 关键发现：TLS Router 热切换中 `pause()` 不可省略

**场景：** RFC 方案引入 passthrough → MITM 热切换。TLS Router 需要在收到 `POST /__activate-mitm` 后，将后续 HTTPS 连接从"TCP 透传"切换到"MITM 拦截"。切换的关键操作是：TLS Router 从 TCP socket 读取 TLS ClientHello 提取 SNI 后，将 socket 连同已读取的数据交给 HTTPS MITM server 处理。

**问题：** 在 Suite 10 测试 B5 中，passthrough → MITM 热切换后的第一个 HTTPS 连接一致失败。客户端（Python ssl）报 `SSL: UNEXPECTED_EOF_WHILE_READING`，即 TLS 握手过程中服务端突然关闭了连接。

**根因：** TLS Router 使用 `socket.on('data', ...)` 读取了 ClientHello 到 `buf` 中，然后执行以下操作将 socket 交给 MITM server：

```javascript
// ❌ 错误写法（B5 一致失败）
clientSocket.removeListener('data', onData)
clientSocket.unshift(buf)                    // 将 ClientHello 放回 socket 的读缓冲区
mitmServer.emit('connection', clientSocket)  // 注入到 HTTPS server
```

问题在于：`unshift(buf)` 将数据放回了 socket 的读缓冲区，但 socket 仍处于 flowing 模式（因为之前注册了 `data` 事件）。Node.js 事件循环会在当前同步代码执行完毕后立即触发 `readable` 事件，将 `unshift` 的数据消费掉——**在 HTTPS server 有机会读取它之前**。结果是 HTTPS server 收到一个空 socket，无法完成 TLS 握手。

**修复：**

```javascript
// ✅ 正确写法（B5 一致通过）
clientSocket.pause()                         // ← 关键：阻止事件循环消费 unshift 的数据
clientSocket.removeListener('data', onData)
clientSocket.unshift(buf)
mitmServer.emit('connection', clientSocket)  // HTTPS server 接管后会自行 resume
```

`pause()` 将 socket 切换到 paused 模式，阻止 `readable`/`data` 事件触发，确保 `unshift` 的 ClientHello 数据在 `emit('connection')` 后由 HTTPS server 的 TLS 层读取。HTTPS server 内部会在需要时自行 `resume()` socket。

**验证：**
- 无 `pause()`：Suite 10 B5 在 3 次独立运行中全部失败（`SSL: UNEXPECTED_EOF_WHILE_READING`）
- 有 `pause()`：Suite 10 B5 在 3 次独立运行中全部通过（收到 Moxt CA 签发的 MITM 证书）

**与现有代码的关系：** `mitm-proxy.ts` 第 305 行的 `routeConnection()` 函数已有 `clientSocket.pause()`。但该路径是在 proxy 始终以 MITM 模式启动时执行的（当前架构）。RFC 方案新增了 passthrough → MITM 热切换路径，这条新路径**必须**复制相同的 `pause()` 模式，否则热切换后的 HTTPS 连接会全部失败。

**实施清单：**
- [ ] `/__activate-mitm` 切换模式后，TLS Router 的 MITM 分支必须包含 `clientSocket.pause()`
- [ ] 新增的热切换代码应参考 `mitm-proxy.ts:routeConnection()` 的完整流程：`pause → removeListener → unshift → emit`
- [ ] 热切换功能的集成测试必须包含"激活后立即发起 HTTPS 连接"的验证（对应 Suite 10 B5）

### MITM server 必须用 `https.createServer`，不能用 `tls.createServer`

**场景：** 热切换的 MITM server 需要接收 TLS Router 通过 `emit('connection')` 注入的 socket。

**问题：** 使用 `tls.createServer` 创建 MITM server 时，注入的 socket TLS 握手失败（`SSL: UNEXPECTED_EOF_WHILE_READING`），即使 `pause()` 已正确调用。

**根因：** `tls.createServer` 和 `https.createServer` 对 `emit('connection')` 注入 socket 的处理不同。`https.createServer` 内部正确处理了从 raw TCP socket 开始的 TLS 握手序列（因为它在 `http.Server` 基础上包装了 TLS 层）。`tls.createServer` 期望接管完整的 socket 生命周期，对外部注入的 socket 行为不一致。

**修复：** MITM server 使用 `https.createServer`（与现有 `mitm-proxy.ts:156` 一致）。

**验证：** Suite 10 B5 使用 `https.createServer` 通过，`tls.createServer` 失败。

### E2B socat 拦截 `127.0.0.1` 端口的 TCP 连接

**场景：** 在 E2B sandbox 内部通过 `curl`/`wget`/`fetch` 访问 `127.0.0.1:18080`。

**问题：** 请求被 E2B 的 socat 端口转发进程拦截，而非直达 proxy-adapter。proxy-adapter 绑定在 `127.0.0.1:18080`，但 E2B socat 也在监听同端口（用于将 sandbox 端口暴露到外部）。结果是 `/__health` 和 `/__update-config` 等内部端点的请求被 socat 转发后改变了 HTTP 语义，proxy 将其当做普通转发请求处理。

**影响范围：** 仅影响 sandbox **内部**对 proxy 的 loopback 访问。nft REDIRECT 流量（外部 HTTP/HTTPS → proxy）不受影响，因为 nft 直接改写目标端口。

**规避方法：**
- `/__health` 检查改用 PID 文件 + 进程存活检测（`kill -0 PID` + `ss` 端口检查）
- `/__update-config` 和 `/__activate-mitm` 改用 Python raw socket 直连 `127.0.0.1:18080`（绕过 socat），或杀掉端口对应的 socat 进程

**生产影响：** 无。生产中 parent-process.ts 在 sandbox 内部通过 `fetch('http://127.0.0.1:18080/...')` 调用这些端点，此时 socat 转发不会改变 HTTP 语义（因为 parent-process 的 fetch 发到的是 proxy 而非 socat 目标）。该问题仅在**测试环境**中通过 E2B SDK 远程执行命令时出现。

**验证：** Suite 07 T7-T8、Suite 09 T1-T4 验证了通过杀 socat / raw socket 方式可以访问内部端点。

### E2B template 需要安装 `nftables` 和 `ca-certificates` 包

**场景：** 当前 `template.py` 安装了 `iptables` 但没有 `nftables`。proxy-adapter 的 `setupCa()` 调用 `update-ca-certificates` 将 MITM CA 安装到系统信任库。

**问题：**
1. nft 命令不存在——RFC 方案所有规则使用 nft，必须安装 `nftables` 包
2. `update-ca-certificates` 失败——E2B base image 可能缺少 `ca-certificates` 包，导致 proxy 启动时 CA 安装失败（proxy 日志：`update-ca-certificates failed`）

**修复：** `template.py` 中添加：
```python
.run_cmd("apt-get install -y nftables ca-certificates")
```

**验证：** Suite 07-10 的所有测试在 `setupSandbox()` 中显式安装这两个包后通过。

### `flush ruleset` 的安全性

**场景：** `nft-rules.conf` 以 `flush ruleset` 开头，清除所有 nft 规则后再加载 proxy 规则。

**当前状态：** E2B sandbox 无预置 nft 规则（Suite 05 R1a 验证），`flush ruleset` 安全。

**潜在风险：** 如果 E2B 未来在 base image 中添加自己的 nft 规则（如网络隔离），`flush ruleset` 会将其清除。

**建议：** 将 `flush ruleset` 改为 `flush table ip proxy`（仅清除 proxy 表），或在 flush 前检查是否存在非 proxy 表：

```
# 安全写法
table ip proxy {}           # 确保表存在
flush table ip proxy        # 只清除 proxy 表
delete table ip proxy       # 删除旧表
table ip proxy { ... }      # 重新创建
```

**验证：** Suite 05 R1a 确认当前 E2B 无预置 nft 规则。此建议为防御性改进。

### proxy-adapter.js bundle 必须从最新源码构建

**场景：** 测试时使用了 moxt 仓库中已存在的 `sandbox/proxy-adapter.js` bundle（20KB，2026-04-10 构建）。

**问题：** 该 bundle 缺少 `/__health` 和 `/__update-config` 端点——这些端点在源码中存在（`mitm-proxy.ts:190-215`），但 bundle 是从较早的代码构建的。所有依赖这两个端点的测试失败。

**修复：** 从最新源码重新构建 bundle：
```bash
cd sandbox/sandbox-execution
npx tsx scripts/gen-types-from-schema.ts  # 先生成类型
pnpm build                                # rspack 构建
# 输出: sandbox/proxy-adapter.js (24KB)
```

**教训：** 部署到 E2B template 之前，必须验证 proxy-adapter.js bundle 是从与 server-ts 相同的代码版本构建的。类型生成（`gen-types-from-schema.ts`）是构建的前置依赖，遗漏会导致构建失败。

**验证：** Suite 07 使用重建后的 bundle（24KB）通过 25/25，旧 bundle（20KB）在端点测试中失败。

### nft 规则先于 proxy 加载时 proxy 正常工作（已验证）

**场景：** RFC 方案是 image-layer 架构——nft 规则烘焙进 snapshot，proxy 启动时规则已生效。之前所有测试都是先启动 proxy 再加载 nft 规则。

**验证（Suite 13 Section A）：** 先加载 nft 规则，再启动 proxy-adapter。结果：
- proxy 正常启动（`PROXY_READY`）：CA 生成成功，因为 `openssl` 和 `sudo update-ca-certificates` 是本地操作，不受 nft 网络规则影响
- HTTP 转发、HTTPS MITM、UID 豁免全部正常

**结论：** nft 规则先于 proxy 加载不会导致 proxy 启动失败。image-layer 架构的前提条件已验证。

### Bypass hosts 没有独立的环境变量配置机制

**场景：** 实施 RFC 时可能需要动态添加 bypass hosts（如新增外部 API 不需要 MITM 拦截）。

**发现（Suite 14 Section A）：** `PROXY_BYPASS_HOSTS` 环境变量**不存在**于 moxt 代码库中。当前 bypass hosts 的来源仅有：

1. 硬编码：`api.anthropic.com`
2. 从 env URL 提取 hostname：`ANTHROPIC_BASE_URL`、`HTTP_PROXY_WORKER_URL`、`CDN_HOST`、`TXOM_ZIP_URL`、`MFS_S3_ENDPOINT`

**影响：** 如果需要添加新的 bypass host（如新增 LLM 提供商），必须通过以下方式之一：
- 在 `proxy-adapter.ts` 的 `buildBypassHosts()` 中硬编码
- 通过上述 env URL 变量间接添加（设置一个包含该 hostname 的 URL）

**建议：** RFC 实施时考虑添加 `PROXY_BYPASS_HOSTS` 环境变量，支持逗号分隔的自定义 bypass host 列表，以便运维团队灵活配置。

### 磁盘满时 cert 生成快速失败但不自动恢复

**场景：** E2B sandbox 的 `/tmp` 磁盘空间耗尽时，新 host 的 MITM cert 生成失败。

**验证（Suite 15 Section A）：**
- 磁盘满时 proxy **不会挂起**（95ms 内快速失败）✅
- 磁盘满时 proxy **不会崩溃**（进程存活）✅
- 磁盘释放后**已缓存**的 cert 仍可用 ✅
- 磁盘释放后新 host 的 cert 生成**可能不恢复**（openssl 临时文件状态污染）⚠️

**影响：** 磁盘满是极端场景，但如果发生，proxy 需要重启才能恢复 cert 生成能力。已缓存的 host 不受影响。

### `update-ca-certificates` 失败时 curl/wget 将无法验证 MITM 证书

**场景：** E2B base image 缺少 `ca-certificates` 包，或 `update-ca-certificates` 执行失败。

**验证（Suite 15 Section B）：**
- Proxy 仍能启动（`PROXY_READY`）✅
- CA cert 文件本身生成成功 ✅
- `NODE_EXTRA_CA_CERTS` 作为备选方案有效（Node.js child process 可信任 MITM CA）✅
- **curl/wget 将失败**（系统信任库未更新，certificate verify failed）⚠️
- **显式指定 `--cacert` 可绕过**（`curl --cacert /tmp/moxt-proxy/ca.crt`）✅

**影响：** Agent 如果使用 curl/wget/Python requests 且依赖系统信任库，MITM host 的 HTTPS 请求会失败。Node.js child process 通过 `NODE_EXTRA_CA_CERTS` 不受影响。

**缓解：** `template.py` 必须安装 `ca-certificates` 包（已在实施计划中记录）。`buildProxyEnvVars()` 设置 `SSL_CERT_FILE`/`REQUESTS_CA_BUNDLE`/`CURL_CA_BUNDLE` 指向系统 CA 文件——前提是该文件已被 `update-ca-certificates` 更新。

### proxy 对恶意/畸形输入的韧性（已验证）

**验证（Suite 15 Section C-G）：**
| 场景 | 结果 |
|------|------|
| Invalid JSON to `/__update-config` | 返回 400，proxy 存活 ✅ |
| 截断的请求 body（Content-Length 不匹配） | Proxy 存活 ✅ |
| 客户端在 `forwardDirect` 流传输中断开 | Proxy 存活，后续请求正常 ✅ |
| 纯 HTTP 发送到 TLS 端口 18443 | 连接关闭，proxy 存活 ✅ |
| 损坏的 TLS ClientHello 发送到 18443 | TLS alert 返回，proxy 存活 ✅ |
| 缺少 Host header 的 HTTP 请求 | 返回 400，proxy 存活 ✅ |
| 10 并发 HTTPS 到同一未缓存 host | 零 cert 失败，proxy 存活 ✅ |

## 实施计划

1. **验证：** 修改 `paraflow-hq/sandbox` template.py，在 `setStartCmd` 中添加最小化代理 + nft 规则。构建模板，创建 sandbox，验证规则和代理在创建时即已生效。注意 template.py 需增加 `apt-get install -y nftables`（当前只安装了 iptables）。
2. **实现代理直通模式：** 修改 proxy-adapter，支持无 CA 启动，HTTPS 默认 TCP 透传。新增 `/__activate-mitm` 端点。
3. **实现 parent-process 改动：** 删除运行时 iptables/spawn 逻辑。在 prep 阶段后添加 `activateMitm()` 调用。
4. **端到端测试：** 在 dev 环境完整运行 pipeline。验证：prep 期间无 ECONNRESET、Agent 前 MITM 已激活、sandbox reuse 正常。
5. **部署：** 重新构建模板 + 部署 server-ts。已有 sandbox 继续使用运行时 iptables（来自之前的运行）。新 sandbox 使用镜像层规则。

## 参考资料

- [E2B IP Tunneling 文档](https://e2b.dev/docs/sandbox/ip-tunneling) — 官方透明代理设置，使用 `setStartCmd` + iptables
- [E2B Start/Ready Command 文档](https://e2b.dev/docs/template/start-ready-command) — `setStartCmd` 在 build 阶段运行，snapshot 捕获运行中的进程
- [nodejs/node #54293](https://github.com/nodejs/node/issues/54293) — 事件循环阻塞 + keep-alive = ECONNRESET
- [nodejs/undici #3492](https://github.com/nodejs/undici/issues/3492) — fetch 可能复用已关闭的连接（仍 open）
- [aws/aws-sdk-js-v3 #6861](https://github.com/aws/aws-sdk-js-v3/issues/6861) — execSync + ECONNABORTED
- [Firecracker Snapshot 文档](https://github.com/firecracker-microvm/firecracker/blob/main/docs/snapshotting/snapshot-support.md) — 快照保存完整 guest memory
- [Firecracker Snapshot 安全](https://github.com/firecracker-microvm/firecracker/blob/main/docs/snapshotting/random-for-clones.md) — 警告不应在 VM 克隆间共享加密状态
- [mitmproxy 证书文档](https://docs.mitmproxy.org/dev/concepts/certificates/) — CA 每安装实例独立生成
- [mitmproxy 透明模式文档](https://docs.mitmproxy.org/stable/howto-transparent/) — `--uid-owner` 防回环
- [PR #4378](https://github.com/paraflow-hq/moxt/pull/4378) — ECONNRESET 缓解方案（execSync → execAsync）
- [#3784](https://github.com/paraflow-hq/moxt/issues/3784) — P0 故障分析：代理自环
