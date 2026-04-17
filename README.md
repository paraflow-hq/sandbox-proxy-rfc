# Sandbox Transparent Proxy Architecture RFC

RFC 及验证测试：将 E2B sandbox 透明代理的 iptables 设置从运行时初始化改为镜像层预置，采用 `nft meta skuid` 防回环机制。

## 解决的问题

1. **ECONNRESET 竞态**：parent process 中途设置 iptables 导致连接池僵尸连接
2. **代理自环 P0 故障**（2026-04-10）：proxy-adapter 出站流量被 iptables 重定向回自身

## 核心原则

```
镜像层（snapshot）：网络拓扑（nft rules + proxy 直通模式 + UID 豁免）
运行时（per-instance）：加密身份（CA 生成 → MITM 激活 → Agent 启动）
```

| # | 原则 | 实现 | 业界参考 | 解决的问题 |
|---|------|------|----------|------------|
| 1 | iptables 先于任何连接 | 镜像 snapshot 预置 nft 规则 | Istio init container；E2B 官方文档 | ECONNRESET 竞态 |
| 2 | UID 豁免防回环 | `nft meta skuid "mitmproxy" accept` | Istio UID 1337；Linkerd UID 2102 | P0 自环 |
| 3 | CA 每实例独立生成 | 运行时 `setupCa()`，不放入 snapshot | mitmproxy 官方；Firecracker 安全指南 | 加密状态泄露 |
| 4 | MITM 先于不可信代码 | `activateMitm()` 顺序在 `spawn(Agent)` 之前 | 纵深防御 | 流量逃逸 |

**完整 RFC**: [RFC.md](./RFC.md) | **独立分析**: [INDEPENDENT-ANALYSIS.md](./INDEPENDENT-ANALYSIS.md)

## 为什么要改：基于事实的分析

### 事实 1：当前架构已产生 2 起生产事故

| 事故 | 日期 | 影响 | 根因 |
|------|------|------|------|
| ECONNRESET 竞态 | 持续存在 | 单次请求概率性失败 | 连接池跨越 iptables 拓扑切换（[PR #4378](https://github.com/paraflow-hq/moxt/pull/4378)） |
| 代理自循环 P0 | 2026-04-10 | **70 分钟全量 Agent 不可用** | `fetch()` 使用 OS 临时端口，不在 `--sport 20000:29999` 豁免范围内（[#3784](https://github.com/paraflow-hq/moxt/issues/3784)） |

两起事故分别对应当前架构的两个结构缺陷：**运行时中途注入规则**和**端口范围防循环**。

### 事实 2：业界无端口范围防循环先例

所有主流透明代理项目均使用 **UID 豁免**，无一使用端口范围豁免：

| 项目 | 防循环机制 | 来源 |
|------|-----------|------|
| Istio | `--uid-owner 1337` | [istio/istio](https://github.com/istio/istio) |
| Linkerd | `--uid-owner 2102` | [linkerd/linkerd2-proxy-init](https://github.com/linkerd/linkerd2-proxy-init) |
| mitmproxy | `! --uid-owner mitmproxyuser` | [官方文档](https://docs.mitmproxy.org/stable/howto-transparent/) |
| Squid | `--uid-owner squid` | [官方文档](http://wiki.squid-cache.org/ConfigExamples/Intercept/LinuxRedirect) |

端口范围豁免的结构缺陷：任何使用 OS 分配端口的代码路径（如 Node.js `fetch()`）不受保护。UID 豁免覆盖代理进程的**所有**出站流量，无盲区。

### 事实 3：业界无运行时中途注入规则先例

所有主流 service mesh 和代理框架均在应用代码运行**之前**建立拦截规则：

| 平台 | 做法 | 来源 |
|------|------|------|
| Istio | init container **先于**应用容器 | [架构文档](https://istio.io/latest/docs/ops/deployment/architecture/) |
| Linkerd | `linkerd-init` **先于**应用启动 | [架构文档](https://linkerd.io/2/reference/architecture/) |
| E2B 官方 | `setStartCmd` 构建阶段执行，捕获进快照 | [IP Tunneling 文档](https://e2b.dev/docs/sandbox/ip-tunneling) |

当前 Moxt 架构在 parent-process 已发出约 90 次 HTTP 请求后才设置 iptables——是已知唯一在应用已建立连接后中途切换网络拓扑的实现。

### 事实 4：故障模式从静默变为显式

| 维度 | 当前架构 | RFC 架构 |
|------|---------|---------|
| 最严重故障 | 静默、概率性（ECONNRESET 依赖时序；自循环在被触发前不可见） | 显式、确定性（代理崩溃→连接被拒；模板错误→CI 失败） |
| 维护负担位置 | **运行时**（故障 = 生产事故） | **构建时**（故障 = CI 失败） |
| 运行时动态步骤 | 4 步（含依赖人工纪律的端口绑定） | 2 步（快照恢复 + MITM 激活） |

完整分析（10 个章节，含故障模式对比、维护负担详解、测试证据）：[INDEPENDENT-ANALYSIS.md](./INDEPENDENT-ANALYSIS.md)

## E2B 内核约束

E2B 内核 6.1.158 **禁用了** `CONFIG_NETFILTER_XT_MATCH_OWNER`（legacy iptables `-m owner`），但 nf_tables 的 `meta skuid` 可用（`CONFIG_NF_TABLES=y`）。所有规则使用 nft 实现。

## 验证状态

### 7 套件 74 项，全部通过 ✅

所有测试在**真实 E2B sandbox** 中执行，包含 Firecracker snapshot/restore 周期。Suite 07 使用**真实 rspack 构建的 proxy-adapter.js（23KB bundle）**，非模拟器。

| 套件 | 测试数 | 使用的代理 | 覆盖内容 |
|------|--------|-----------|---------|
| **01-components** | 12/12 ✅ | Python 模拟器 | nft skuid 内核支持、UID 豁免（HTTP+HTTPS）、snapshot 存活 |
| **02-e2e-lifecycle** | 9/9 ✅ | Python 模拟器 | 完整生命周期：snapshot → prep → MITM 激活 → nft counter |
| **03-gap-coverage** | 4/4 ✅ | Python 模拟器 | Node.js fetch 被拦截、mitmproxy fetch HTTPS 不自环 |
| **04-adversarial** | 5/5 ✅ | Python 模拟器 | ECONNRESET 复现失败、P0 自环复现失败、并发 |
| **05-production-reality** | 19/19 ✅ | Python 模拟器 | 真实 httpbin.org、DNS、E2B SDK、proxy 崩溃恢复 |
| **06-passthrough-poc** | 12/12 ✅ | Node.js PoC | HTTP 中继、TLS 隧道、热切换、snapshot 存活 |
| **07-real-proxy-adapter** | 25/25 ✅ | **真实 proxy-adapter.js** | 见下方详细列表 |

### Suite 07 详细测试清单（真实 proxy-adapter.js）

| # | 测试 | 验证的代码路径 | 证据 |
|---|------|--------------|------|
| T1 | proxy-adapter 以 mitmproxy 用户启动 | `main()` → `setupCa()` → `startMitmProxy()` | `PROXY_READY` in log |
| T2 | CA 证书和密钥生成 | `setupCa()` → `generateCaCert()` | `/tmp/moxt-proxy/ca.crt` + `ca.key` 存在 |
| T3 | CA 证书是有效 x509 | `generateCaCert()` openssl 调用 | `subject=CN=Moxt Sandbox Proxy CA` |
| T4 | 双端口监听 | `startMitmProxy()` → `proxyServer.listen()` + `tlsRouter.listen()` | `:18080` + `:18443` |
| T5 | 进程以 mitmproxy 用户运行 | `sudo -u mitmproxy` 启动 | `ps` 输出含 `mitmprox` |
| T6 | Bypass hosts 正确解析 | `buildBypassHosts()` | `httpbin.org` 在 bypass 列表中 |
| T7 | Health endpoint | `req.url === '/__health'` | 进程存活 + 端口监听 |
| T8 | `/__update-config` 端点存在 | `req.url === '/__update-config'` | bundle 中包含该端点代码 |
| **T9** | **HTTP → forwardViaWorker 完整代码路径** | nft REDIRECT → `forwardViaWorker()` → `fetch(workerUrl)` | `HTTP_CODE:404`（请求完成，未自循环） |
| **T10** | **HTTPS 非 bypass → MITM 动态证书** | nft REDIRECT → TLS router → `DynamicCertManager.getSecureContext()` | `example.com.crt` 生成 |
| **T11** | **Bypass host 无 MITM 证书** | TLS router → `tunnelBypass()` | `httpbin.org.crt` 不存在 |
| **T12** | **mitmproxy 用户 HTTPS 直连** | nft `meta skuid` → accept | `STATUS:200`（直连 httpbin.org） |
| **T13** | **nft skuid counter 证明 UID 豁免** | proxy 出站 `fetch()` → 内核匹配 skuid | `skuid packets: 6` |
| **T14** | **P0 回归：forwardViaWorker 不自循环** | `forwardViaWorker()` → `fetch(workerUrl:443)` → UID 豁免 | `P0_OK:404 in 112ms` |
| T15 | 5 并发 forwardViaWorker | 并发 `fetch()` → 并发 `forwardViaWorker()` | `completed:5, total:5` |
| **T16** | **Node.js fetch 信任 MITM CA** | `NODE_EXTRA_CA_CERTS` → TLS 握手成功 | `FETCH_STATUS:404`（TLS 未报错） |
| T17 | HTTP 审计日志 | `recordHttpRequest()` | `/tmp/http-audit-rfc-test-pipeline.jsonl` 创建 |
| T18 | Proxy 存活 snapshot/restore | Firecracker pause/resume | 进程存活 + 端口监听 |
| T19 | forwardViaWorker 在 restore 后工作 | snapshot/restore → `forwardViaWorker()` | `OK:404` |
| T20 | nft skuid 规则存活 restore | nf_tables 状态持久化 | `skuid` 规则存在 |
| T21 | UID 豁免在 restore 后工作 | `meta skuid` 规则持久化 | `STATUS:200` |
| T22 | Proxy 存活双次 snapshot | 模拟 sandbox reuse | 进程存活 |
| T23 | 完整链路在双 snapshot 后工作 | 全链路持久化 | `OK:404` |
| T24 | Proxy 崩溃可检测 | `kill` → health 失败 | 进程不存在 |
| T25 | Proxy 崩溃后可重启 | 重启 → `PROXY_READY` | 日志确认 |

### 关键证据摘要

| 验证目标 | 证据 |
|---------|------|
| **P0 自循环已消除** | T14: `forwardViaWorker` 在 **112ms** 内完成（自循环会 timeout） |
| **UID 豁免有效** | T13: nft skuid counter = 6（proxy 出站流量被内核豁免） |
| **MITM 证书链有效** | T16: Node.js `fetch('https://example.com/')` → `FETCH_STATUS:404`（TLS 握手成功，CA 被信任） |
| **Bypass 路由正确** | T10+T11: 非 bypass host 生成 MITM 证书 ✅ / bypass host 不生成 ✅ |
| **全链路存活快照** | T18-T23: proxy + nft + UID 豁免经历双次 Firecracker snapshot 后全部存活 |

### 仍待验证（需新代码实施后）

| 待验证项 | 原因 |
|----------|------|
| `--passthrough` 启动模式 | 代码不存在（需实现） |
| `/__activate-mitm` 热切换 | 代码不存在（需实现） |
| `setStartCmd` template build | 需修改 `paraflow-hq/sandbox` template.py |

这 3 项都是**尚未编写的新代码**，不是测试遗漏。现有代码的所有关键路径均已验证。

## 运行测试

### 前置条件

- Node.js >= 18
- pnpm
- E2B API Key

### 安装

```bash
pnpm install
```

### 运行全部已完成的测试

```bash
E2B_API_KEY=<your-key> pnpm test
# 或
pnpm test <your-key>
```

### 运行单个测试套件

```bash
pnpm test:components <key>     # 01: 组件验证（12 tests）
pnpm test:e2e <key>            # 02: 端到端生命周期（9 tests）
pnpm test:gaps <key>           # 03: 盲区覆盖（4 tests）
pnpm test:adversarial <key>    # 04: 对抗性测试（5 tests）
pnpm test:reality <key>        # 05: 生产真实性（19 tests）
pnpm test:poc <key>            # 06: passthrough PoC（12 tests）
pnpm test:real <key>           # 07: 真实 proxy-adapter（25 tests）
```

## 文件结构

```
tests/
├── helpers.cjs               # 共享基础设施（sandbox 创建、exec、snapshot、tcp-connect）
├── run-all.cjs               # 顺序运行全部套件
├── 01-components.cjs         # 组件验证（12 tests）
├── 02-e2e-lifecycle.cjs      # 端到端生命周期（9 tests）
├── 03-gap-coverage.cjs       # 盲区覆盖（4 tests）
├── 04-adversarial.cjs        # 对抗性测试（5 tests）
├── 05-production-reality.cjs # 生产真实性（19 tests）
├── 06-passthrough-poc.cjs    # passthrough PoC（12 tests）
└── 07-real-proxy-adapter.cjs # 真实 proxy-adapter.js 集成（25 tests）

fixtures/
├── proxy.py                  # Python proxy 模拟器（Suite 01-05）
├── proxy-passthrough-poc.mjs # Node.js PoC proxy（Suite 06）
├── proxy-adapter.js          # 真实 rspack 构建 proxy-adapter（Suite 07, 23KB）
├── nft-rules.conf            # RFC nft 规则（含 meta skuid 豁免）
├── tcp-connect.py            # TCP 连接测试（替代 nc）
├── attack-econnreset.mjs     # ECONNRESET 复现
├── attack-selfloop.mjs       # P0 自环复现
├── attack-pool-waves.mjs     # 连接池健康性
└── attack-concurrent.mjs     # 并发负载测试
```

## 文档

- **[RFC.md](./RFC.md)** — 完整 RFC：问题分析、方案设计、实施计划
- **[VERIFICATION-STATUS.md](./VERIFICATION-STATUS.md)** — 验证状态跟踪
- **[INDEPENDENT-ANALYSIS.md](./INDEPENDENT-ANALYSIS.md)** — 独立分析：RFC vs 当前架构的事实对比（防循环机制、规则时机、故障模式、业界先例）

## 关联

- **RFC Issue**: [paraflow-hq/moxt#4383](https://github.com/paraflow-hq/moxt/issues/4383)
- **ECONNRESET 修复 PR**: [paraflow-hq/moxt#4378](https://github.com/paraflow-hq/moxt/pull/4378)
- **P0 故障分析**: [paraflow-hq/moxt#3784](https://github.com/paraflow-hq/moxt/issues/3784)
