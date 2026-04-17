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

### 事实 3：业界无运行时中途注入规则先例

| 平台 | 做法 | 来源 |
|------|------|------|
| Istio | init container **先于**应用容器 | [架构文档](https://istio.io/latest/docs/ops/deployment/architecture/) |
| Linkerd | `linkerd-init` **先于**应用启动 | [架构文档](https://linkerd.io/2/reference/architecture/) |
| E2B 官方 | `setStartCmd` 构建阶段执行，捕获进快照 | [IP Tunneling 文档](https://e2b.dev/docs/sandbox/ip-tunneling) |

### 事实 4：故障模式从静默变为显式

| 维度 | 当前架构 | RFC 架构 |
|------|---------|---------|
| 最严重故障 | 静默、概率性（ECONNRESET 依赖时序；自循环在被触发前不可见） | 显式、确定性（代理崩溃→连接被拒；模板错误→CI 失败） |
| 维护负担位置 | **运行时**（故障 = 生产事故） | **构建时**（故障 = CI 失败） |
| 运行时动态步骤 | 4 步（含依赖人工纪律的端口绑定） | 2 步（快照恢复 + MITM 激活） |

完整分析（10 个章节）：[INDEPENDENT-ANALYSIS.md](./INDEPENDENT-ANALYSIS.md)

## E2B 内核约束

E2B 内核 6.1.158 **禁用了** `CONFIG_NETFILTER_XT_MATCH_OWNER`（legacy iptables `-m owner`），但 nf_tables 的 `meta skuid` 可用（`CONFIG_NF_TABLES=y`）。所有规则使用 nft 实现。

## 验证状态

### 19 套件 355 项，全部通过 ✅

所有测试在**真实 E2B sandbox** 中执行，包含 Firecracker snapshot/restore 周期。Suite 07-15 使用**真实 rspack 构建的 proxy-adapter.js（24KB bundle）**。Suite 10-11 使用**自写的 passthrough → MITM 热切换实现**验证 RFC 核心新机制。Suite 16 使用 **E2B Template SDK `setStartCmd` API** 构建真实模板，验证生产 build 路径。Suite 17 覆盖 **WebSocket（ws:// / wss://）** 透明代理行为。Suite 18 使用**真实 proxy-adapter.js 的 `--passthrough` + `/__activate-mitm`** 验证 RFC 完整热切换机制。Suite 19 验证**真实 proxy-adapter.js --passthrough + setStartCmd 模板构建**——生产部署的精确路径。

| 套件 | 测试数 | 使用的代理 | 覆盖内容 |
|------|--------|-----------|---------|
| **01-components** | 12 ✅ | Python 模拟器 | nft skuid 内核支持、UID 豁免、snapshot 存活 |
| **02-e2e-lifecycle** | 9 ✅ | Python 模拟器 | 完整生命周期：snapshot → prep → MITM 激活 → nft counter |
| **03-gap-coverage** | 4 ✅ | Python 模拟器 | Node.js fetch 被拦截、mitmproxy fetch 不自环 |
| **04-adversarial** | 5 ✅ | Python 模拟器 | ECONNRESET 复现失败、P0 自环复现失败 |
| **05-production-reality** | 19 ✅ | Python 模拟器 | 真实 httpbin.org、DNS、E2B SDK、proxy 崩溃恢复 |
| **06-passthrough-poc** | 12 ✅ | Node.js PoC | HTTP 中继、TLS 隧道、热切换、snapshot 存活 |
| **07-real-proxy-adapter** | 25 ✅ | **真实 bundle** | forwardViaWorker、DynamicCertManager、tunnelBypass、审计日志 |
| **08-extended-coverage** | 8 ✅ | **真实 bundle** | Root HTTPS bypass 真实证书、ECONNRESET 对抗、50 并发 |
| **09-deep-coverage** | 14 ✅ | **真实 bundle** | /__health 响应、/__update-config 生效、forwardDirect、审计日志内容、1MB payload |
| **10-production-sequence** | 20 ✅ | **真实 bundle + 热切换** | trustMitmCaCertForParentProcess、生产启动全序列、HTTPS forwardDirect、并发 MITM |
| **11-hotswitch-lifecycle** | 18 ✅ | **热切换实现** | passthrough ECONNRESET 证明、全生命周期 + snapshot、幂等激活、并发模式切换 |
| **12-production-edge-cases** | 32 ✅ | **热切换实现** | sandbox reuse、崩溃恢复、跨模式双 snapshot、keep-alive 跨切换、混合工作负载 |
| **13-stress-and-resilience** | 25 ✅ | **真实 bundle** | nft-先于-proxy 验证、100 请求 burst、错误韧性、二进制 payload、20 host cert 生成 |
| **14-moxt-code-paths** | 21 ✅ | **真实 bundle** | bypass hosts env 解析、feature switch 禁用、缺失 env vars、TLS monkey-patch 深度验证 |
| **15-final-coverage** | 29 ✅ | **真实 bundle** | 磁盘满、缺失 update-ca-certificates、畸形输入、客户端中断、坏 TLS 数据、并发同 host cert |
| **16-setStartCmd-template-build** | 29 ✅ | **Template SDK build** | `setStartCmd` 真实模板构建、proxy + nft 从 sandbox 创建即生效、UID 豁免、snapshot/restore、多 sandbox 隔离、完整 RFC 生命周期 |
| **17-websocket** | 25 ✅ | **真实 bundle + 热切换** | ws:// HTTP Upgrade 优雅处理、wss:// passthrough TCP 隧道全双工 echo、wss:// MITM TLS 终止、并发 WebSocket 韧性、UID 豁免 WebSocket 绕过 |
| **18-real-passthrough-activate-mitm** | 24 ✅ | **真实 bundle（含 --passthrough + /__activate-mitm）** | passthrough 启动无 CA、health 报告模式、HTTP 直转、HTTPS 真实上游证书、激活 MITM 后 HTTPS 获得 Moxt CA 证书、snapshot/restore 存活、幂等激活 |
| **19-template-real-passthrough** | 24 ✅ | **真实 bundle --passthrough + Template SDK build** | 生产精确路径：setStartCmd 烘焙真实 proxy-adapter.js --passthrough + nft 规则、passthrough 从 sandbox 创建即生效、activate-mitm、MITM 证书、二次 snapshot 存活、多 sandbox 隔离 + 独立激活 |

### 关键证据摘要

| 验证目标 | 证据 | 套件 |
|---------|------|------|
| **P0 自循环已消除** | `forwardViaWorker` 在 **112ms** 完成（自循环会 timeout） | 07 T14 |
| **ECONNRESET 已消除** | 100 sequential + 50 concurrent = **0** ECONNRESET | 13 B2-B4 |
| **UID 豁免有效** | nft skuid counter = 6（proxy 出站被内核豁免） | 07 T13 |
| **Passthrough → MITM 热切换** | passthrough 收到 Cloudflare 真实证书 → 激活 → 收到 Moxt CA 证书 | 10 B2-B5 |
| **热切换 + snapshot** | passthrough → snap → restore → activate MITM → MITM cert ✅ | 11 B1-B8 |
| **Image-layer 顺序** | nft 先于 proxy 加载：CA 生成、HTTP、MITM、UID 豁免全部正常 | 13 A1-A5 |
| **TLS monkey-patch** | `fetch()` + `https.request()` 通过 monkey-patch 信任 MITM CA（无需 NODE_EXTRA_CA_CERTS） | 14 D2-D5 |
| **Sandbox reuse** | 第二次 pipeline 重新激活 MITM，HTTP/HTTPS 正常 | 12 A1-A7 |
| **崩溃恢复** | MITM 崩溃 → 流量显式失败 → 重启 passthrough → 重新激活 MITM | 12 B1-B9 |
| **错误韧性** | 5xx、DNS 失败、超时、invalid JSON、截断 body、坏 TLS — proxy 全部存活 | 13 C, 15 C-E |
| **磁盘满** | cert gen 95ms 快速失败不挂起，proxy 存活 | 15 A2-A3 |
| **20 host 并发 cert** | 20 real hosts → 20 MITM certs，零 cert 失败 | 13 E2 |
| **混合工作负载** | 10 HTTP + 5 bypass + 5 MITM 并发，零 ECONNRESET | 12 E2 |
| **setStartCmd build 路径** | Template SDK 构建真实模板 → sandbox 创建即 proxy + nft 就绪 → UID 豁免有效 | 16 A1-B10 |
| **Template sandbox 多实例隔离** | 同 template 创建多 sandbox，proxy/nft 独立，请求不串 | 16 D1-D5 |
| **WebSocket wss:// passthrough** | raw TCP 隧道全双工 echo，WebSocket 帧完整通过 | 17 B1-B5 |
| **WebSocket ws:// 优雅处理** | HTTP Upgrade 不传播但 proxy 不 crash，正常返回 HTTP 响应 | 17 A1-A5 |
| **真实 --passthrough 启动** | proxy-adapter.js `--passthrough` 无 CA 启动，health 报告 passthrough | 18 A1-A4 |
| **真实 /__activate-mitm** | CA 生成 → POST /__activate-mitm → HTTPS 获得 Moxt CA 证书 | 18 C3-D2 |
| **Passthrough → MITM snapshot** | passthrough → activate → snapshot → restore → MITM 仍生效 | 18 E1-E5 |
| **生产精确路径** | 真实 proxy-adapter.js --passthrough + setStartCmd 模板构建 → passthrough 从 birth → activate → MITM cert → 二次 snapshot | 19 全部 |
| **Template 多 sandbox 独立激活** | 同 template 两 sandbox，各自独立 passthrough → 独立 activate → 独立 MITM | 19 F1-F4 |

### 仍待验证（无）

所有待验证项已全部完成。包括生产部署的精确路径（真实 proxy-adapter.js --passthrough + setStartCmd 模板构建）已通过 Suite 19（24/24）在真实 E2B 环境中验证。

### 源码覆盖率

所有 proxy-adapter 源码函数均已被至少一项测试覆盖：

| 源码文件 | 函数/路径 | 测试 |
|---------|----------|------|
| proxy-adapter.ts | `main()` 启动 | 07 T1 |
| proxy-adapter.ts | `buildBypassHosts()` | 14 A1-A6 |
| proxy-adapter.ts | Feature switch 禁用 / 缺失 env vars | 14 B1-C2 |
| cert-manager.ts | `setupCa()` + `generateCaCert()` | 07 T2-T3 |
| cert-manager.ts | `installCaToSystemTrustStore()` | 15 B1-B5 |
| cert-manager.ts | `DynamicCertManager.getSecureContext()` | 07 T10, 13 E2, 15 F2 |
| cert-manager.ts | 磁盘满 cert gen | 15 A2-A4 |
| mitm-proxy.ts | `startMitmProxy()` | 07 T4 |
| mitm-proxy.ts | `createTlsRouter()` bypass | 07 T11, 08 T1 |
| mitm-proxy.ts | `createTlsRouter()` MITM | 07 T10, 08 T2 |
| mitm-proxy.ts | `createTlsRouter()` non-TLS | 15 E2-E3 |
| mitm-proxy.ts | `tunnelBypass()` | 07 T11, 08 T1 |
| mitm-proxy.ts | `forwardViaWorker()` | 07 T9/T14, 08 T4-T8, 13 B2 |
| mitm-proxy.ts | `forwardDirect()` | 09 T5-T6, 13 D2 |
| mitm-proxy.ts | `forwardDirect()` 客户端中断 | 15 D2-D4 |
| mitm-proxy.ts | `/__health` | 09 T1 |
| mitm-proxy.ts | `/__update-config` | 09 T2-T3 |
| mitm-proxy.ts | `/__update-config` invalid JSON | 15 C2 |
| mitm-proxy.ts | `collectBody()` 截断 | 15 C4 |
| mitm-proxy.ts | 缺失 Host header | 15 G2 |
| http-audit-recorder.ts | `recordHttpRequest()` | 09 T7-T8 |
| transparent-proxy.ts | `trustMitmCaCertForParentProcess()` | 14 D2-D5 |

## 运行测试

### 前置条件

- Node.js >= 18
- pnpm
- E2B API Key

### 安装

```bash
pnpm install
```

### 运行全部测试

```bash
E2B_API_KEY=<your-key> pnpm test
```

### 运行单个套件

```bash
pnpm test:components <key>     # 01: 组件验证（12 tests）
pnpm test:e2e <key>            # 02: 端到端生命周期（9 tests）
pnpm test:gaps <key>           # 03: 盲区覆盖（4 tests）
pnpm test:adversarial <key>    # 04: 对抗性测试（5 tests）
pnpm test:reality <key>        # 05: 生产真实性（19 tests）
pnpm test:poc <key>            # 06: passthrough PoC（12 tests）
pnpm test:real <key>           # 07: 真实 proxy-adapter（25 tests）
pnpm test:extended <key>       # 08: 扩展覆盖（8 tests）
pnpm test:deep <key>           # 09: 深度覆盖（14 tests）
pnpm test:production <key>     # 10: 生产序列 + 热切换（20 tests）
pnpm test:lifecycle <key>      # 11: 热切换全生命周期（18 tests）
pnpm test:edge <key>           # 12: 生产边缘场景（32 tests）
pnpm test:stress <key>         # 13: 压力与韧性（25 tests）
pnpm test:moxt <key>           # 14: moxt 代码路径（21 tests）
pnpm test:final <key>          # 15: 终极覆盖（29 tests）
pnpm test:template <key>       # 16: setStartCmd 模板构建（29 tests）
pnpm test:websocket <key>      # 17: WebSocket 透明代理（25 tests）
pnpm test:passthrough <key>    # 18: 真实 --passthrough + /__activate-mitm（24 tests）
pnpm test:template-passthrough <key> # 19: 真实 --passthrough + setStartCmd 模板构建（24 tests）
```

## 文件结构

```
tests/
├── helpers.cjs                # 共享基础设施
├── run-all.cjs                # 顺序运行全部套件
├── 01-components.cjs          # 组件验证（12）
├── 02-e2e-lifecycle.cjs       # 端到端生命周期（9）
├── 03-gap-coverage.cjs        # 盲区覆盖（4）
├── 04-adversarial.cjs         # 对抗性测试（5）
├── 05-production-reality.cjs  # 生产真实性（19）
├── 06-passthrough-poc.cjs     # passthrough PoC（12）
├── 07-real-proxy-adapter.cjs  # 真实 proxy-adapter（25）
├── 08-extended-coverage.cjs   # 扩展覆盖（8）
├── 09-deep-coverage.cjs       # 深度覆盖（14）
├── 10-production-sequence.cjs # 生产序列 + 热切换（20）
├── 11-hotswitch-lifecycle.cjs # 热切换全生命周期（18）
├── 12-production-edge-cases.cjs # 生产边缘场景（32）
├── 13-stress-and-resilience.cjs # 压力与韧性（25）
├── 14-moxt-code-paths.cjs     # moxt 代码路径（21）
├── 15-final-coverage.cjs      # 终极覆盖（29）
├── 16-setStartCmd-template-build.cjs # setStartCmd 模板构建（29）
├── 17-websocket.cjs           # WebSocket 透明代理（25）
├── 18-real-passthrough-activate-mitm.cjs # 真实 --passthrough + /__activate-mitm（24）
└── 19-template-real-passthrough.cjs # 真实 --passthrough + setStartCmd 模板构建（24）

fixtures/
├── proxy.py                   # Python proxy 模拟器（Suite 01-05）
├── proxy-passthrough-poc.mjs  # Node.js PoC proxy（Suite 06）
├── passthrough-hotswitch.mjs  # passthrough → MITM 热切换实现（Suite 10-12）
├── production-sequence.mjs    # 生产启动序列模拟（Suite 10）
├── proxy-adapter.js           # 真实 rspack 构建 proxy-adapter（Suite 07-15, 24KB）
├── nft-rules.conf             # RFC nft 规则（含 meta skuid 豁免）
├── tcp-connect.py             # TCP 连接测试
├── attack-econnreset.mjs      # ECONNRESET 复现
├── attack-selfloop.mjs        # P0 自环复现
├── attack-pool-waves.mjs      # 连接池健康性
└── attack-concurrent.mjs      # 并发负载测试
```

## 文档

- **[RFC.md](./RFC.md)** — 完整 RFC：问题分析、方案设计、实施计划、实施注意事项（10 个踩坑记录）
- **[VERIFICATION-STATUS.md](./VERIFICATION-STATUS.md)** — 验证状态跟踪
- **[INDEPENDENT-ANALYSIS.md](./INDEPENDENT-ANALYSIS.md)** — 独立分析：RFC vs 当前架构的事实对比

## 关联

- **RFC Issue**: [paraflow-hq/moxt#4383](https://github.com/paraflow-hq/moxt/issues/4383)
- **ECONNRESET 修复 PR**: [paraflow-hq/moxt#4378](https://github.com/paraflow-hq/moxt/pull/4378)
- **P0 故障分析**: [paraflow-hq/moxt#3784](https://github.com/paraflow-hq/moxt/issues/3784)
