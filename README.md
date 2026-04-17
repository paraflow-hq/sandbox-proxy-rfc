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

### 已完成：基础设施层（5 套件 49 项，全部通过）

所有测试在**真实 E2B sandbox** 中执行，包含 Firecracker snapshot/restore 周期。

| 套件 | 测试数 | 视角 | 结果 |
|------|--------|------|------|
| **01-components** | 12/12 ✅ | 基础组件 | nft skuid 内核支持、mitmproxy 用户 nologin、proxy 双端口监听、HTTP/HTTPS REDIRECT、UID 豁免（HTTP+HTTPS）、snapshot 存活（规则+进程+豁免） |
| **02-e2e-lifecycle** | 9/9 ✅ | 生产生命周期 | snapshot → prep 请求被拦截 → proxy outbound 不回环 → MITM 激活 → post-MITM 请求工作 → nft counter 确认流量分离 |
| **03-gap-coverage** | 4/4 ✅ | 实现层盲区 | Node.js fetch (undici) 被拦截、HTTPS :443 REDIRECT、mitmproxy 用户 fetch HTTPS 不自环 |
| **04-adversarial** | 5/5 ✅ | 攻防对抗 | ECONNRESET 复现失败（5 req → 6s idle → 5 req 全部成功）、P0 自环复现失败、3×10 并发 + 4s 间隔全健康、10 并发全成功 |
| **05-production-reality** | 19/19 ✅ | 真实网络 | `flush ruleset` 不破坏 DNS/E2B SDK、真实 httpbin.org HTTP 被拦截、mitmproxy 用户直连真实 HTTPS（HTTP 200）、端口 8443 REDIRECT、UID 跨 snapshot 不变（999→999）、proxy 崩溃检测+重启恢复、UDP(DNS) 不受影响 |

**关键证据：**
- ECONNRESET 复现：`{"phase1":5,"phase2":5,"errors":[]}` — 6 秒 idle 后池复用零错误
- P0 自环复现：`AbortError, AbortError, AbortError` — 全部直连超时，未回环
- 真实网络：root `curl httpbin.org/get` → `OK path=/get`（被拦截）；mitmproxy `curl https://httpbin.org/status/200` → `200`（直连真实服务器）
- nft counter：`skuid packets: 5`（豁免）vs `redirect packets: N`（重定向）

### 未完成：应用层（需实施后验证）

| 待验证项 | 原因 | 对应实施步骤 |
|----------|------|-------------|
| **`setStartCmd` build 路径** | 需修改 `paraflow-hq/sandbox` template.py 并触发 E2B template build（CI 流程） | 实施步骤 1 |
| **真实 proxy-adapter.js 以 mitmproxy 用户运行** | 需构建 proxy-adapter bundle（依赖 server-ts 类型生成） | 实施步骤 2 |
| **`/__activate-mitm` 热切换** | 新端点代码尚不存在，需实现后验证 | 实施步骤 2 |
| **CA 生成 + TLS monkey-patch** | `setupCa()` + `trustMitmCaCertForParentProcess()` 需在 nft 环境下验证 | 实施步骤 3 |
| **完整请求转发链路** | client → nft → proxy → forwardViaWorker → UID 豁免 → CF Worker → 目标 | 实施步骤 4 |
| **Sandbox reuse 路径** | 第二次 pipeline 检测已有 proxy + 更新 config | 实施步骤 4 |

**每个未验证项都有明确的实施步骤对应，完成实施后即可验证。**

### 应用层验证计划

以下测试需要在对应代码实施完成后执行：

#### 步骤 1 完成后（template.py setStartCmd）

```
TEST-APP-1: 从新模板创建 sandbox，验证：
  - proxy 进程在 sandbox 创建时已运行（无需 parent-process 启动）
  - nft 规则已生效（无需运行时设置）
  - `curl http://external-host/` 被 REDIRECT 到 proxy
  - sandbox 创建到 proxy 可用的延迟 < 100ms（snapshot 恢复，非冷启动）
```

#### 步骤 2 完成后（proxy-adapter 直通模式 + activate-mitm）

```
TEST-APP-2: 真实 proxy-adapter.js 以 mitmproxy 用户运行：
  - 以 `sudo -u mitmproxy node proxy-adapter.js --passthrough` 启动
  - health check 响应
  - HTTP 直连转发（forwardDirect 逻辑）正常
  - HTTPS TCP 透传（tunnelBypass 逻辑）正常
  - proxy 的 forwardViaWorker fetch() 不被 nft REDIRECT（UID 豁免）

TEST-APP-3: /__activate-mitm 热切换：
  - POST /__activate-mitm { caCertPath, caKeyPath, sandboxToken, pipelineId, bypassHosts }
  - 切换后 TLS router 从全透传变为 bypass+MITM 分流
  - 已建立的透传连接不中断
  - 新连接走 MITM 路径
  - bypass hosts 的连接仍然透传
```

#### 步骤 3 完成后（parent-process 改动）

```
TEST-APP-4: CA 生成在 nft 环境下工作：
  - mitmproxy 用户可执行 openssl 生成 CA
  - mitmproxy 用户的 sudoers 允许 cp + update-ca-certificates
  - trustMitmCaCertForParentProcess() 的 TLS monkey-patch 生效
  - parent-process 的 prep 阶段请求全部经代理（无直连连接）

TEST-APP-5: parent-process activateMitm() 调用：
  - prep 完成后调用 POST /__activate-mitm
  - Agent spawn 在 activateMitm 之后（顺序保证）
  - Agent 的 HTTPS 请求被 MITM 拦截
```

#### 步骤 4 完成后（dev 环境端到端）

```
TEST-APP-6: 完整 pipeline run：
  - 从新模板创建 sandbox
  - parent-process prep 阶段：Datadog 日志、git clone、文件下载全部经代理
  - prep 期间零 ECONNRESET
  - MITM 激活后 Agent 运行正常
  - Agent 的 LLM 调用（经 bypass）正常
  - Agent 的外部 HTTP 请求被 MITM 拦截审计

TEST-APP-7: Sandbox reuse：
  - 第二次 pipeline 检测到已有 proxy
  - updateProxyConfig 刷新 token
  - 无需重新设置 nft 规则
  - Agent 运行正常

TEST-APP-8: 回归验证 — P0 场景：
  - 故意从 bypassHosts 中移除 HTTP_PROXY_WORKER_URL
  - proxy 的 forwardViaWorker fetch(workerUrl:443) 不回环（UID 豁免）
  - 请求可能失败（无 bypass 走 MITM）但不会无限循环
```

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
pnpm test:components <key>     # 01: 组件验证
pnpm test:e2e <key>            # 02: 端到端生命周期
pnpm test:gaps <key>           # 03: 盲区覆盖
pnpm test:adversarial <key>    # 04: 对抗性测试
pnpm test:reality <key>        # 05: 生产真实性
```

## 文件结构

```
tests/
├── helpers.cjs              # 共享基础设施（sandbox 创建、exec、snapshot、tcp-connect）
├── run-all.cjs              # 顺序运行全部套件
├── 01-components.cjs        # 组件验证（12 tests）
├── 02-e2e-lifecycle.cjs     # 端到端生命周期（9 tests）
├── 03-gap-coverage.cjs      # 盲区覆盖（4 tests）
├── 04-adversarial.cjs       # 对抗性测试（5 tests）
└── 05-production-reality.cjs # 生产真实性（19 tests）

fixtures/
├── proxy.py                 # Python proxy 模拟器（HTTP :18080 + TCP :18443）
├── nft-rules.conf           # RFC nft 规则（含 meta skuid 豁免）
├── tcp-connect.py           # TCP 连接测试（替代 nc）
├── attack-econnreset.mjs    # ECONNRESET 复现（pool build → idle → reuse）
├── attack-selfloop.mjs      # P0 自环复现（mitmproxy 用户 fetch HTTPS）
├── attack-pool-waves.mjs    # 连接池健康性（3 波并发 + 间隔）
└── attack-concurrent.mjs    # 并发负载测试
```

## 文档

- **[RFC.md](./RFC.md)** — 完整 RFC：问题分析、方案设计、实施计划
- **[VERIFICATION-STATUS.md](./VERIFICATION-STATUS.md)** — 验证状态跟踪
- **[INDEPENDENT-ANALYSIS.md](./INDEPENDENT-ANALYSIS.md)** — 独立分析：RFC vs 当前架构的事实对比（防循环机制、规则时机、故障模式、业界先例）

## 关联

- **RFC Issue**: [paraflow-hq/moxt#4383](https://github.com/paraflow-hq/moxt/issues/4383)
- **ECONNRESET 修复 PR**: [paraflow-hq/moxt#4378](https://github.com/paraflow-hq/moxt/pull/4378)
- **P0 故障分析**: [paraflow-hq/moxt#3784](https://github.com/paraflow-hq/moxt/issues/3784)
