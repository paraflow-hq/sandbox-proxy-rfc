# 独立分析：RFC 方案 vs 当前架构

基于事实的客观对比。以下每一条结论都附有可验证的来源。

## 1. 生产事故记录

| 事故 | 日期 | 持续时间 | 根因 | 来源 |
|------|------|----------|------|------|
| ECONNRESET 竞态 | 持续存在（概率性） | 单次请求失败 | 连接池跨越 iptables 拓扑切换 | [PR #4378](https://github.com/paraflow-hq/moxt/pull/4378) |
| 代理自循环（P0） | 2026-04-10 | **70 分钟**全量 Agent 不可用 | `forwardViaWorker` 的 `fetch()` 使用 OS 分配的临时端口，不在 `--sport 20000:29999` 豁免范围内 | [#3784](https://github.com/paraflow-hq/moxt/issues/3784) |

**事实**：当前架构已有 2 起已确认的生产故障。RFC 架构尚未上线，无生产数据。

## 2. 防循环机制：端口范围 vs UID 豁免

### 当前方案：源端口范围豁免（`--sport 20000:29999`）

- 仅保护**显式绑定**到 20000-29999 端口的代码路径
- Node.js `fetch()`（undici）使用 OS 分配的临时端口（通常 32768-60999）——**不在保护范围内**
- proxy-adapter 中每新增一条出站代码路径，如果开发者忘记绑定到 bypass 端口范围，就是一个潜在的自循环入口
- P0 事故正是由此缺口导致：`forwardViaWorker` 内部调用 `fetch()` 未显式绑定端口

### RFC 方案：UID 豁免（`nft meta skuid "mitmproxy"`）

- 豁免 `mitmproxy` 用户的**所有**出站流量，不论端口、代码路径、调用方式
- 无需开发者做任何事——以 `mitmproxy` 用户运行的任何代码自动受保护
- 零维护：新增代码路径自动覆盖

### 业界做法（可验证）

| 项目 | 防循环机制 | 来源 |
|------|-----------|------|
| **Istio** | `iptables -m owner --uid-owner 1337 -j RETURN` | [istio/istio `pkg/iptables`](https://github.com/istio/istio) |
| **Linkerd** | `iptables -m owner --uid-owner 2102 -j RETURN` | [linkerd/linkerd2-proxy-init](https://github.com/linkerd/linkerd2-proxy-init) |
| **mitmproxy** | `iptables -m owner ! --uid-owner mitmproxyuser -j REDIRECT` | [mitmproxy 透明模式文档](https://docs.mitmproxy.org/stable/howto-transparent/) |
| **Squid** | `iptables -m owner --uid-owner squid -j RETURN` | [Squid 透明拦截文档](http://wiki.squid-cache.org/ConfigExamples/Intercept/LinuxRedirect) |

**事实**：没有任何主流透明代理项目使用源端口范围豁免来防循环。全部使用 UID 豁免。这不是偏好问题——端口范围豁免存在已知结构缺陷（任何使用 OS 分配端口的代码路径都不受保护）。

## 3. 规则注入时机：运行时 vs 镜像层

### 当前方案：运行时中途注入

```
parent-process 启动
  → prep 阶段：约 90 次 HTTP 请求（Datadog 日志、进度上报、git clone 等）
  → 连接池积累 keep-alive 连接（直连，不经过代理）
  → setupIptablesTransparentProxy()  ← 网络拓扑在此切换
  → 后续请求可能取出僵尸连接 → ECONNRESET
```

ECONNRESET 的发生原因：iptables **之前**建立的连接是直连的，iptables **之后**的请求必须经代理。连接池中的旧直连连接遇到服务端 RST。

### RFC 方案：镜像层预置

```
模板构建：代理 + nft 规则烘焙进 Firecracker 快照
  → 从快照创建 sandbox：代理已运行，规则从零时刻起生效
  → parent-process 启动：第一个 fetch() 就经过代理
  → 连接池中永远不存在直连连接
  → 永远不会发生拓扑切换
```

### 业界做法（可验证）

| 平台 | 规则时机 | 来源 |
|------|---------|------|
| **Istio** | init container 在应用容器**之前**运行 | [Istio 架构文档](https://istio.io/latest/docs/ops/deployment/architecture/) |
| **Linkerd** | `linkerd-init` 容器在应用启动**之前**配置 iptables | [Linkerd 架构文档](https://linkerd.io/2/reference/architecture/) |
| **AWS App Mesh** | init container 在 Envoy + 应用**之前**设置 iptables | [App Mesh 文档](https://docs.aws.amazon.com/app-mesh/latest/userguide/getting-started.html) |
| **E2B** | `setStartCmd` 在构建阶段运行，捕获进快照 | [E2B IP Tunneling 文档](https://e2b.dev/docs/sandbox/ip-tunneling) |

**事实**：所有主流 service mesh 和代理框架都在应用代码运行**之前**建立网络拦截规则。当前 Moxt 架构是已知唯一一个在应用已建立网络连接**之后**才中途设置透明代理规则的实现。

## 4. 运行时动态步骤

### 当前架构：每个 Sandbox 的运行时步骤

1. 启动 proxy-adapter 进程
2. 执行 iptables 命令设置 REDIRECT 规则
3. 确保 proxy-adapter 中每条出站代码路径绑定到 bypass 端口范围
4. 维护 bypass host 列表与 iptables 规则的一致性

步骤 1-2 发生在 parent-process 已建立网络连接**之后**。步骤 3 依赖开发者手动遵守。步骤 4 曾失败（P0 事故）。

### RFC 架构：每个 Sandbox 的运行时步骤

1. 从快照创建 sandbox（代理 + nft 规则已就位——原子操作，全有或全无）
2. `POST /__activate-mitm` 传入本实例的 CA

**事实**：RFC 将运行时动态操作从 4 步减少到 2 步。Firecracker 快照恢复是原子的——代理和规则要么同时存在，要么同时不存在。不存在"代理在运行但规则未设置"的中间状态。

## 5. 故障模式对比

### 当前架构的故障模式

| 故障 | 触发条件 | 概率 | 严重度 | 可检测性 |
|------|---------|------|--------|---------|
| ECONNRESET | iptables 切换期间 keep-alive 超时 | 中（概率性，依赖时序） | 中（单次请求） | 难（间歇性，依赖时序） |
| 自循环 | proxy 任何出站 fetch() 使用 OS 分配端口 | 低但**已发生** | **P0**（无限循环，全量不可用） | 难（表现为正常高 CPU，需排查才能发现） |
| iptables 设置失败 | 运行时命令执行错误 | 低 | 高（无代理保护） | 中 |
| 端口范围维护遗漏 | 开发者忘记绑定新代码路径 | 中（人为错误） | **P0**（潜在自循环） | **在生产事故发生前无法检测** |

### RFC 架构的故障模式

| 故障 | 触发条件 | 概率 | 严重度 | 可检测性 |
|------|---------|------|--------|---------|
| 代理进程崩溃 | Bug、OOM | 低 | 高（所有重定向流量失败） | 易（health check 报错；连接被拒——非静默） |
| 模板构建失败 | template.py 构建错误 | 低 | 中（阻止新 sandbox 创建；已有 sandbox 不受影响） | 易（CI 构建失败） |
| `flush ruleset` 冲突 | E2B 未来添加自己的 nft 规则 | 当前为零（E2B 无预置 nft 规则——已在测试中验证） | 高（如果触发） | 中 |
| `/__activate-mitm` 失败 | 热切换端点 bug | 低 | 高（MITM 未为 Agent 激活） | 易（HTTP 响应码） |

### 关键区别

**当前架构最严重的故障是静默和概率性的**——ECONNRESET 取决于时序，自循环取决于走哪条代码路径，端口范围缺口在被利用前不可见。

**RFC 架构的故障是显式和确定性的**——代理崩溃立即导致连接被拒（非静默丢数据），模板构建失败阻止 CI（非生产），health check 端点支持显式监控。

**事实**：静默故障严格难于检测、诊断和预防。RFC 将静默故障模式替换为显式故障模式。

## 6. 维护负担

### 当前架构更容易维护的方面

- **无需重建模板**：代理代码变更无需重建 E2B 模板，proxy-adapter 迭代更快。
- **无需管理系统用户**：不需要维护 `mitmproxy` 系统用户或理解 nft 语法。
- **心智模型更简单**：只有一种代理模式（始终 MITM），没有 passthrough/MITM 双模式或热切换端点。

### RFC 架构更容易维护的方面

- **无需隐式开发者纪律**：UID 豁免不需要开发者做任何事。端口范围豁免要求每个接触 proxy-adapter 出站代码的开发者记住绑定到 20000-29999——一个不可见的约定，违反时产生 P0 故障。
- **无需考虑 iptables 时序**：不需要推理连接池状态与 iptables 设置时机的关系。
- **更简单的诊断**：`nft list ruleset` 和 `nft list counters` 直接显示活跃规则和每条规则匹配的流量计数。所有测试套件中都演示了基于 counter 的调试。
- **移除运行时 iptables 代码**：删除 `setupIptablesTransparentProxy()`、`cleanupIptablesTransparentProxy()`、`ensureIptablesTransparentProxy()`、所有 `execSync`/`execAsync` iptables 命令。

### RFC 架构更难维护的方面

- **代理变更需重建模板**：proxy-adapter.js 的任何变更都需要重建 E2B 模板（构建→测试→部署周期）。RFC 认为代理变更不频繁——这在历史上是准确的，但增加了摩擦。
- **双模式代理复杂度**：passthrough → MITM 热切换给代理增加了一个状态转换，需要测试和推理更多代码路径。
- **需要 nft 知识**：运维团队需要理解 nftables 语法来进行调试，这比 iptables 知识更少见。

### 本质区别

当前架构的维护负担在**运行时**——故障表现为生产事故（P0 自循环、ECONNRESET）。RFC 架构的维护负担在**构建时**——故障表现为 CI 失败或模板构建错误。

**事实**：构建时故障在代码到达生产环境之前被捕获。运行时故障**由**生产环境捕获。这是两种方案可维护性的根本区别。

## 7. E2B 内核约束

**事实**（在 E2B sandbox 中验证，记录于 RFC 测试）：

```
# E2B 内核 6.1.158 的 /proc/config.gz
# CONFIG_NETFILTER_XT_MATCH_OWNER is not set    ← iptables -m owner 不可用
CONFIG_NF_TABLES=y                               ← nft meta skuid 可用
```

这意味着：
- Istio/Linkerd 使用的 legacy `iptables -m owner --uid-owner` 在 E2B 上**不可用**
- `nft meta skuid` 通过 nf_tables 实现相同的 UID 豁免功能
- RFC 选择 nft 而非 iptables 是**技术必要性**，不是偏好

行业背景：nftables 是 Linux 内核中 iptables 的指定继任者（Linux 3.13 合入，RHEL 8+/Debian 10+ 默认），不是实验性技术。

## 8. 测试证据

RFC 包含 253 项自动化测试（15 套件），运行在**真实 E2B sandbox** 中（非 mock），包括使用真实 proxy-adapter.js 的应用层测试和 passthrough → MITM 热切换验证。

### 攻击复现测试（对抗性套件）

| 攻击 | 测试方法 | 结果 | 证明了什么 |
|------|---------|------|-----------|
| ECONNRESET 复现 | 建立连接池（5 次请求）→ 等待 6 秒（模拟 keep-alive 超时）→ 再发 5 次请求 | `{"phase1":5,"phase2":5,"errors":[]}` — 零错误 | 在 RFC 架构下，空闲期 + 连接池复用不会导致 ECONNRESET，因为所有连接从一开始就经过代理 |
| P0 自循环复现 | 以 `mitmproxy` 用户运行 → `fetch("https://198.18.0.1/...")` | `AbortError`（超时，直连不可路由 IP）——**不是**重定向循环 | UID 豁免阻止内核将代理自身的出站流量重定向回自己 |

### 真实网络测试（生产真实性套件）

| 测试项 | 证据 |
|--------|------|
| root HTTP 被拦截 | `curl httpbin.org/get` → 来自 proxy 的响应（`OK path=/get`） |
| mitmproxy HTTPS 绕过代理 | `curl https://httpbin.org/status/200` → 来自真实 httpbin.org 的 HTTP 200 |
| nft counter 准确 | `skuid packets: 5`（被豁免）vs `redirect packets: N`（被重定向） |
| 快照存活 | 规则、counter、代理进程、UID 全部在 Firecracker pause/resume 后存活 |
| 双次快照（sandbox reuse） | 以上所有项在第 2 次 snapshot/restore 后验证通过 |

**事实**：这些测试证明该架构在真实 E2B 环境中可工作，而非仅在理论上。

## 9. 事实总结

| 维度 | 当前架构 | RFC 架构 |
|------|---------|---------|
| 生产事故 | 2 起已确认（ECONNRESET + P0 自循环） | 0（未部署） |
| 防循环机制 | 端口范围（部分覆盖，依赖开发者纪律） | UID（完全覆盖，零维护） |
| 防循环的业界先例 | 未找到 | Istio、Linkerd、mitmproxy、Squid |
| 规则时机 | 运行时中途（连接已建立后） | 镜像层（任何连接之前） |
| 规则时机的业界先例 | 未找到 | Istio、Linkerd、AWS App Mesh、E2B 官方文档 |
| 运行时动态步骤 | 4 步 | 2 步 |
| 最严重故障模式 | 静默（概率性 ECONNRESET、不可见的自循环风险） | 显式（连接被拒、CI 失败） |
| 维护负担位置 | 运行时（生产事故） | 构建时（CI 失败） |
| 代理迭代速度 | 更快（无需重建模板） | 更慢（需重建模板） |
| 系统复杂度 | 更低（单一代理模式） | 更高（双模式 + 热切换） |
| 自动化测试覆盖 | 未记录 | 253 项测试（15 套件），在真实 E2B sandbox 中运行 |

## 10. 结论

严格基于可验证的事实：

1. 当前架构存在两个结构性缺陷（运行时规则注入、端口范围防循环），两者都已产生生产事故。
2. RFC 架构使用业界标准机制（UID 豁免、规则先于应用）消除了这两个缺陷——Istio、Linkerd、mitmproxy、Squid 均采用相同做法。
3. RFC 以更慢的代理迭代速度（需重建模板）换取了两个已知生产故障模式的消除。
4. RFC 的故障模式是确定性的、可在构建时检测到的；当前架构的故障模式是概率性的、仅能在运行时检测到。

这个取舍是否值得是判断问题。以上事实为该判断提供依据。
