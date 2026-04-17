# Sandbox Transparent Proxy Architecture RFC

RFC 及验证测试：将 E2B sandbox 透明代理的 iptables 设置从运行时初始化改为镜像层预置，采用 `nft meta skuid` 防回环机制。

## 解决的问题

1. **ECONNRESET 竞态**：parent process 中途设置 iptables 导致连接池僵尸连接
2. **代理自环 P0 故障**：proxy-adapter 出站流量被 iptables 重定向回自身

## 核心原则

```
镜像层（snapshot）：网络拓扑（nft rules + proxy 直通模式 + UID 豁免）
运行时（per-instance）：加密身份（CA 生成 → MITM 激活 → Agent 启动）
```

| 原则 | 实现 | 业界参考 |
|------|------|----------|
| iptables 先于任何连接 | 镜像 snapshot 预置 nft 规则 | Istio init container；E2B 官方文档 |
| UID 豁免防回环 | `nft meta skuid "mitmproxy" accept` | Istio UID 1337；Linkerd UID 2102 |
| CA 每实例独立生成 | 运行时 `setupCa()`，不放入 snapshot | mitmproxy 官方；Firecracker 安全指南 |
| MITM 先于不可信代码 | `activateMitm()` 顺序在 `spawn(Agent)` 之前 | 纵深防御 |

**完整 RFC**: [RFC.md](./RFC.md)

## E2B 内核约束

E2B 内核 6.1.158 **禁用了** `CONFIG_NETFILTER_XT_MATCH_OWNER`（legacy iptables `-m owner`），但 nf_tables 的 `meta skuid` 可用（`CONFIG_NF_TABLES=y`）。所有规则使用 nft 实现。

## 测试

所有测试在**真实 E2B sandbox** 中执行，包含 Firecracker snapshot/restore 周期。

### 前置条件

- Node.js >= 18
- E2B API Key

### 安装

```bash
pnpm install
```

### 运行全部测试

```bash
E2B_API_KEY=<your-key> pnpm test
# 或
pnpm test <your-key>
```

### 运行单个测试套件

```bash
pnpm test:components <key>     # 组件验证
pnpm test:e2e <key>            # 端到端生命周期
pnpm test:gaps <key>           # 盲区覆盖
pnpm test:adversarial <key>    # 对抗性测试
```

### 测试套件

| 套件 | 内容 | 验证的 RFC 原则 |
|------|------|----------------|
| **01-components** | nft skuid 内核支持、proxy 启动、UID 豁免、REDIRECT、snapshot 存活 | 1, 2 |
| **02-e2e-lifecycle** | 完整生命周期：snapshot → prep → activate MITM → verify | 1, 2, 3, 4 |
| **03-gap-coverage** | Node.js fetch (undici)、HTTPS REDIRECT、P0 自环 (fetch) | 1, 2 |
| **04-adversarial** | 复现 ECONNRESET、复现 P0 自环、连接池时序、并发负载 | 1, 2 |

### 测试文件

```
tests/
├── helpers.cjs              # 共享基础设施（sandbox 创建、exec、snapshot）
├── run-all.cjs              # 顺序运行全部套件
├── 01-components.cjs        # 组件验证
├── 02-e2e-lifecycle.cjs     # 端到端生命周期
├── 03-gap-coverage.cjs      # 盲区覆盖
└── 04-adversarial.cjs       # 对抗性测试

fixtures/
├── proxy.py                 # Python proxy 模拟器（HTTP :18080 + TCP :18443）
├── nft-rules.conf           # RFC 设计的 nft 规则（含 meta skuid 豁免）
├── attack-econnreset.mjs    # ECONNRESET 复现脚本（pool build → idle → reuse）
├── attack-selfloop.mjs      # P0 自环复现脚本（mitmproxy 用户 fetch HTTPS）
├── attack-pool-waves.mjs    # 连接池健康性测试（3 波并发 + 间隔）
└── attack-concurrent.mjs    # 并发负载测试
```

## 关联

- **RFC Issue**: [paraflow-hq/moxt#4383](https://github.com/paraflow-hq/moxt/issues/4383)
- **ECONNRESET 修复 PR**: [paraflow-hq/moxt#4378](https://github.com/paraflow-hq/moxt/pull/4378)
- **P0 故障分析**: [paraflow-hq/moxt#3784](https://github.com/paraflow-hq/moxt/issues/3784)
