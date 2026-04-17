# 验证状态

## 总计：15 套件 253 项，全部通过 ✅

所有测试在真实 E2B sandbox 中执行，非 mock。

## 基础设施层：5 套件 49 项 ✅

| 套件 | 测试数 | 结果 |
|------|--------|------|
| 01-components | 12/12 | nft skuid 内核支持、proxy 双端口、UID 豁免（HTTP+HTTPS）、snapshot 存活 |
| 02-e2e-lifecycle | 9/9 | 完整生命周期：snapshot → prep → MITM 激活 → nft counter |
| 03-gap-coverage | 4/4 | Node.js fetch、HTTPS REDIRECT、P0 自环 fetch |
| 04-adversarial | 5/5 | ECONNRESET 复现失败、P0 自环复现失败、连接池时序、并发 |
| 05-production-reality | 19/19 | 真实 httpbin.org、DNS、E2B SDK、proxy 崩溃恢复、UDP |

## Passthrough PoC：1 套件 12 项 ✅

| 套件 | 测试数 | 结果 |
|------|--------|------|
| 06-passthrough-poc | 12/12 | Node.js PoC proxy、HTTP 中继、TLS 隧道、热切换、snapshot 存活 |

## 真实 proxy-adapter.js：3 套件 47 项 ✅

使用 rspack 构建的真实 proxy-adapter.js（24KB bundle）。

| 套件 | 测试数 | 结果 |
|------|--------|------|
| 07-real-proxy-adapter | 25/25 | forwardViaWorker、DynamicCertManager、tunnelBypass、审计日志、snapshot、崩溃恢复 |
| 08-extended-coverage | 8/8 | Root HTTPS bypass 真实证书、ECONNRESET 对抗（10+6s+10=0）、50 并发 |
| 09-deep-coverage | 14/14 | /__health 响应、/__update-config 生效、forwardDirect、审计 JSONL 内容、1MB payload、PID 文件 |

## 生产启动序列 + 热切换：3 套件 70 项 ✅

包含自写的 passthrough → MITM 热切换实现（`passthrough-hotswitch.mjs`）。

| 套件 | 测试数 | 结果 |
|------|--------|------|
| 10-production-sequence | 20/20 | trustMitmCaCertForParentProcess monkey-patch、生产全序列（prep→MITM→agent）、HTTPS forwardDirect |
| 11-hotswitch-lifecycle | 18/18 | passthrough ECONNRESET 证明、全生命周期+snapshot、幂等激活、并发模式切换 |
| 12-production-edge-cases | 32/32 | sandbox reuse、崩溃恢复（MITM→passthrough→重新激活）、跨模式双snapshot、keep-alive跨切换 |

## 压力测试 + moxt 代码路径：2 套件 46 项 ✅

| 套件 | 测试数 | 结果 |
|------|--------|------|
| 13-stress-and-resilience | 25/25 | nft 先于 proxy（image-layer 验证）、100 请求 burst、错误韧性、二进制 payload、20 host cert gen |
| 14-moxt-code-paths | 21/21 | bypass hosts env 解析、feature switch 禁用、缺失 env vars、TLS monkey-patch 深度验证 |

## 终极覆盖：1 套件 29 项 ✅

基于穷举审计，覆盖所有剩余可测试的故障场景。

| 套件 | 测试数 | 结果 |
|------|--------|------|
| 15-final-coverage | 29/29 | 磁盘满 cert gen、缺失 update-ca-certificates、invalid JSON、截断 body、客户端中断、坏 TLS 数据、同 host 并发 cert、缺失 Host header |

## 仍待验证（需新代码实施后）

| 待验证项 | 阻塞原因 |
|----------|----------|
| proxy-adapter `--passthrough` 模式 | 代码不存在（需实现） |
| `/__activate-mitm` 在真实 proxy-adapter 中 | 代码不存在（需实现，热切换已用独立实现验证） |
| `setStartCmd` template build | 需修改 `paraflow-hq/sandbox` template.py |

## 测试中发现的实施注意事项

所有发现已记录到 [RFC.md](./RFC.md) 的"实施注意事项"章节：

| # | 发现 | 来源 | 影响 |
|---|------|------|------|
| 1 | `clientSocket.pause()` 必须在热切换 `unshift+emit` 前调用 | Suite 10 B5 | 不加则 HTTPS 全部失败 |
| 2 | MITM server 必须用 `https.createServer`（不能 `tls.createServer`） | Suite 10 B5 | 后者对 emit('connection') 注入的 socket 处理不同 |
| 3 | E2B socat 拦截 `127.0.0.1` 端口的 TCP 连接 | Suite 07 T7 | 仅影响测试环境，不影响生产 |
| 4 | template.py 需安装 `nftables` + `ca-certificates` 包 | Suite 07-10 | 当前只装了 iptables |
| 5 | `flush ruleset` 会清除所有 nft 规则 | Suite 05 R1a | 建议改为 `flush table ip proxy` |
| 6 | proxy-adapter.js bundle 必须从最新源码构建 | Suite 07 | 旧 bundle 缺少端点 |
| 7 | nft 规则先于 proxy 加载时 proxy 正常工作 | Suite 13 A | image-layer 前提已验证 |
| 8 | Bypass hosts 没有独立 env var 配置机制 | Suite 14 A | 只能通过 URL env vars 间接添加 |
| 9 | 磁盘满时 cert gen 快速失败但不自动恢复 | Suite 15 A | 需重启 proxy |
| 10 | `update-ca-certificates` 失败时 curl/wget 将无法验证 MITM 证书 | Suite 15 B | NODE_EXTRA_CA_CERTS 可用作备选 |
