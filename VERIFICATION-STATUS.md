# 验证状态

## 总计：19 套件 355 项，全部通过 ✅

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

## setStartCmd 模板构建：1 套件 29 项 ✅

使用 E2B Template SDK `setStartCmd` API 构建真实模板，验证生产 build 路径（Suite 01-15 全部使用运行时 setup）。

| 套件 | 测试数 | 结果 |
|------|--------|------|
| 16-setStartCmd-template-build | 29/29 | Template SDK 构建成功、proxy 以 mitmproxy 用户从 snapshot 存活、nft rules/counters 存在、HTTP/HTTPS 拦截、UID 豁免、snapshot/restore、多 sandbox 隔离、prep 20 请求零 ECONNRESET、activate-mitm 模式切换、post-MITM snapshot 存活 |

### Suite 16 关键证据

| 验证目标 | 证据 | 测试 |
|---------|------|------|
| `setStartCmd` build 成功 | templateId 返回，proxy + nft 在 build 日志中启动 | A1 |
| Proxy 从 snapshot 存活 | `ps aux` 显示 python3 进程 ALIVE | B1 |
| Proxy 以 mitmproxy 用户运行 | `/proc/<pid>/status` Uid=999 → USER=mitmproxy | B3 |
| nft 规则从创建即生效 | `nft list ruleset` 包含 skuid + redirect 80 + redirect 443 | B4 |
| HTTP 拦截 | root curl → `OK path=/get mode=passthrough` | B6 |
| UID 豁免 | mitmproxy curl → httpbin 真实 JSON（不经 proxy） | B7 |
| HTTPS 拦截 | root TCP → `TLS_PASSTHROUGH_REACHED` | B8 |
| Snapshot/restore | proxy + nft + UID 豁免在 pause/resume 后全部存活 | C1-C5 |
| 多 sandbox 隔离 | 同 template 两 sandbox，请求不串 | D1-D5 |
| Prep 零 ECONNRESET | 20 sequential requests，零错误 | E1-E2 |
| activate-mitm | `/__activate-mitm` → `"activated": true` → mode=mitm | E3-E4 |
| Post-MITM snapshot | proxy + nft 在 MITM 激活后 snapshot/restore 存活 | E6-E8 |

## WebSocket 协议覆盖：1 套件 25 项 ✅

透明代理拦截 TCP 80/443 上的所有流量，WebSocket（HTTP Upgrade）是必须覆盖的协议。

| 套件 | 测试数 | 结果 |
|------|--------|------|
| 17-websocket | 25/25 | ws:// HTTP Upgrade 优雅处理（proxy 不 crash）、wss:// passthrough TCP 隧道全双工 echo、wss:// MITM TLS 终止、并发 WebSocket 韧性、UID 豁免 WebSocket 绕过 |

### Suite 17 关键发现

| 协议路径 | 行为 | 影响 |
|---------|------|------|
| ws:// → proxy HTTP handler | `forwardViaWorker` 用 `http.request + pipe`，**不传播 Upgrade** — 请求作为普通 HTTP GET 转发 | WebSocket over HTTP 不工作，但 proxy 不 crash |
| wss:// → passthrough TLS router | raw TCP 隧道，所有字节透传 — **WebSocket 完整工作** | wss:// 在 passthrough 模式下无损 |
| wss:// → MITM TLS router | proxy 终止 TLS 后走 HTTP 层 — 同 ws:// 限制 | MITM 模式下 wss:// WebSocket 不工作 |

## 真实 proxy-adapter --passthrough + /__activate-mitm：1 套件 24 项 ✅

真实 proxy-adapter.js bundle（25KB, rspack 构建）实现 `--passthrough` flag 和 `/__activate-mitm` 端点。

| 套件 | 测试数 | 结果 |
|------|--------|------|
| 18-real-passthrough-activate-mitm | 24/24 | passthrough 启动无 CA、health=passthrough、HTTP 直转、HTTPS 真实上游证书、10 请求零 ECONNRESET、UID 豁免、CA 生成 + activate-mitm、HTTPS 获得 Moxt CA、snapshot/restore 存活、幂等激活 |

### Suite 18 关键证据

| 验证目标 | 证据 | 测试 |
|---------|------|------|
| `--passthrough` 启动 | health 返回 `"mode":"passthrough"`，无 CA 文件 | A1-A3 |
| Passthrough HTTPS | 上游真实证书 `issuer=C=US, O=Amazon` | B2 |
| `/__activate-mitm` | 返回 `{"activated":true,"mode":"mitm"}` | C3 |
| MITM 生效 | HTTPS cert `issuer=CN=Moxt Sandbox Proxy CA` | D1-D2 |
| Snapshot 存活 | proxy + nft + MITM 模式在 restore 后全部存活 | E1-E5 |
| 幂等激活 | 双次 activate 不 crash，MITM 继续工作 | F1-F3 |

## 生产精确路径：真实 proxy-adapter --passthrough + setStartCmd：1 套件 24 项 ✅

Suite 16 用 Python proxy + setStartCmd。Suite 18 用真实 proxy-adapter --passthrough + 运行时 setup。Suite 19 测的是两者的交叉——生产部署的精确路径。

| 套件 | 测试数 | 结果 |
|------|--------|------|
| 19-template-real-passthrough | 24/24 | Template SDK 构建真实 proxy-adapter.js --passthrough + nft、passthrough 从 birth、10 请求零 ECONNRESET、真实上游证书、activate-mitm → MITM 证书、二次 snapshot 存活、多 sandbox 隔离 + 独立激活 |

## 仍待验证（无）

所有待验证项已全部完成。包括生产部署的精确路径。

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
