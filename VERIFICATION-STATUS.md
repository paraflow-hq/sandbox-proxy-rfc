# 验证状态

## 基础设施层：49/49 自动化测试通过 ✅

| 套件 | 测试数 | 结果 |
|------|--------|------|
| 01-components | 12/12 | nft skuid 内核支持、proxy 双端口、UID 豁免（HTTP+HTTPS）、snapshot 存活 |
| 02-e2e-lifecycle | 9/9 | 完整生命周期：snapshot → prep → MITM 激活 → nft counter |
| 03-gap-coverage | 4/4 | Node.js fetch、HTTPS REDIRECT、P0 自环 fetch |
| 04-adversarial | 5/5 | ECONNRESET 复现失败、P0 自环复现失败、连接池时序、并发 |
| 05-production-reality | 19/19 | 真实 httpbin.org、DNS、E2B SDK、proxy 崩溃恢复、UDP |

## 应用层：真实 proxy-adapter.js 验证 ✅

从 PR #4378 分支构建真实 proxy-adapter.js（rspack，21KB），上传到 E2B sandbox，以 mitmproxy 用户启动，加载 nft 规则，测试真实外部流量和 snapshot/restore。

### 真实 proxy-adapter 基础功能

| 测试项 | 结果 | 证据 |
|--------|------|------|
| rspack 构建成功 | ✅ | 21KB bundle，0 errors |
| 以 mitmproxy 用户启动 | ✅ | `pid=785, node /opt/proxy-adapter.js` |
| CA 自动生成（openssl） | ✅ | `CA cert ready at /tmp/moxt-proxy/ca.crt` |
| CA 安装到系统信任库（sudo cp + update-ca-certificates） | ✅ | `/usr/local/share/ca-certificates/moxt-proxy-ca.crt` |
| Bypass hosts 正确解析 | ✅ | `api.anthropic.com, litellm.moxt.ai, web-api.moxt.ai, sandbox-proxy.moxt.ai, cdn.moxt.ai` |
| 双端口监听 | ✅ | `:18080`(HTTP) + `:18443`(HTTPS transparent) |
| Health check | ✅ | `{"status":"ok"}` |

### 真实 proxy-adapter + snapshot/restore

| 测试项 | 结果 | 证据 |
|--------|------|------|
| proxy-adapter 在 snapshot/restore 后存活 | ✅ | `{"status":"ok"}` |
| HTTP 转发在 restore 后工作 | ✅ | `httpbin.org/ip` 返回真实 JSON |

### 真实 TLS SNI 路由（nft redirect :443 → proxy :18443）

| 测试项 | 结果 | 证据 |
|--------|------|------|
| Bypass host（api.anthropic.com）→ SNI 透传 | ✅ | Python ssl 收到真实证书 `REAL_CERT:api.anthropic.com` |
| 非 bypass host（example.com）→ 经 proxy 处理 | ✅ | 连接成功，请求经 CF Worker 转发 |

### MITM CA 信任 + Node.js HTTPS

| 测试项 | 结果 | 证据 |
|--------|------|------|
| `NODE_EXTRA_CA_CERTS` 设置后 Node.js fetch HTTPS 成功 | ✅ | `HTTPS_OK:{"origin":"136.109.228.165"}` — httpbin.org 真实 JSON 通过 MITM proxy 返回 |

### 双次 snapshot（sandbox reuse 模拟）

| 测试项 | 结果 | 证据 |
|--------|------|------|
| proxy-adapter 在第 2 次 snapshot 后存活 | ✅ | `{"status":"ok"}` |
| HTTP 转发在第 2 次 restore 后工作 | ✅ | httpbin.org 返回真实 JSON |
| nft skuid 规则在第 2 次 restore 后存活 | ✅ | `skuid rules: present` |
| UID 豁免在第 2 次 restore 后工作 | ✅ | `curl https://httpbin.org/status/200` → HTTP 200 |

### 真实流量转发链路

| 测试项 | 结果 | 证据 |
|--------|------|------|
| root HTTP → proxy → CF Worker → httpbin.org | ✅ | 返回真实 httpbin JSON，origin 含 CF Worker IP |
| mitmproxy HTTPS → UID 豁免 → 直连 httpbin.org | ✅ | HTTP 200 |
| Node.js fetch HTTPS → MITM proxy → CF Worker → httpbin.org | ✅ | CA trusted，返回真实 JSON |
| proxy 出站 fetch(workerUrl) → UID 豁免 → CF Worker | ✅ | 请求成功转发（未回环） |

## 仍待验证（需新代码实施后）

| 待验证项 | 阻塞原因 |
|----------|----------|
| proxy-adapter `--passthrough` 模式 | 代码不存在（需实现） |
| `/__activate-mitm` 热切换 | 代码不存在（需实现） |
| `setStartCmd` template build | 需修改 `paraflow-hq/sandbox` template.py |

这 3 项都是**新代码**，当前不存在。基础设施层和现有应用层已验证完毕。
