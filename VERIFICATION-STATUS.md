# 验证状态

## 基础设施层：49/49 通过 ✅

| 套件 | 测试数 | 结果 |
|------|--------|------|
| 01-components | 12/12 | nft skuid 内核支持、proxy 双端口、UID 豁免（HTTP+HTTPS）、snapshot 存活 |
| 02-e2e-lifecycle | 9/9 | 完整生命周期：snapshot → prep → MITM 激活 → nft counter |
| 03-gap-coverage | 4/4 | Node.js fetch、HTTPS REDIRECT、P0 自环 fetch |
| 04-adversarial | 5/5 | ECONNRESET 复现失败、P0 自环复现失败、连接池时序、并发 |
| 05-production-reality | 19/19 | 真实 httpbin.org、DNS、E2B SDK、proxy 崩溃恢复、UDP |

## 应用层验证（手动测试，2026-04-17）

### 真实 proxy-adapter.js 以 mitmproxy 用户运行

**方法：** 从 PR #4378 分支（删除了 feature switch）构建真实 proxy-adapter.js（rspack，21KB），上传到 E2B sandbox，以 mitmproxy 用户启动，加载 nft 规则，测试真实外部流量。

**结果：**

| 测试项 | 结果 | 证据 |
|--------|------|------|
| rspack 构建成功 | ✅ | 21KB bundle，0 errors |
| 以 mitmproxy 用户启动 | ✅ | `pid=785, Sl, node /opt/proxy-adapter.js` |
| CA 自动生成 | ✅ | `CA cert ready at /tmp/moxt-proxy/ca.crt` |
| CA 安装到系统信任库 | ✅ | `/usr/local/share/ca-certificates/moxt-proxy-ca.crt` |
| Bypass hosts 正确解析 | ✅ | `api.anthropic.com, litellm.moxt.ai, web-api.moxt.ai, sandbox-proxy.moxt.ai, cdn.moxt.ai` |
| 双端口监听 | ✅ | `:18080` (HTTP) + `:18443` (HTTPS transparent) |
| Health check | ✅ | `{"status":"ok"}` |
| **真实 HTTP 转发（httpbin.org）** | ✅ | root `curl httpbin.org/get` → 返回**真实 httpbin JSON**（proxy 通过 CF Worker 转发） |
| **mitmproxy 用户 HTTPS 绕过（httpbin.org）** | ✅ | `curl https://httpbin.org/status/200` → HTTP 200（UID 豁免直连） |
| proxy 出站 fetch 不回环 | ✅ | `forwardViaWorker` 的 `fetch(sandbox-proxy.moxt.ai)` 成功到达 CF Worker（UID 豁免） |

### mitmproxy 用户 CA 证书操作

**方法：** 在 E2B sandbox 中以 mitmproxy 用户执行 CA 生成和安装全流程。

**结果：**

| 测试项 | 结果 | 证据 |
|--------|------|------|
| openssl 可用 | ✅ | `OpenSSL 3.5.5 27 Jan 2026` |
| 生成 CA 密钥对 | ✅ | `ca.key`(1700B, owner-only) + `ca.crt`(1107B) 创建成功 |
| `sudo cp` 到系统信任库 | ✅ | cp 到 `/usr/local/share/ca-certificates/` 成功 |
| `sudo update-ca-certificates` | ✅ | `Running hooks... done.` |
| 文件权限正确 | ✅ | `ca.key` 权限 `rw-------`（只有 mitmproxy 可读） |

**结论：** template.py 中配置的 sudoers 规则（`cp` + `update-ca-certificates`）工作正常。mitmproxy 用户可以完成 CA 生成和安装全流程。

## 仍待验证（需新代码实施后）

| 待验证项 | 阻塞原因 |
|----------|----------|
| proxy-adapter `--passthrough` 模式 | 代码不存在（需实现） |
| `/__activate-mitm` 热切换 | 代码不存在（需实现） |
| `setStartCmd` template build | 需修改 `paraflow-hq/sandbox` template.py |
| sandbox reuse | 需完整 pipeline 环境 |

注：完整转发链路已通过真实 proxy-adapter + nft + httpbin.org 验证。
