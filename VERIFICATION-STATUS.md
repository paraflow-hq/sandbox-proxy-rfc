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

**方法：** 构建真实 proxy-adapter.js（rspack），上传到 E2B sandbox，以 mitmproxy 用户启动。

**结果：**

| 测试项 | 结果 | 证据 |
|--------|------|------|
| proxy-adapter.js 构建成功 | ✅ | rspack build，24KB bundle，5 warnings 0 errors |
| 以 mitmproxy 用户启动 | ❌ 预期失败 | `MITM_PROXY feature not enabled, exiting` — 当前 main 上的 feature switch 检查。PR #4378 已删除此检查。RFC 方案下 proxy-adapter 以 `--passthrough` 模式启动，不经过此路径。 |

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
| 完整转发链路 | 需生产环境 CF Worker + sandboxToken |
| sandbox reuse | 需完整 pipeline 环境 |
