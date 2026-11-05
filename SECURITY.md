# 安全政策

目前支持 1.1.x 版本的安全更新。

如发现漏洞，请通过仓库 Security 标签页 → “Report a vulnerability” [私密报告](https://github.com/gluttony-club/AuthPass/security/advisories/new)，不要提交公开 Issue。请提供影响版本、复现步骤和影响说明；我们预计在 7 天内确认收到，并在评估后告知修复进展及预计时间。

如果私密报告页面无法打开，请提交一个公开 Issue，只说明需要私密联系方式，**不要包含任何漏洞细节**、复现步骤或受影响的域名，我们会与你另行联系。

## 威胁模型

- AuthPass 安装本地根 CA，私钥保存在 `~/Library/Application Support/AuthPass`，权限为 `0600`。该密钥可签发任意域名证书，任何取得私钥的人都能对用户实施中间人攻击。
- 代理仅监听 `127.0.0.1`。凭据仅注入同时匹配规则前缀和 `trusted_domains` 的主机，默认仅限 HTTPS；HTTP 需显式启用 `allow_http`。
- 密码保存在 macOS Keychain；设置 API 通过随机令牌及 Host/Origin 检查保护。
- 不在保护范围内：已以同一用户身份运行的本地攻击者，以及对 `upstream_ca_file`、`insecure_skip_verify_upstream`、`host_overrides` 的误用（这些选项仅用于开发和测试）。
