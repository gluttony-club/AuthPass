# BasicAuth Helper

macOS 菜单栏小工具，为公司测试、预发站点自动填写 HTTP Basic Auth。通过系统 PAC 将目标域名交给本地代理；HTTP 请求直接注入认证，HTTPS 仅对目标域名执行本地 MITM，使用本机生成的 CA 签发站点证书。非目标 CONNECT 直接建立 TCP 隧道，不解密、不添加认证。无痕窗口也生效，因为代理设置在系统层。

## 配置

程序不嵌入任何账号或密码。默认不带任何规则，首次打开后在设置页自行添加（例如前缀 `dev.`、`staging.`），每条规则填写各自的用户名和密码；首次启动将默认配置写入数据目录，以后只读取用户配置，不再与默认值合并。

macOS 配置路径为 `~/Library/Application Support/BasicAuthHelper/config.json`，其他系统为 `os.UserConfigDir()/BasicAuthHelper/config.json`。配置只保存规则 ID、名称、主机前缀、用户名、启用状态等非密码信息。macOS 密码通过 `/usr/bin/security` 保存到登录钥匙串，服务名 `com.example.basicauthhelper`，账号为规则 ID；增改使用 `add-generic-password -U`，读取使用 `find-generic-password`，删除使用 `delete-generic-password`，均不依赖 cgo。`-w` 参数中的密码会短暂出现在进程参数中，可被本机进程观察。非 macOS 使用数据目录中的 `secrets.json`（0600 明文文件），仅作为开发、测试回退。

菜单点击「设置…」打开本地中文设置页。Linux/headless 启动时向 stdout 打印完整设置 URL。每次启动生成 32 字节随机 token（64 位十六进制），只保存在内存；不要分享该 URL。页面显示代理地址、CA 路径、系统代理状态，可添加、编辑、删除、上移、启用规则，再点击「保存」。编辑时密码留空保留原密码，点击「清除密码」可显式清除。保存后代理和 PAC 立即更新，macOS 已启用时重新设置带新 `?t=` 的系统 PAC URL；已有连接及浏览器 PAC 缓存可能需要重新连接后更新。

主机匹配忽略大小写、端口和末尾 DNS 点，按列表顺序取第一条启用且前缀匹配的规则。该规则用户名为空时不注入认证，HTTPS 使用普通 CONNECT 隧道，PAC 返回 DIRECT。前缀不能为空，只接受 `[a-z0-9.-]`，建议以 `.` 结尾。例如 `dev.` 匹配 `dev.foo.com`、`dev.a.b.cn`；新增 `feature.` 规则可使用另一组独立账号。不是域名后缀或通配符匹配，不提供端口筛选。目标请求已有 Authorization 会被覆盖，非目标请求保留原认证；代理移除逐跳和 Proxy-* 请求/响应头。

配置示例（密码仅通过设置页输入）：

```json
{
  "listen": "127.0.0.1:18080",
  "pac_path": "/proxy.pac",
  "auto_enable": true,
  "launch_at_login": true,
  "insecure_skip_verify_upstream": false,
  "upstream_ca_file": "",
  "rules": []
}
```

设置 API 仅接收直接访问本地监听器的请求，`/settings` 与所有 `/api/*` 要求 `X-Auth-Token` 请求头或 `token` 查询参数；Host 必须为监听端口的 `127.0.0.1:<port>` 或 `localhost:<port>`，Origin 若存在必须严格等于当前 HTTP 本地源，防止 DNS rebinding 与跨源访问。代理形式的 URL 不会被当作设置页处理。

- `GET /api/preferences`：返回 `launch_at_login` 和 `launch_at_login_error`；`PUT /api/preferences` 接收 `{"launch_at_login":false}` 保存自启偏好，使用相同鉴权保护。
- `GET /api/status`：代理地址、CA 路径、系统代理启用状态。
- `GET /api/rules`：规则数组，包含 `has_password`，从不返回密码。
- `PUT /api/rules`：完整替换规则数组，顺序即优先级；新规则可省略 ID，由服务端生成。`password` 缺失、null 或空字符串均保留旧密码；非空字符串更新密码；`clear_password:true` 配合缺失/null/空密码显式清除。删除规则会删除对应秘密。不要回传只读的 `has_password` 字段。

例如从启动日志取得 token 后添加功能规则（数组应同时包含要保留的其他规则）：

```sh
curl -X PUT 'http://127.0.0.1:18080/api/rules' \
  -H "X-Auth-Token: $TOKEN" -H 'Content-Type: application/json' \
  --data '[{"name":"功能环境","host_prefix":"feature.","username":"your-user","password":"your-password","enabled":true}]'
```

默认验证 HTTPS 上游证书。公司自签名环境建议用 `upstream_ca_file` 指定可信 PEM CA（保留系统根证书）；`insecure_skip_verify_upstream: true` 可临时关闭上游验证，但会降低安全性。`host_overrides: {"dev.foo.test":"127.0.0.1"}` 仅供开发测试，改变代理侧 DNS，保留原主机名用于 Host 和 TLS 验证。请保持监听地址为回环地址，避免成为局域网认证代理。

## macOS 构建与使用

安装 Go（1.22 或更新版本）和 Xcode Command Line Tools：

```sh
xcode-select --install
go mod tidy
./build-mac.sh
./build-mac.sh --dmg
```

脚本使用 CGO 构建 arm64、amd64，并以 lipo 合成通用程序；某架构工具链失败时回退为单架构，并显示警告。产物在 `dist/BasicAuth Helper.app`，可选 DMG 在 dist 下。脚本尝试 ad-hoc codesign，它不等同于 Developer ID 签名或公证。LSUIElement 隐藏 Dock 图标。

将 app 拖到 Applications。未签名应用首次启动可右键“打开”，或到“系统设置 > 隐私与安全性 > 仍要打开”。确认来源可信后，也可以运行：

```sh
xattr -dr com.apple.quarantine "/Applications/BasicAuth Helper.app"
```

首次启用生成本机 CA，安装到登录钥匙串并设为信任根证书，系统可能提示输入钥匙串密码。`networksetup` 在部分系统或企业策略下可能要求管理员授权；若报权限错误，应按本机管理策略处理。程序不会自动使用 sudo。启用失败会在菜单状态行显示错误。

默认启动自动启用。菜单提供设置…、启用/停用、打开配置目录、安装/信任证书、退出。停用保留本地代理运行，但恢复原系统 PAC。退出及 SIGINT/SIGTERM 会恢复 PAC；意外崩溃时，下次启动先读取数据目录中的 `proxy-state.json` 恢复，再按配置启用。若应用未运行但浏览器仍指向本地 PAC，可重新启动并停用，或在网络设置中手动关闭自动代理配置。

Firefox 默认使用独立证书库：在 `about:config` 设置 `security.enterprise_roots.enabled=true`，使其信任 macOS 系统根证书；网络设置选择“使用系统代理设置”（通常为默认值）。浏览器需使用系统代理才能获得此功能。

## 开机自动启动

默认开启；配置 `launch_at_login` 缺失或为 null 时按 true 处理，首次启动尝试启用并保存 true。请先把应用拖到 `/Applications`（「应用程序」）再开启。磁盘映像、App Translocation 和非 app bundle 路径会显示中文错误提示；移动到应用程序后可重新保存。

macOS 使用 `~/Library/LaunchAgents/com.example.basicauthhelper.plist`，下次登录启动当前应用。应用移动后再次启动会自动更新旧路径。可在菜单或设置页取消「开机自动启动」；关闭只删除 plist，当前实例继续运行。开启不会立即启动第二个实例。非 macOS 仅保存偏好。

同一监听地址只允许运行一个实例：检测到本应用时输出 `already running` 并正常退出；端口被其他程序占用时显示明确错误。

## Linux / headless 验证

```sh
./build-linux-test.sh
./test/e2e.sh
go run ./cmd/basicauth-helper -config /path/config.json -datadir /tmp/helper-data -listen 127.0.0.1:18080
```

非 macOS、`-tags notray` 或禁用 CGO 时使用 CLI，只运行代理并打印 CA 路径、设置 URL（可用 `-token` 固定测试 token），不修改系统代理/信任库。curl 需显式使用 `-x` 并为目标 HTTPS 提供 `--cacert ca.crt`。e2e 脚本启动本地 HTTP/HTTPS 上游，使用 host_overrides，验证目标认证、非目标 401、非目标上游原证书和 PAC。curl 的 `--resolve` 无法控制 HTTP 代理端的 DNS。

## 分发、安全与卸载

仅通过内部渠道分发 zip/DMG。构建产物不含凭据；推荐使用权限最小的专用测试账号。用户名和规则保存在配置中，密码保存在 Keychain；Linux 回退秘密文件为明文。设置 token 可修改凭据，需与密码一样妥善保管。

CA 按用户、按机器生成；ECDSA P-256 根有效期十年，站点证书不超过 397 天、仅内存缓存。ca.key 和 ca.crt 文件权限为 0600，数据目录新建为 0700。不要共享 CA 私钥或提交到仓库。仅匹配目标主机的 HTTPS 被解密；代理能够看到这些主机的流量，请谨慎配置目标范围。

现有 PAC 被暂时替换并记录，停用后恢复；已有手动 HTTP/HTTPS 代理字段不修改，但生效优先级及 VPN、公司代理、网络扩展可能与本工具冲突。新添加的网络服务需重新启用才能配置。系统代理不覆盖自行忽略 PAC 的应用。强制终止无法立即恢复，持久化恢复依赖下次启动；不要删除仍需恢复的状态文件。

卸载前先停用并退出，并删除 `~/Library/LaunchAgents/com.example.basicauthhelper.plist`。在“钥匙串访问”删除 `BasicAuth Helper Local CA`，删除服务名 `com.example.basicauthhelper` 下的密码项目（也可先在设置页删除所有规则），删除 app 和 `~/Library/Application Support/BasicAuthHelper`。代码也提供 `internal/trust.Uninstall` 供集成使用。删除 CA 后重新运行会产生新的 CA，需重新信任。

当前支持 HTTP/1.1、HTTPS keep-alive，不支持 WebSocket Upgrade、HTTP/2 MITM、客户端证书认证；上游通常可协商 HTTP/1.1。不存在自动更新或公网代理服务。

未来可在规则增加 `auth_type` 认证类型字段，目前所有规则仅实现 Basic Auth，该字段尚未实现。未来可增加 `feishu` provider：飞书 SSO 登录后获取短期凭据，管理刷新/过期，再交给代理注入。当前仅留注释，不实现飞书登录或凭据获取。
