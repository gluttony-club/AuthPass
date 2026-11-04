# AuthPass

一个 macOS 菜单栏小工具：按域名前缀自动为网站填写 HTTP Basic Auth，不用每次打开测试、预发这类环境都输一遍账号密码。

在系统层生效，Safari、Chrome、Edge、Firefox 等浏览器都能用，无痕窗口也有效。

## 功能

- 按主机名前缀匹配规则，例如 `dev.` 匹配 `dev.example.com`
- 每条规则有自己的用户名和密码，可以随时添加、编辑、删除、调整顺序、启用或停用
- 不内置任何账号密码，全部由用户自己填写；密码存在 macOS 钥匙串里
- 开机自动启动（默认开启，可关闭）
- 只拦截匹配规则的域名，其他网站的流量不会被解密或改动

## 安装

1. 到 [Releases](https://github.com/gluttony-club/AuthPass/releases/latest) 下载 `AuthPass.dmg`。
2. 双击打开，把 AuthPass 拖进「应用程序」。
3. 从「应用程序」里打开 AuthPass。

系统要求 macOS 13 及以上，Apple 芯片和 Intel 都支持。

应用没有做苹果开发者签名，首次打开会被系统拦截。处理方法任选一种：

- 打开「系统设置 → 隐私与安全性」，拉到底部，点 AuthPass 旁的「仍要打开」。
- 或在终端执行：

  ```sh
  xattr -dr com.apple.quarantine "/Applications/AuthPass.app"
  ```

第一次启用时会生成本机根证书并加入钥匙串信任，系统会要求输入密码或指纹，这是正常的。

## 使用

1. 点击菜单栏的 AuthPass 图标，选择「设置…」。
2. 点「添加」，填写名称、主机前缀（如 `dev.`、`staging.`）、用户名和密码。
3. 点「保存」，规则立即生效，刷新网页即可。

![AuthPass 设置页](docs/images/settings.png)

规则说明：

- 匹配忽略大小写和端口，按列表顺序取第一条启用且匹配的规则。
- 前缀只能包含 `a-z 0-9 . -`，建议以 `.` 结尾。它只匹配开头，不是通配符：`dev.` 能匹配 `dev.example.com`，不能匹配 `mydev.example.com`。
- 用户名为空的规则不会生效。
- 编辑时密码留空表示保持原密码，点「清除密码」才会删除。

菜单里还可以启用/停用、打开配置目录、安装/信任根证书、切换开机自动启动、退出。停用或退出时会恢复原来的系统代理设置。

### 配置文件示例

规则保存在 `~/Library/Application Support/AuthPass/config.json`，一般在设置页改就行，不用手动编辑。密码不在这个文件里，只存在钥匙串中。

```json
{
  "listen": "127.0.0.1:18080",
  "launch_at_login": true,
  "rules": [
    {"id": "dev", "name": "开发环境", "host_prefix": "dev.", "username": "dev-user", "enabled": true},
    {"id": "staging", "name": "预发环境", "host_prefix": "staging.", "username": "staging-user", "enabled": true},
    {"id": "feature", "name": "特性环境", "host_prefix": "feature.", "username": "feature-user", "enabled": false}
  ]
}
```

按这份配置，`dev.example.com` 会用 dev-user 的账号登录，`staging.example.com` 会用 staging-user 的账号登录，特性环境这条已停用，不会生效。

### Firefox

Firefox 默认不信任系统证书。在 `about:config` 中把 `security.enterprise_roots.enabled` 设为 `true`，并确认网络设置为「使用系统代理设置」。

## 工作原理

AuthPass 在本机 `127.0.0.1:18080` 运行一个代理，并设置系统自动代理（PAC），只把匹配规则的域名交给它：

- HTTP 请求：直接加上 `Authorization` 头。
- HTTPS 请求：用本机生成的根证书在本地解密、加头后再转发到目标站点。
- 其他域名：PAC 直接返回 DIRECT，不经过代理。

## 安全说明

- 安装包里没有任何凭据；密码只保存在本机钥匙串中。
- 根证书和私钥每台机器单独生成，保存在 `~/Library/Application Support/AuthPass/`，权限 0600，请勿分享。
- 只有匹配规则的域名会被解密，请只为你信任的环境添加规则。
- 代理只监听本机回环地址，设置页使用每次启动随机生成的 token 保护。

## 已知限制

- 不支持 WebSocket、HTTP/2 解密和客户端证书认证。
- 自行忽略系统代理的应用不受影响；VPN 或其他代理工具可能与本工具冲突。
- 强制退出时无法立刻恢复系统代理，下次启动会自动恢复。

## 卸载

1. 在菜单中选择「停用」，然后退出。
2. 删除 `/Applications/AuthPass.app`。
3. 删除 `~/Library/Application Support/AuthPass` 和 `~/Library/LaunchAgents/club.gluttony.authpass.plist`。
4. 在「钥匙串访问」中删除证书 `AuthPass Local CA`，以及服务名为 `club.gluttony.authpass` 的密码项。

## 从源码构建

需要 Go 1.22+ 和 Xcode Command Line Tools：

```sh
xcode-select --install
./build-mac.sh          # 生成 dist/AuthPass.app（arm64 + amd64 通用）
./build-mac.sh --dmg    # 同时生成 dist/AuthPass.dmg
```

运行测试：

```sh
go test ./...
./test/e2e.sh           # 端到端测试，可在 Linux 上运行
```

## 许可证

[MIT](LICENSE)
