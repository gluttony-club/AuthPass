# 参与贡献

欢迎提交 Issue 和 Pull Request。安全漏洞请勿公开提交，按 [SECURITY.md](SECURITY.md) 私密报告。

## 构建

需要 Go 1.24+；打包 macOS 应用还需要 Xcode Command Line Tools：

```sh
./build-mac.sh          # 生成 dist/AuthPass.app（arm64 + x86_64 通用）
./build-mac.sh --dmg    # 同时生成 dist/AuthPass.dmg
./build-linux-test.sh   # 在 Linux 上构建无菜单栏的测试版 dist/authpass
```

## 测试

```sh
gofmt -l .                          # 应无输出
go vet ./...
GOOS=darwin CGO_ENABLED=0 go vet ./...
go test ./...
./test/e2e.sh                       # 端到端测试，Linux / macOS 均可，需要 rg（ripgrep）和 curl
```

单元测试只使用临时目录和文件存储，不会访问真实钥匙串或修改系统代理。`internal/sysproxy/real_darwin_test.go` 会改动真实网络服务，只在设置 `AUTHPASS_TEST_SERVICE` 指向一个临时网络服务时运行，请勿对日常使用的网络服务运行。

## Pull Request

- 一个 PR 只做一件事，附上改动原因；行为变化请同步更新 README。
- 提交前确认上面的检查全部通过，CI 会在 Linux 和 macOS 上重复运行。
- 涉及钥匙串、系统代理、证书信任或菜单栏的改动，请说明在哪个 macOS 版本的真机上验证过。
- **不要在代码、测试、截图、日志或提交说明中出现真实域名、账号、密码、证书或本机路径**；示例请用 `example.com`、`dev-user` 这类占位值。
- 提交的代码以 [MIT 许可证](LICENSE) 发布。
