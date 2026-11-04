//go:build darwin && !notray && cgo

package main

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"fyne.io/systray"
	"github.com/gluttony-club/AuthPass/internal/ca"
	"github.com/gluttony-club/AuthPass/internal/config"
	"github.com/gluttony-club/AuthPass/internal/instance"
	"github.com/gluttony-club/AuthPass/internal/proxy"
	"github.com/gluttony-club/AuthPass/internal/secret"
	"github.com/gluttony-club/AuthPass/internal/settings"
	"github.com/gluttony-club/AuthPass/internal/sysproxy"
	"github.com/gluttony-club/AuthPass/internal/trust"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

//go:embed icon.png
var icon []byte

func main() { systray.Run(ready, func() {}) }
func ready() {
	systray.SetTemplateIcon(icon, icon)
	systray.SetTooltip("AuthPass")
	status := systray.AddMenuItem("已停用", "")
	status.Disable()
	toggle := systray.AddMenuItem("启用", "")
	open := systray.AddMenuItem("打开配置目录", "")
	login := systray.AddMenuItemCheckbox("开机自动启动", "", true)
	settingsItem := systray.AddMenuItem("设置…", "")

	install := systray.AddMenuItem("安装/信任根证书", "")
	quit := systray.AddMenuItem("退出", "")
	go func() {
		dir, e := config.DataDir()
		if e != nil {
			log.Print(e)
			systray.Quit()
			return
		}
		path := filepath.Join(dir, "config.json")
		var c *config.Config
		var a *ca.Authority
		var p *proxy.Server
		var srv *http.Server
		enabled := false
		var manager *settings.Manager
		var launchErr error
		refresh := make(chan struct{}, 1)
		report := func(e error) {
			if e != nil {
				log.Print(e)
				status.SetTitle("错误: " + e.Error())
			}
		}
		stop := func() {
			if srv != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				p.Close()
				_ = srv.Shutdown(ctx)
				cancel()
				srv = nil
			}
		}
		load := func() error {
			nc, e := config.Load(path)
			if e != nil {
				return e
			}
			ln, e := instance.Listen(nc.Listen)
			if e != nil {
				return e
			}
			ok := false
			defer func() {
				if !ok {
					ln.Close()
				}
			}()
			na, e := ca.Open(dir)
			if e != nil {
				return e
			}
			nm, e := settings.New(nc, path, secret.New(dir), "")
			if e != nil {
				return e
			}
			nm.PreferencesChanged = func(v bool) {
				if v {
					login.Check()
				} else {
					login.Uncheck()
				}
			}
			launchErr = initializeLaunchAtLogin(nm)
			nm.PreferencesChanged(nm.LaunchAtLogin())
			nm.CAPath = na.CertPath
			np, e := proxy.New(nc, na)
			if e != nil {
				return e
			}
			np.Local = nm
			nm.Publish = np.Update
			nm.Changed = func() error {
				select {
				case refresh <- struct{}{}:
				default:
				}
				return nil
			}
			manager = nm
			stop()
			ok = true
			c, a, p = nc, na, np
			srv = &http.Server{Handler: p, ReadHeaderTimeout: 15 * time.Second}
			go func(s *http.Server) {
				if e := s.Serve(ln); e != nil && e != http.ErrServerClosed {
					log.Print(e)
				}
			}(srv)
			return nil
		}
		disable := func() error {
			if e := sysproxy.Restore(dir); e != nil {
				return e
			}
			enabled = false
			if manager != nil {
				manager.SetEnabled(false)
			}
			toggle.SetTitle("启用")
			if c != nil {
				status.SetTitle("已停用 / " + c.Listen)
			}
			return nil
		}
		enable := func() error {
			if srv == nil {
				if e := load(); e != nil {
					return e
				}
			}
			if e := trust.Ensure(a.CertPath); e != nil {
				return e
			}
			if e := sysproxy.Enable(dir, fmt.Sprintf("http://%s%s", c.Listen, c.PACPath)); e != nil {
				return e
			}
			enabled = true
			manager.SetEnabled(true)
			toggle.SetTitle("停用")
			status.SetTitle("运行中 / " + c.Listen)
			return nil
		}
		if e = load(); e != nil {
			if errors.Is(e, instance.ErrAlreadyRunning) {
				log.Print("already running")
				systray.Quit()
				return
			}
			log.Print(e)
			systray.Quit()
			os.Exit(1)
		} else {
			report(sysproxy.Restore(dir))
			status.SetTitle("已停用 / " + c.Listen)
			if c.AutoEnable {
				report(enable())
			}
		}
		report(launchErr)
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
		for {
			select {
			case <-login.ClickedCh:
				if manager != nil {
					report(manager.UpdateLaunchAtLogin(!manager.LaunchAtLogin()))
				}
			case <-toggle.ClickedCh:
				if enabled {
					report(disable())
				} else {
					report(enable())
				}
			case <-settingsItem.ClickedCh:
				if manager != nil {
					report(exec.Command("open", manager.URL()).Start())
				}
			case <-open.ClickedCh:
				report(exec.Command("open", dir).Start())
			case <-refresh:
				if enabled {
					report(sysproxy.Enable(dir, fmt.Sprintf("http://%s%s", c.Listen, c.PACPath)))
				}
			case <-install.ClickedCh:
				if a != nil {
					report(trust.Ensure(a.CertPath))
				}
			case <-quit.ClickedCh:
				// Never trap the user in the app: log restore errors and quit anyway.
				// proxy-state.json is kept on failure and retried on next launch.
				report(disable())
				stop()
				systray.Quit()
				return
			case <-signals:
				report(disable())
				stop()
				systray.Quit()
				return
			}
		}
	}()
}
