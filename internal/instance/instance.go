package instance

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"syscall"
	"time"
)

const PingPath = "/__basicauth_helper_ping"
const Identity = "com.example.basicauthhelper/v1"

var ErrAlreadyRunning = errors.New("already running")

func Listen(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err == nil {
		return ln, nil
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		return nil, err
	}
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	resp, probeErr := client.Get("http://" + addr + PingPath)
	if probeErr == nil {
		defer resp.Body.Close()
		b, readErr := io.ReadAll(io.LimitReader(resp.Body, 256))
		if readErr == nil && resp.StatusCode == http.StatusOK && string(b) == Identity {
			return nil, ErrAlreadyRunning
		}
	}
	return nil, fmt.Errorf("监听地址 %s 已被其他程序占用: %w", addr, err)
}
