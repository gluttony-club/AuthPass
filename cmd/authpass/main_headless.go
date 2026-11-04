//go:build !darwin || notray || !cgo

package main

import (
	"github.com/gluttony-club/AuthPass/internal/ca"
	"github.com/gluttony-club/AuthPass/internal/config"
	"github.com/gluttony-club/AuthPass/internal/instance"
	"github.com/gluttony-club/AuthPass/internal/proxy"
	"github.com/gluttony-club/AuthPass/internal/secret"
	"github.com/gluttony-club/AuthPass/internal/settings"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func main() {
	dir, e := config.DataDir()
	if e != nil {
		log.Fatal(e)
	}
	cp := flag.String("config", "", "configuration file")
	dp := flag.String("datadir", dir, "CA data directory")
	lp := flag.String("listen", "", "listen override")
	tp := flag.String("token", "", "settings token override for tests")
	flag.Parse()
	path := filepath.Join(*dp, "config.json")
	if *cp != "" {
		b, e := os.ReadFile(*cp)
		if e != nil {
			log.Fatal(e)
		}
		if _, e = os.Stat(path); os.IsNotExist(e) {
			if e = config.WriteFile(path, b); e != nil {
				log.Fatal(e)
			}
		}
	}
	c, e := config.Load(path)
	if e != nil {
		log.Fatal(e)
	}
	if *lp != "" {
		c.Listen = *lp
	}
	ln, e := instance.Listen(c.Listen)
	if errors.Is(e, instance.ErrAlreadyRunning) {
		log.Print("already running")
		return
	}
	if e != nil {
		log.Fatal(e)
	}
	defer ln.Close()
	a, e := ca.Open(*dp)
	if e != nil {
		log.Fatal(e)
	}
	m, e := settings.New(c, path, secret.New(*dp), *tp)
	if e != nil {
		log.Fatal(e)
	}
	if err := initializeLaunchAtLogin(m); err != nil {
		log.Print(err)
	}
	m.CAPath = a.CertPath
	p, e := proxy.New(c, a)
	if e != nil {
		log.Fatal(e)
	}
	p.Local = m
	m.Publish = p.Update
	defer p.Close()
	srv := &http.Server{Addr: c.Listen, Handler: p, ReadHeaderTimeout: 15 * time.Second}
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-done
		p.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()
	fmt.Printf("Settings: %s\n", m.URL())
	fmt.Printf("CA: %s\nListening: %s\n", a.CertPath, c.Listen)
	if e = srv.Serve(ln); e != nil && e != http.ErrServerClosed {
		log.Fatal(e)
	}
}
