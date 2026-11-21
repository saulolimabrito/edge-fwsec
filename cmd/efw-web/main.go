// Command efw-web is the unprivileged web console of Edge FWSec.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/saulolimabrito/edge-fwsec/internal/auth"
	"github.com/saulolimabrito/edge-fwsec/internal/sysinfo"
	"github.com/saulolimabrito/edge-fwsec/internal/tlsutil"
	"github.com/saulolimabrito/edge-fwsec/internal/version"
	"github.com/saulolimabrito/edge-fwsec/internal/web"
	"github.com/saulolimabrito/edge-fwsec/ui"
)

func main() {
	listen := flag.String("listen", "[::]:443", "HTTPS listen address")
	stateDir := flag.String("state-dir", "/var/lib/efw-web", "accounts, bootstrap credential and TLS material")
	socket := flag.String("agent-socket", "/run/efw/agent.sock", "efw-agent socket")
	bootstrapIfaces := flag.String("bootstrap-interfaces", "", "comma-separated devices allowed before the first confirmed configuration (loopback is always allowed)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Printf("efw-web %s (%s, %s)\n", version.Version, version.Commit, version.Date)
		return
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(log, *listen, *stateDir, *socket, splitList(*bootstrapIfaces)); err != nil {
		log.Error("efw-web", "err", err)
		os.Exit(1)
	}
}

func splitList(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

// certHosts lists names and addresses for the self-signed certificate.
func certHosts() []string {
	hosts := []string{"localhost", "127.0.0.1", "::1"}
	if h, err := os.Hostname(); err == nil {
		hosts = append(hosts, h)
	}
	if ifs, err := (sysinfo.Reader{}).Interfaces(); err == nil {
		for _, it := range ifs {
			for _, a := range it.Addresses {
				if a.Scope == "global" {
					if ip, _, err := net.ParseCIDR(a.CIDR); err == nil {
						hosts = append(hosts, ip.String())
					}
				}
			}
		}
	}
	return hosts
}

func run(log *slog.Logger, listen, stateDir, socket string, bootstrap []string) error {
	acc, err := auth.OpenAccounts(stateDir)
	if err != nil {
		return err
	}
	certs, err := tlsutil.Open(filepath.Join(stateDir, "tls"), certHosts())
	if err != nil {
		return fmt.Errorf("tls: %w", err)
	}
	agentClient := web.SocketAgent{Path: socket}
	s := &web.Server{
		UI: ui.FS(), Reader: sysinfo.Reader{}, Log: log,
		Accounts: acc, Sessions: &auth.Sessions{}, Limiter: &auth.Limiter{},
		Agent: agentClient, TLS: certs,
		Access: &web.MgmtAccess{Agent: agentClient, Bootstrap: bootstrap},
	}
	if has, _ := acc.HasUsers(); !has && !acc.BootstrapPending() {
		log.Warn("no administrator and no bootstrap credential: run `efwctl bootstrap` on the local console")
	}
	srv := &http.Server{
		Addr:              listen,
		Handler:           s.Handler(),
		TLSConfig:         certs.Config(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelDebug), // TLS handshake noise from scanners
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	info := certs.Info()
	log.Info("listening", "addr", listen, "version", version.Version, "tls_sha256", info.SHA256, "custom_certificate", info.Custom, "bootstrap_interfaces", bootstrap)
	if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
