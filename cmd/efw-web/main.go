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
	"syscall"
	"time"

	"github.com/saulolimabrito/edge-fwsec/internal/sysinfo"
	"github.com/saulolimabrito/edge-fwsec/internal/version"
	"github.com/saulolimabrito/edge-fwsec/internal/web"
	"github.com/saulolimabrito/edge-fwsec/ui"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8080", "listen address (stage 1: loopback only, plain HTTP)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Printf("efw-web %s (%s, %s)\n", version.Version, version.Commit, version.Date)
		return
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := checkLoopback(*listen); err != nil {
		log.Error("refusing to listen", "addr", *listen, "err", err)
		os.Exit(2)
	}
	srv := &http.Server{
		Addr:              *listen,
		Handler:           (&web.Server{UI: ui.FS(), Reader: sysinfo.Reader{}, Log: log}).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Info("listening", "addr", *listen, "version", version.Version)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("serve", "err", err)
		os.Exit(1)
	}
}

// checkLoopback enforces the stage-1 invariant: without TLS and
// authentication the console must not be reachable off-host.
func checkLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if host == "localhost" || (ip != nil && ip.IsLoopback()) {
		return nil
	}
	return errors.New("non-loopback addresses require TLS and authentication (stage 3)")
}
