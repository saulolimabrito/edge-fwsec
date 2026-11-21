// Command efw-agent is the privileged Edge FWSec service. It owns the
// revision store and is the only component that changes system state.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/saulolimabrito/edge-fwsec/internal/agent"
	"github.com/saulolimabrito/edge-fwsec/internal/nft"
	"github.com/saulolimabrito/edge-fwsec/internal/nm"
	"github.com/saulolimabrito/edge-fwsec/internal/store"
	"github.com/saulolimabrito/edge-fwsec/internal/version"
)

func main() {
	stateDir := flag.String("state-dir", "/var/lib/efw", "revision store directory")
	socket := flag.String("socket", "/run/efw/agent.sock", "Unix socket path")
	group := flag.String("socket-group", "efw", "group allowed to use the socket (empty: keep current)")
	nftBin := flag.String("nft", "nft", "nft binary")
	network := flag.String("network", "nm", "network backend: nm (NetworkManager checkpoints) or none")
	minTimeout := flag.Duration("min-timeout", 30*time.Second, "shortest confirmation window")
	maxTimeout := flag.Duration("max-timeout", 10*time.Minute, "longest confirmation window")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Printf("efw-agent %s (%s, %s)\n", version.Version, version.Commit, version.Date)
		return
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if *network != "nm" && *network != "none" {
		log.Error("invalid -network", "value", *network)
		os.Exit(2)
	}
	if err := run(log, *stateDir, *socket, *group, *nftBin, *network, *minTimeout, *maxTimeout); err != nil {
		log.Error("efw-agent", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger, stateDir, socket, group, nftBin, network string, minT, maxT time.Duration) error {
	st, err := store.Open(stateDir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()
	a := &agent.Agent{Store: st, NFT: nft.Runner{Binary: nftBin}, Log: log, MinTimeout: minT, MaxTimeout: maxT}
	if network == "nm" {
		c, err := nm.Connect()
		if err != nil {
			return fmt.Errorf("NetworkManager: %w", err)
		}
		defer c.Close()
		v, err := c.Version()
		if err != nil {
			return fmt.Errorf("NetworkManager not reachable on the system bus: %w", err)
		}
		log.Info("network backend", "networkmanager", v)
		a.Network = agent.NMNetwork{N: &nm.Network{Client: c}}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Recovery comes before the socket opens: nobody can start a change
	// until the confirmed revision is in place.
	if err := a.Recover(ctx); err != nil {
		log.Error("recovery could not reapply the confirmed revision", "err", err)
	}
	ln, err := agent.Listen(socket, group)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	log.Info("ready", "socket", socket, "state", stateDir, "version", version.Version, "confirmed", st.State().Confirmed)
	err = a.Serve(ctx, ln)
	a.Shutdown(context.Background())
	return err
}
