package agent

import (
	"context"
	"errors"
	"time"

	"github.com/saulolimabrito/edge-fwsec/internal/nm"
	"github.com/saulolimabrito/edge-fwsec/internal/policy"
)

// NMNetwork adapts nm.Network to the agent's Network step.
type NMNetwork struct {
	N *nm.Network
}

// Begin implements Network.
func (n NMNetwork) Begin(ctx context.Context, cfg *policy.Config, deadline time.Duration) (string, error) {
	ps, err := nm.Profiles(cfg)
	if err != nil {
		return "", err
	}
	return n.N.Begin(ctx, ps, deadline)
}

// Commit implements Network.
func (n NMNetwork) Commit(ctx context.Context, cp string) error { return n.N.Commit(ctx, cp) }

// Rollback implements Network.
func (n NMNetwork) Rollback(ctx context.Context, cp string, confirmed *policy.Config) error {
	err := n.N.Rollback(ctx, cp)
	if err == nil || !errors.Is(err, nm.ErrCheckpointGone) {
		return err
	}
	var ps []nm.Profile
	if confirmed != nil {
		if ps, err = nm.Profiles(confirmed); err != nil {
			return err
		}
	}
	return n.N.Restore(ctx, ps)
}
