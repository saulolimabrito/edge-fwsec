package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/saulolimabrito/edge-fwsec/internal/nft"
	"github.com/saulolimabrito/edge-fwsec/internal/policy"
	"github.com/saulolimabrito/edge-fwsec/internal/store"
	"github.com/saulolimabrito/edge-fwsec/internal/textdiff"
)

// Applier loads an nftables script (nft.Runner in production).
type Applier interface {
	Apply(ctx context.Context, script string) error
}

// Network applies the interface/VLAN/route part of a configuration under
// a checkpoint (NetworkManager in production; nil disables the step).
type Network interface {
	Begin(ctx context.Context, cfg *policy.Config, deadline time.Duration) (checkpoint string, err error)
	Commit(ctx context.Context, checkpoint string) error
	// Rollback restores the checkpoint, or rewrites the confirmed
	// configuration (nil = none) when the checkpoint is gone.
	Rollback(ctx context.Context, checkpoint string, confirmed *policy.Config) error
}

// Agent owns the apply/confirm/rollback state machine. The confirmation
// deadline is enforced here, not by the client.
type Agent struct {
	Store          *store.Store
	NFT            Applier
	Network        Network // optional
	Log            *slog.Logger
	MinTimeout     time.Duration // default 30s
	MaxTimeout     time.Duration // default 10m
	DefaultTimeout time.Duration // default 2m
	Now            func() time.Time

	mu    sync.Mutex
	timer *time.Timer
}

func (a *Agent) defaults() {
	if a.MinTimeout == 0 {
		a.MinTimeout = 30 * time.Second
	}
	if a.MaxTimeout == 0 {
		a.MaxTimeout = 10 * time.Minute
	}
	if a.DefaultTimeout == 0 {
		a.DefaultTimeout = 2 * time.Minute
	}
	if a.Now == nil {
		a.Now = time.Now
	}
	if a.Log == nil {
		a.Log = slog.Default()
	}
}

// Recover runs at startup: a revision left under test (crash, restart or
// reboot) is abandoned and the last confirmed revision is applied, which
// also restores the ruleset after a reboot.
func (a *Agent) Recover(ctx context.Context) error {
	a.defaults()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rollbackNetworkLocked(ctx)
	if rev, err := a.Store.EndTest("recover", "efw-agent", "agent started while the revision was under test"); err != nil {
		return err
	} else if rev != 0 {
		a.Log.Warn("abandoned revision left under test", "revision", rev)
	}
	return a.applyConfirmedLocked(ctx, "startup")
}

// Shutdown rolls back a revision under test so a stopped agent never
// leaves an unconfirmed policy active past its deadline.
func (a *Agent) Shutdown(ctx context.Context) {
	a.defaults()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.Store.State().Testing != nil {
		a.rollbackLocked(ctx, "efw-agent", "agent stopped during the test window")
	}
}

// Handle executes one request. peer identifies the caller for the audit log.
func (a *Agent) Handle(ctx context.Context, req *Request, peer string) Response {
	a.defaults()
	a.mu.Lock()
	defer a.mu.Unlock()
	author := req.Author
	if author == "" {
		author = peer
	} else {
		author = author + " via " + peer
	}
	switch req.Op {
	case OpStatus:
		return Response{OK: true, Status: a.statusLocked()}
	case OpValidate:
		if _, resp := decodeConfig(req.Config); resp != nil {
			return *resp
		}
		return Response{OK: true}
	case OpDiff:
		return a.diffLocked(req.Config)
	case OpApply:
		return a.applyLocked(ctx, req, author)
	case OpConfirm:
		return a.confirmLocked(req.Revision, author)
	case OpRollback:
		if a.Store.State().Testing == nil {
			return fail(CodeNotTesting, "no revision is under test")
		}
		rev := a.rollbackLocked(ctx, author, "rolled back on request")
		return Response{OK: true, Revision: rev, Status: a.statusLocked()}
	case OpHistory:
		h, err := a.Store.History(req.Limit)
		if err != nil {
			return fail(CodeInternal, err.Error())
		}
		return Response{OK: true, History: h}
	case OpGet:
		r, err := a.Store.Get(req.Revision)
		if err != nil {
			return fail(CodeNotFound, fmt.Sprintf("revision %d not found", req.Revision))
		}
		return Response{OK: true, Revision: r.Number, Config: r.Config}
	}
	return fail(CodeBadRequest, "unknown op")
}

func (a *Agent) statusLocked() *Status {
	st := a.Store.State()
	s := &Status{Confirmed: st.Confirmed, LastRevision: st.LastRevision, Testing: st.Testing, Now: a.Now().UTC()}
	if st.Testing != nil {
		rem := max(0, int(st.Testing.Deadline.Sub(a.Now()).Seconds()))
		s.RemainingSeconds = &rem
	}
	return s
}

func decodeConfig(raw json.RawMessage) (*policy.Config, *Response) {
	c, err := policy.Decode(bytes.NewReader(raw))
	if err != nil {
		r := fail(CodeInvalid, err.Error())
		return nil, &r
	}
	if err := policy.Validate(c); err != nil {
		r := fail(CodeInvalid, "configuration is invalid")
		var ps policy.Problems
		if errors.As(err, &ps) {
			r.Error.Problems = ps
		}
		return nil, &r
	}
	return c, nil
}

func (a *Agent) confirmedScript() (string, error) {
	st := a.Store.State()
	if st.Confirmed == 0 {
		return nft.RemoveScript(), nil
	}
	r, err := a.Store.Get(st.Confirmed)
	if err != nil {
		return "", err
	}
	c, err := r.Decode()
	if err != nil {
		return "", err
	}
	return nft.Render(c)
}

func (a *Agent) diffLocked(raw json.RawMessage) Response {
	c, resp := decodeConfig(raw)
	if resp != nil {
		return *resp
	}
	next, err := nft.Render(c)
	if err != nil {
		return fail(CodeInvalid, err.Error())
	}
	cur, err := a.confirmedScript()
	if err != nil {
		return fail(CodeInternal, err.Error())
	}
	d := textdiff.Lines(cur, next, 3)
	return Response{OK: true, Diff: &d, Ruleset: next}
}

func (a *Agent) applyLocked(ctx context.Context, req *Request, author string) Response {
	c, resp := decodeConfig(req.Config)
	if resp != nil {
		return *resp
	}
	timeout := a.DefaultTimeout
	if req.TimeoutSeconds > 0 {
		timeout = time.Duration(req.TimeoutSeconds) * time.Second
	}
	if timeout < a.MinTimeout || timeout > a.MaxTimeout {
		return fail(CodeBadRequest, fmt.Sprintf("timeout must be between %s and %s", a.MinTimeout, a.MaxTimeout))
	}
	script, err := nft.Render(c)
	if err != nil {
		return fail(CodeInvalid, err.Error())
	}
	rev, err := a.Store.Propose(c, *req.BaseRevision, author, req.Message)
	switch {
	case errors.Is(err, store.ErrConflict):
		return fail(CodeConflict, err.Error())
	case errors.Is(err, store.ErrBusy):
		return fail(CodeBusy, err.Error())
	case err != nil:
		return fail(CodeInternal, err.Error())
	}
	deadline := a.Now().Add(timeout)
	// Persist "testing" before touching the system: a crash from here on
	// is recovered by rolling back to the confirmed revision.
	if err := a.Store.BeginTest(rev.Number, deadline, author); err != nil {
		return fail(CodeBusy, err.Error())
	}
	// Network first (under a checkpoint), then the firewall that refers
	// to its devices. Rollback runs in the opposite order of trust:
	// network restored first, then the confirmed ruleset.
	if a.Network != nil {
		cp, err := a.Network.Begin(ctx, c, timeout)
		if err != nil {
			a.Log.Error("network apply failed, rolling back", "revision", rev.Number, "err", err)
			a.Store.Audit(store.Event{Action: "apply_failed", Revision: rev.Number, Author: author, Result: "network: " + err.Error()})
			a.rollbackLocked(ctx, "efw-agent", "network apply failed")
			// Begin already rolled its checkpoint back; reassert the confirmed
			// profiles as well, so no partial network change can survive.
			a.reassertNetworkLocked(ctx)
			return fail(CodeApply, "network: "+err.Error())
		}
		if err := a.Store.SetCheckpoint(rev.Number, cp); err != nil {
			a.Log.Error("could not record checkpoint", "err", err)
		}
	}
	if err := a.NFT.Apply(ctx, script); err != nil {
		a.Log.Error("apply failed, rolling back", "revision", rev.Number, "err", err)
		a.Store.Audit(store.Event{Action: "apply_failed", Revision: rev.Number, Author: author, Result: err.Error()})
		a.rollbackLocked(ctx, "efw-agent", "apply failed")
		return fail(CodeApply, err.Error())
	}
	a.armLocked(rev.Number, timeout)
	a.Log.Info("revision under test", "revision", rev.Number, "deadline", deadline, "author", author)
	return Response{OK: true, Revision: rev.Number, Deadline: &deadline, Status: a.statusLocked()}
}

func (a *Agent) confirmLocked(rev int, author string) Response {
	st := a.Store.State()
	if st.Testing == nil || st.Testing.Revision != rev {
		return fail(CodeNotTesting, fmt.Sprintf("revision %d is not under test", rev))
	}
	if a.Network != nil && st.Testing.Checkpoint != "" {
		if err := a.Network.Commit(context.Background(), st.Testing.Checkpoint); err != nil {
			// The network may already have been restored by NetworkManager;
			// do not confirm a state we cannot vouch for.
			a.rollbackLocked(context.Background(), "efw-agent", "network checkpoint could not be released: "+err.Error())
			return fail(CodeApply, "network checkpoint could not be released; the change was rolled back")
		}
	}
	if err := a.Store.Confirm(rev, author); err != nil {
		if errors.Is(err, store.ErrNotTesting) {
			return fail(CodeNotTesting, fmt.Sprintf("revision %d is not under test", rev))
		}
		return fail(CodeInternal, err.Error())
	}
	a.disarmLocked()
	a.Log.Info("revision confirmed", "revision", rev, "author", author)
	return Response{OK: true, Revision: rev, Status: a.statusLocked()}
}

// rollbackLocked clears the test state first (durable), then reapplies the
// confirmed revision. Returns the abandoned revision.
func (a *Agent) rollbackLocked(ctx context.Context, author, reason string) int {
	a.disarmLocked()
	a.rollbackNetworkLocked(ctx)
	rev, err := a.Store.EndTest("rollback", author, reason)
	if err != nil {
		a.Log.Error("could not record rollback", "err", err)
	}
	if err := a.applyConfirmedLocked(ctx, "rollback"); err != nil {
		a.Log.Error("CRITICAL: reapplying the confirmed revision failed", "err", err)
	}
	a.Log.Warn("rolled back", "revision", rev, "reason", reason)
	return rev
}

// rollbackNetworkLocked restores the network of a revision under test.
func (a *Agent) rollbackNetworkLocked(ctx context.Context) {
	st := a.Store.State()
	if a.Network == nil || st.Testing == nil || st.Testing.Checkpoint == "" {
		return
	}
	var confirmed *policy.Config
	if st.Confirmed != 0 {
		if r, err := a.Store.Get(st.Confirmed); err == nil {
			confirmed, _ = r.Decode()
		}
	}
	if err := a.Network.Rollback(ctx, st.Testing.Checkpoint, confirmed); err != nil {
		a.Log.Error("CRITICAL: network rollback failed", "checkpoint", st.Testing.Checkpoint, "err", err)
		a.Store.Audit(store.Event{Action: "network_rollback_failed", Revision: st.Testing.Revision, Author: "efw-agent", Result: err.Error()})
	}
}

// reassertNetworkLocked rewrites the confirmed network profiles (no
// checkpoint involved).
func (a *Agent) reassertNetworkLocked(ctx context.Context) {
	if a.Network == nil {
		return
	}
	var confirmed *policy.Config
	if st := a.Store.State(); st.Confirmed != 0 {
		if r, err := a.Store.Get(st.Confirmed); err == nil {
			confirmed, _ = r.Decode()
		}
	}
	if err := a.Network.Rollback(ctx, "", confirmed); err != nil {
		a.Log.Error("CRITICAL: could not reassert the confirmed network", "err", err)
		a.Store.Audit(store.Event{Action: "network_rollback_failed", Revision: a.Store.State().Confirmed, Author: "efw-agent", Result: err.Error()})
	}
}

func (a *Agent) applyConfirmedLocked(ctx context.Context, why string) error {
	script, err := a.confirmedScript()
	if err != nil {
		return err
	}
	st := a.Store.State()
	err = a.NFT.Apply(ctx, script)
	res := "ok"
	if err != nil {
		res = err.Error()
	}
	a.Store.Audit(store.Event{Action: "restore_" + why, Revision: st.Confirmed, Author: "efw-agent", Result: res})
	return err
}

func (a *Agent) armLocked(rev int, d time.Duration) {
	a.disarmLocked()
	a.timer = time.AfterFunc(d, func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		st := a.Store.State()
		if st.Testing == nil || st.Testing.Revision != rev {
			return // confirmed or replaced meanwhile
		}
		a.rollbackLocked(context.Background(), "efw-agent", "confirmation deadline expired")
	})
}

func (a *Agent) disarmLocked() {
	if a.timer != nil {
		a.timer.Stop()
		a.timer = nil
	}
}

func fail(code, msg string) Response {
	return Response{OK: false, Error: &Error{Code: code, Message: msg}}
}
