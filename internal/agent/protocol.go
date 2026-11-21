// Package agent implements efw-agent, the privileged service that owns
// system changes, and the typed protocol spoken on its Unix socket.
//
// One request per connection, one JSON object each way. Requests are
// decoded strictly and every operation accepts only its own fields; the
// agent revalidates configurations even though efw-web already did.
package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/saulolimabrito/edge-fwsec/internal/policy"
	"github.com/saulolimabrito/edge-fwsec/internal/store"
)

// MaxRequestBytes bounds a request (a configuration is a few KiB).
const MaxRequestBytes = 1 << 20

// Operations.
const (
	OpStatus   = "status"
	OpValidate = "validate"
	OpDiff     = "diff"
	OpApply    = "apply"
	OpConfirm  = "confirm"
	OpRollback = "rollback"
	OpHistory  = "history"
	OpGet      = "get"
)

// Request is the union of all operation payloads.
type Request struct {
	Op             string          `json:"op"`
	Config         json.RawMessage `json:"config,omitempty"`
	BaseRevision   *int            `json:"base_revision,omitempty"`
	Revision       int             `json:"revision,omitempty"`
	TimeoutSeconds int             `json:"timeout_seconds,omitempty"`
	Author         string          `json:"author,omitempty"`
	Message        string          `json:"message,omitempty"`
	Limit          int             `json:"limit,omitempty"`
}

// Error codes.
const (
	CodeBadRequest = "bad_request"
	CodeInvalid    = "invalid_config"
	CodeConflict   = "conflict"
	CodeBusy       = "busy"
	CodeNotTesting = "not_testing"
	CodeNotFound   = "not_found"
	CodeApply      = "apply_failed"
	CodeInternal   = "internal"
)

// Error is a typed failure.
type Error struct {
	Code     string           `json:"code"`
	Message  string           `json:"message"`
	Problems []policy.Problem `json:"problems,omitempty"`
}

// Status is the agent's view of the appliance policy.
type Status struct {
	Confirmed        int            `json:"confirmed"`
	LastRevision     int            `json:"last_revision"`
	Testing          *store.Testing `json:"testing"`
	RemainingSeconds *int           `json:"remaining_seconds"`
	Now              time.Time      `json:"now"`
}

// Response is the union of all operation results.
type Response struct {
	OK       bool            `json:"ok"`
	Error    *Error          `json:"error,omitempty"`
	Status   *Status         `json:"status,omitempty"`
	Revision int             `json:"revision,omitempty"`
	Deadline *time.Time      `json:"deadline,omitempty"`
	Diff     *string         `json:"diff,omitempty"`
	Ruleset  string          `json:"ruleset,omitempty"`
	History  []store.Event   `json:"history,omitempty"`
	Config   json.RawMessage `json:"config,omitempty"`
}

var reAuthor = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)

// DecodeRequest reads one request strictly and checks that only the
// fields of its operation are present.
func DecodeRequest(r io.Reader) (*Request, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxRequestBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxRequestBytes {
		return nil, errors.New("request too large")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var req Request
	if err := dec.Decode(&req); err != nil {
		return nil, fmt.Errorf("decode request: %w", err)
	}
	if dec.More() {
		return nil, errors.New("trailing data after request")
	}
	return &req, req.check()
}

func (r *Request) check() error {
	has := map[string]bool{
		"config":          len(r.Config) > 0,
		"base_revision":   r.BaseRevision != nil,
		"revision":        r.Revision != 0,
		"timeout_seconds": r.TimeoutSeconds != 0,
		"author":          r.Author != "",
		"message":         r.Message != "",
		"limit":           r.Limit != 0,
	}
	allowed := map[string][]string{
		OpStatus:   {},
		OpValidate: {"config"},
		OpDiff:     {"config"},
		OpApply:    {"config", "base_revision", "timeout_seconds", "author", "message"},
		OpConfirm:  {"revision", "author"},
		OpRollback: {"author"},
		OpHistory:  {"limit"},
		OpGet:      {"revision"},
	}
	ok, known := allowed[r.Op]
	if !known {
		return fmt.Errorf("unknown op %q", r.Op)
	}
	okSet := map[string]bool{}
	for _, f := range ok {
		okSet[f] = true
	}
	for f, present := range has {
		if present && !okSet[f] {
			return fmt.Errorf("field %q is not accepted by op %q", f, r.Op)
		}
	}
	switch r.Op {
	case OpValidate, OpDiff:
		if !has["config"] {
			return errors.New("config is required")
		}
	case OpApply:
		if !has["config"] || !has["base_revision"] {
			return errors.New("config and base_revision are required")
		}
	case OpConfirm, OpGet:
		if r.Revision <= 0 {
			return errors.New("revision must be > 0")
		}
	case OpHistory:
		if r.Limit < 0 || r.Limit > 1000 {
			return errors.New("limit must be 0..1000")
		}
	}
	if r.Author != "" && !reAuthor.MatchString(r.Author) {
		return errors.New("author must match " + reAuthor.String())
	}
	if len(r.Message) > 500 {
		return errors.New("message is limited to 500 characters")
	}
	if r.TimeoutSeconds < 0 {
		return errors.New("timeout_seconds must be positive")
	}
	return nil
}
