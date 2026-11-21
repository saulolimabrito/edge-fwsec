// Package backup exports and imports configuration backups.
//
// A backup is a JSON envelope around one configuration revision. It never
// contains secrets: administrator accounts, password hashes, session keys
// and TLS private keys are not part of the policy and are not exported.
// Restoring goes through the normal validate → diff → apply-with-deadline
// flow; this package only parses, migrates and validates.
package backup

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/saulolimabrito/edge-fwsec/internal/policy"
)

// Format identifies Edge FWSec backups.
const (
	Format        = "edge-fwsec-backup"
	FormatVersion = 1
	MaxBytes      = 1 << 20
)

// Envelope is the backup file.
type Envelope struct {
	Format        string          `json:"format"`
	FormatVersion int             `json:"format_version"`
	SchemaVersion int             `json:"schema_version"`
	Revision      int             `json:"revision"`
	ExportedAt    time.Time       `json:"exported_at"`
	ExportedBy    string          `json:"exported_by"`
	AppVersion    string          `json:"app_version"`
	Config        json.RawMessage `json:"config"`
}

// Export wraps a confirmed configuration.
func Export(cfg *policy.Config, rev int, by, appVersion string, now time.Time) ([]byte, error) {
	raw, err := cfg.Canonical()
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(Envelope{Format: Format, FormatVersion: FormatVersion, SchemaVersion: cfg.SchemaVersion,
		Revision: rev, ExportedAt: now.UTC(), ExportedBy: by, AppVersion: appVersion, Config: raw}, "", "  ")
}

// Info summarizes an imported backup.
type Info struct {
	Revision      int       `json:"revision"`
	ExportedAt    time.Time `json:"exported_at"`
	ExportedBy    string    `json:"exported_by"`
	AppVersion    string    `json:"app_version"`
	SchemaVersion int       `json:"schema_version"`
	MigratedFrom  int       `json:"migrated_from,omitempty"`
}

// Import parses, migrates and validates a backup.
func Import(b []byte) (*policy.Config, *Info, error) {
	if len(b) > MaxBytes {
		return nil, nil, errors.New("backup is larger than 1 MiB")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var env Envelope
	if err := dec.Decode(&env); err != nil {
		return nil, nil, fmt.Errorf("not an Edge FWSec backup: %w", err)
	}
	if env.Format != Format {
		return nil, nil, errors.New("not an Edge FWSec backup (format field)")
	}
	if env.FormatVersion != FormatVersion {
		return nil, nil, fmt.Errorf("backup format version %d is not supported (this build reads %d)", env.FormatVersion, FormatVersion)
	}
	if env.SchemaVersion > policy.SchemaVersion {
		return nil, nil, fmt.Errorf("backup uses configuration schema %d, newer than this build (%d); upgrade Edge FWSec first", env.SchemaVersion, policy.SchemaVersion)
	}
	if env.SchemaVersion < 1 {
		return nil, nil, fmt.Errorf("invalid schema version %d", env.SchemaVersion)
	}
	cfg, from, err := policy.DecodeVersioned(bytes.NewReader(env.Config))
	if err != nil {
		return nil, nil, err
	}
	if from != env.SchemaVersion {
		return nil, nil, errors.New("schema_version inside the configuration does not match the envelope")
	}
	info := &Info{Revision: env.Revision, ExportedAt: env.ExportedAt, ExportedBy: env.ExportedBy, AppVersion: env.AppVersion, SchemaVersion: policy.SchemaVersion}
	if from != policy.SchemaVersion {
		info.MigratedFrom = from
	}
	if err := policy.Validate(cfg); err != nil {
		return nil, nil, err
	}
	return cfg, info, nil
}
