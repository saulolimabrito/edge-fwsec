package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// migrations[n] upgrades a raw schema-n document to schema n+1. Every
// schema bump adds an entry here and keeps an old document as a test
// fixture (internal/backup/testdata, internal/policy/testdata).
var migrations = map[int]func(doc map[string]any) error{
	// 1 → 2: SSH on management interfaces. Off for upgraded systems so an
	// upgrade never opens a port the administrator did not choose.
	1: func(doc map[string]any) error {
		admin, ok := doc["admin"].(map[string]any)
		if !ok {
			return errors.New("admin section missing")
		}
		admin["ssh"] = false
		admin["ssh_port"] = 22
		return nil
	},
}

// Upgrade migrates a raw configuration document to SchemaVersion and
// returns the upgraded document and the version it was written with.
func Upgrade(raw []byte) ([]byte, int, error) {
	var head struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return nil, 0, fmt.Errorf("decode config: %w", err)
	}
	from := head.SchemaVersion
	switch {
	case from == SchemaVersion:
		return raw, from, nil
	case from > SchemaVersion:
		return nil, from, fmt.Errorf("configuration schema %d is newer than this build (%d); upgrade Edge FWSec first", from, SchemaVersion)
	case from < 1:
		return nil, from, fmt.Errorf("invalid schema_version %d", from)
	}
	var doc map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return nil, from, err
	}
	for v := from; v < SchemaVersion; v++ {
		m, ok := migrations[v]
		if !ok {
			return nil, from, fmt.Errorf("no migration from schema %d", v)
		}
		if err := m(doc); err != nil {
			return nil, from, fmt.Errorf("migrating schema %d to %d: %w", v, v+1, err)
		}
		doc["schema_version"] = v + 1
	}
	out, err := json.Marshal(doc)
	return out, from, err
}
