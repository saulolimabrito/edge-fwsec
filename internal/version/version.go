// Package version exposes build metadata injected with -ldflags.
package version

// Values are overridden at link time by the Makefile; defaults identify
// development builds so they are never mistaken for releases.
var (
	Version = "0.0.0-dev"
	Commit  = "unknown"
	Date    = "unknown"
)
