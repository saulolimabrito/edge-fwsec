package nft

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Runner invokes the nft binary directly (never through a shell) and feeds
// the script on stdin.
type Runner struct {
	Binary  string        // default "nft"
	Timeout time.Duration // default 15s
}

func (r Runner) run(ctx context.Context, args []string, script string) error {
	bin := r.Binary
	if bin == "" {
		bin = "nft"
	}
	to := r.Timeout
	if to == 0 {
		to = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = strings.NewReader(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// Check asks the kernel to validate the batch without committing it.
func (r Runner) Check(ctx context.Context, script string) error {
	return r.run(ctx, []string{"--check", "-f", "-"}, script)
}

// Apply validates and then loads the batch as one transaction. If the
// load fails, the kernel keeps the previous tables.
func (r Runner) Apply(ctx context.Context, script string) error {
	if err := r.Check(ctx, script); err != nil {
		return err
	}
	return r.run(ctx, []string{"-f", "-"}, script)
}
