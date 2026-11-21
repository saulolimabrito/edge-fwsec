package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/saulolimabrito/edge-fwsec/internal/auth"
)

// bootstrapCmd issues a one-time credential in efw-web's state directory and
// prints it on the local console only. The file is handed to the owner of
// the directory (the efw-web service user).
func bootstrapCmd(args []string) int {
	hours := 24
	if len(args) > 0 {
		n, err := strconv.Atoi(args[0])
		if err != nil || n < 1 || n > 72 {
			fmt.Fprintln(os.Stderr, "efwctl: validity must be 1..72 hours")
			return 2
		}
		hours = n
	}
	dir := env("EFW_WEB_STATE_DIR", "/var/lib/efw-web")
	tok, err := auth.NewBootstrapToken(dir, time.Duration(hours)*time.Hour, time.Now())
	if err != nil {
		fmt.Fprintln(os.Stderr, "efwctl:", err)
		return 1
	}
	if fi, err := os.Stat(dir); err == nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			_ = os.Chown(filepath.Join(dir, "bootstrap.json"), int(st.Uid), int(st.Gid))
		}
	}
	fmt.Printf("One-time administrator credential (valid %dh, single use):\n\n    %s\n\n", hours, tok)
	fmt.Println("Open the console from a management interface and choose \"Set up administrator\".")
	fmt.Println("Using it creates the administrator, or resets the password of an existing one.")
	return 0
}
