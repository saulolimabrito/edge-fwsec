// Command efwctl is the local diagnostic and recovery CLI.
//
// Stage 1 implements read-only diagnostics. Revision inspection and
// rollback-to-confirmed arrive with the policy store (stage 2/3).
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/saulolimabrito/edge-fwsec/internal/sysinfo"
	"github.com/saulolimabrito/edge-fwsec/internal/version"
)

const usage = `usage: efwctl <command> [--json]

commands:
  version      print build version
  system       host identity and uptime
  interfaces   kernel interface state and counters
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	asJSON := len(os.Args) > 2 && os.Args[2] == "--json"
	r := sysinfo.Reader{}
	switch os.Args[1] {
	case "version":
		fmt.Printf("efwctl %s (%s, %s)\n", version.Version, version.Commit, version.Date)
	case "system":
		emit(asJSON, r.SystemInfo(""), func() {
			s := r.SystemInfo("")
			fmt.Printf("host     %s\nos       %s\nkernel   %s\narch     %s\n", s.Hostname, s.OSName, s.Kernel, s.Arch)
		})
	case "interfaces":
		ifs, err := r.Interfaces()
		if err != nil {
			fmt.Fprintln(os.Stderr, "efwctl:", err)
			os.Exit(1)
		}
		emit(asJSON, ifs, func() {
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "IDX\tNAME\tKIND\tSTATE\tMTU\tADDRESSES")
			for _, it := range ifs {
				addrs := ""
				for i, a := range it.Addresses {
					if i > 0 {
						addrs += " "
					}
					addrs += a.CIDR
				}
				fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%d\t%s\n", it.Index, it.Name, it.Kind, it.OperState, it.MTU, addrs)
			}
			tw.Flush()
		})
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

func emit(asJSON bool, v any, text func()) {
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(v)
		return
	}
	text()
}
