// Command efwctl is the local diagnostic and recovery CLI.
//
// Stage 1 implements read-only diagnostics. Revision inspection and
// rollback-to-confirmed arrive with the policy store (stage 2/3).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/saulolimabrito/edge-fwsec/internal/nft"
	"github.com/saulolimabrito/edge-fwsec/internal/policy"
	"github.com/saulolimabrito/edge-fwsec/internal/sysinfo"
	"github.com/saulolimabrito/edge-fwsec/internal/version"
)

const usage = `usage: efwctl <command> [--json]

commands:
  version      print build version
  system       host identity and uptime
  interfaces   kernel interface state and counters

  policy validate <file|->   validate a configuration (exit 1 with problems)
  policy render <file|->     print the nftables script for a configuration
  policy check <file|->      render and ask the kernel to validate it (nft --check, no changes)

  status                     confirmed revision and revision under test (via efw-agent)
  diff <file|->              ruleset diff against the confirmed revision
  apply <file|-> [seconds]   apply with a confirmation deadline (base = confirmed)
  confirm <revision>         keep the revision under test
  rollback                   abandon the revision under test now
  history [n]                audit log
  show <revision>            print a stored configuration

  recover                    console recovery: reapply the last confirmed revision.
                             Uses efw-agent when it answers; otherwise reads the
                             store directly (root, agent stopped).

environment: EFW_SOCKET (default /run/efw/agent.sock), EFW_STATE_DIR (default /var/lib/efw)
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
	case "policy":
		os.Exit(policyCmd(os.Args[2:]))
	case "status", "diff", "apply", "confirm", "rollback", "history", "show":
		os.Exit(agentCmd(os.Args[1], os.Args[2:]))
	case "recover":
		os.Exit(recoverCmd())
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

func policyCmd(args []string) int {
	if len(args) != 2 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	var in io.Reader = os.Stdin
	if args[1] != "-" {
		f, err := os.Open(args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "efwctl:", err)
			return 1
		}
		defer f.Close()
		in = f
	}
	c, err := policy.Decode(in)
	if err != nil {
		fmt.Fprintln(os.Stderr, "efwctl:", err)
		return 1
	}
	if err := policy.Validate(c); err != nil {
		var ps policy.Problems
		if errors.As(err, &ps) {
			for _, p := range ps {
				fmt.Fprintf(os.Stderr, "%s: %s\n", p.Path, p.Message)
			}
		} else {
			fmt.Fprintln(os.Stderr, "efwctl:", err)
		}
		return 1
	}
	switch args[0] {
	case "validate":
		fmt.Println("valid")
		return 0
	case "render", "check":
		script, err := nft.Render(c)
		if err != nil {
			fmt.Fprintln(os.Stderr, "efwctl:", err)
			return 1
		}
		if args[0] == "render" {
			fmt.Print(script)
			return 0
		}
		if err := (nft.Runner{}).Check(context.Background(), script); err != nil {
			fmt.Fprintln(os.Stderr, "efwctl:", err)
			return 1
		}
		fmt.Println("kernel accepts the ruleset (not applied)")
		return 0
	default:
		fmt.Fprint(os.Stderr, usage)
		return 2
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
