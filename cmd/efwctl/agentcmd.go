package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"strconv"
	"time"

	"github.com/saulolimabrito/edge-fwsec/internal/agent"
	"github.com/saulolimabrito/edge-fwsec/internal/nft"
	"github.com/saulolimabrito/edge-fwsec/internal/store"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func socketPath() string { return env("EFW_SOCKET", "/run/efw/agent.sock") }

func readArg(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(io.LimitReader(os.Stdin, agent.MaxRequestBytes))
	}
	return os.ReadFile(path)
}

func localAuthor() string {
	if u, err := user.Current(); err == nil {
		return "console-" + u.Username
	}
	return "console"
}

func call(req *agent.Request) (*agent.Response, int) {
	r, err := agent.Call(context.Background(), socketPath(), req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "efwctl: efw-agent unreachable at %s: %v\n(use `efwctl recover` on the console if the agent is down)\n", socketPath(), err)
		return nil, 1
	}
	if !r.OK {
		fmt.Fprintf(os.Stderr, "efwctl: %s: %s\n", r.Error.Code, r.Error.Message)
		for _, p := range r.Error.Problems {
			fmt.Fprintf(os.Stderr, "  %s: %s\n", p.Path, p.Message)
		}
		return r, 1
	}
	return r, 0
}

func printStatus(s *agent.Status) {
	fmt.Printf("confirmed revision  %d\n", s.Confirmed)
	fmt.Printf("last revision       %d\n", s.LastRevision)
	if s.Testing == nil {
		fmt.Println("under test          none")
		return
	}
	fmt.Printf("under test          %d (by %s)\n", s.Testing.Revision, s.Testing.Author)
	fmt.Printf("deadline            %s (%ds left; rolls back to %d unless confirmed)\n",
		s.Testing.Deadline.Local().Format(time.RFC3339), *s.RemainingSeconds, s.Confirmed)
}

func agentCmd(op string, args []string) int {
	switch op {
	case "status":
		r, rc := call(&agent.Request{Op: agent.OpStatus})
		if rc == 0 {
			printStatus(r.Status)
		}
		return rc
	case "diff", "apply":
		if len(args) < 1 {
			fmt.Fprint(os.Stderr, usage)
			return 2
		}
		cfg, err := readArg(args[0])
		if err != nil {
			fmt.Fprintln(os.Stderr, "efwctl:", err)
			return 1
		}
		if op == "diff" {
			r, rc := call(&agent.Request{Op: agent.OpDiff, Config: cfg})
			if rc == 0 {
				if *r.Diff == "" {
					fmt.Println("no changes")
				} else {
					fmt.Print(*r.Diff)
				}
			}
			return rc
		}
		st, rc := call(&agent.Request{Op: agent.OpStatus})
		if rc != 0 {
			return rc
		}
		base := st.Status.Confirmed
		req := &agent.Request{Op: agent.OpApply, Config: cfg, BaseRevision: &base, Author: localAuthor()}
		if len(args) > 1 {
			n, err := strconv.Atoi(args[1])
			if err != nil {
				fmt.Fprintln(os.Stderr, "efwctl: timeout must be seconds")
				return 2
			}
			req.TimeoutSeconds = n
		}
		r, rc := call(req)
		if rc == 0 {
			fmt.Printf("revision %d applied for testing\n", r.Revision)
			printStatus(r.Status)
			fmt.Printf("\nconfirm with: efwctl confirm %d\n", r.Revision)
		}
		return rc
	case "confirm":
		if len(args) != 1 {
			fmt.Fprint(os.Stderr, usage)
			return 2
		}
		n, err := strconv.Atoi(args[0])
		if err != nil {
			fmt.Fprintln(os.Stderr, "efwctl: revision must be a number")
			return 2
		}
		r, rc := call(&agent.Request{Op: agent.OpConfirm, Revision: n, Author: localAuthor()})
		if rc == 0 {
			fmt.Printf("revision %d confirmed\n", r.Revision)
		}
		return rc
	case "rollback":
		r, rc := call(&agent.Request{Op: agent.OpRollback, Author: localAuthor()})
		if rc == 0 {
			fmt.Printf("revision %d rolled back; confirmed revision %d is active\n", r.Revision, r.Status.Confirmed)
		}
		return rc
	case "history":
		n := 20
		if len(args) > 0 {
			n, _ = strconv.Atoi(args[0])
		}
		r, rc := call(&agent.Request{Op: agent.OpHistory, Limit: n})
		if rc == 0 {
			for _, e := range r.History {
				fmt.Printf("%s  %-16s rev %-4d %-28s %s\n", e.Time.Local().Format(time.DateTime), e.Action, e.Revision, e.Author, e.Result)
			}
		}
		return rc
	case "show":
		if len(args) != 1 {
			fmt.Fprint(os.Stderr, usage)
			return 2
		}
		n, _ := strconv.Atoi(args[0])
		r, rc := call(&agent.Request{Op: agent.OpGet, Revision: n})
		if rc == 0 {
			var v any
			json.Unmarshal(r.Config, &v)
			out, _ := json.MarshalIndent(v, "", "  ")
			fmt.Println(string(out))
		}
		return rc
	}
	return 2
}

// recoverCmd restores the last confirmed revision from the local console,
// through the agent when it answers, otherwise directly from the store.
func recoverCmd() int {
	if r, err := agent.Call(context.Background(), socketPath(), &agent.Request{Op: agent.OpStatus}); err == nil && r.OK {
		if r.Status.Testing == nil {
			fmt.Printf("efw-agent is running; no revision under test; confirmed revision %d is active\n", r.Status.Confirmed)
			return 0
		}
		r2, rc := call(&agent.Request{Op: agent.OpRollback, Author: localAuthor()})
		if rc == 0 {
			fmt.Printf("rolled back revision %d through efw-agent; confirmed revision %d is active\n", r2.Revision, r2.Status.Confirmed)
		}
		return rc
	}
	dir := env("EFW_STATE_DIR", "/var/lib/efw")
	st, err := store.Open(dir)
	if errors.Is(err, store.ErrLocked) {
		fmt.Fprintln(os.Stderr, "efwctl: efw-agent holds the store but does not answer; stop it (systemctl stop efw-agent) and run recover again")
		return 1
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "efwctl:", err)
		return 1
	}
	defer st.Close()
	if rev, err := st.EndTest("recover", localAuthor(), "console recovery with efw-agent down"); err != nil {
		fmt.Fprintln(os.Stderr, "efwctl:", err)
		return 1
	} else if rev != 0 {
		fmt.Printf("abandoned revision %d that was under test\n", rev)
	}
	s := st.State()
	script := nft.RemoveScript()
	if s.Confirmed != 0 {
		r, err := st.Get(s.Confirmed)
		if err == nil {
			cfg, derr := r.Decode()
			if derr == nil {
				script, err = nft.Render(cfg)
			} else {
				err = derr
			}
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "efwctl: cannot load confirmed revision:", err)
			return 1
		}
	}
	if err := (nft.Runner{}).Apply(context.Background(), script); err != nil {
		st.Audit(store.Event{Action: "recover", Revision: s.Confirmed, Author: localAuthor(), Result: err.Error()})
		fmt.Fprintln(os.Stderr, "efwctl:", err)
		return 1
	}
	st.Audit(store.Event{Action: "recover", Revision: s.Confirmed, Author: localAuthor(), Result: "ok"})
	fmt.Printf("confirmed revision %d reapplied directly (efw-agent was not running)\n", s.Confirmed)
	return 0
}
