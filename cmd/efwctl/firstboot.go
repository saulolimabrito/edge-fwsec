package main

import (
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/saulolimabrito/edge-fwsec/internal/auth"
	"github.com/saulolimabrito/edge-fwsec/internal/fsutil"
	"github.com/saulolimabrito/edge-fwsec/internal/sysinfo"
)

// firstbootCmd prepares first access once, for both install paths (ISO and
// installer): it chooses the management interface without changing any
// address, writes /etc/edge-fwsec/web.env, issues a one-time administrator
// credential and shows it on the local console through /etc/issue.d.
// It does nothing when web.env already exists, unless --force is given.
func firstbootCmd(args []string) int {
	fs := flag.NewFlagSet("firstboot", flag.ContinueOnError)
	mgmt := fs.String("mgmt-interface", "", "device that serves the console before the first configuration")
	force := fs.Bool("force", false, "rewrite web.env even if it exists")
	etc := fs.String("etc-dir", "/etc", "root of /etc (tests)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	envFile := filepath.Join(*etc, "edge-fwsec", "web.env")
	if _, err := os.Stat(envFile); err == nil && !*force {
		fmt.Println("first access already prepared:", envFile)
		return 0
	}
	ifs, err := sysinfo.Reader{}.Interfaces()
	if err != nil {
		fmt.Fprintln(os.Stderr, "efwctl:", err)
		return 1
	}
	dev, addr, err := chooseMgmt(ifs, *mgmt, defaultRouteDevice())
	if err != nil {
		fmt.Fprintln(os.Stderr, "efwctl:", err)
		return 1
	}
	body := "# Written by `efwctl firstboot`. Devices that serve the console before the\n# first confirmed configuration. Addresses are not changed by Edge FWSec.\nEFW_BOOTSTRAP_INTERFACES=" + dev + "\n"
	if err := os.MkdirAll(filepath.Dir(envFile), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "efwctl:", err)
		return 1
	}
	if err := fsutil.WriteAtomic(envFile, []byte(body), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "efwctl:", err)
		return 1
	}
	url := "https://<address of " + dev + ">/"
	if addr.IsValid() {
		h := addr.String()
		if addr.Is6() {
			h = "[" + h + "]"
		}
		url = "https://" + h + "/"
	}
	issue := fmt.Sprintf("\nEdge FWSec console: %s (management interface %s)\n", url, dev)
	webDir := env("EFW_WEB_STATE_DIR", "/var/lib/efw-web")
	if !hasUsers(webDir) {
		tok, err := auth.NewBootstrapToken(webDir, 24*time.Hour, time.Now())
		if err != nil {
			fmt.Fprintln(os.Stderr, "efwctl:", err)
			return 1
		}
		chownLikeDir(webDir, filepath.Join(webDir, "bootstrap.json"))
		issue += fmt.Sprintf("One-time administrator credential (single use, valid 24h from %s):\n  %s\nA new one: run `efwctl bootstrap` as root on this console.\n\n",
			time.Now().Format("2006-01-02 15:04"), tok)
	}
	issueFile := filepath.Join(*etc, "issue.d", "50-edge-fwsec.issue")
	if err := os.MkdirAll(filepath.Dir(issueFile), 0o755); err == nil {
		// 0600: only the console (agetty runs as root) shows it.
		_ = fsutil.WriteAtomic(issueFile, []byte(issue), 0o600)
	}
	fmt.Print(issue)
	return 0
}

func hasUsers(dir string) bool {
	fi, err := os.Stat(filepath.Join(dir, "users.json"))
	return err == nil && fi.Size() > 0
}

func chownLikeDir(dir, file string) {
	if fi, err := os.Stat(dir); err == nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			_ = os.Chown(file, int(st.Uid), int(st.Gid))
		}
	}
}

// defaultRouteDevice reads /proc/net/route for the IPv4 default route.
func defaultRouteDevice() string {
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) > 2 && f[1] == "00000000" {
			return f[0]
		}
	}
	return ""
}

// chooseMgmt picks the management device: the requested one, else the
// device of the default route, else the first physical interface with a
// global address. It never configures anything.
func chooseMgmt(ifs []sysinfo.Interface, want, defRoute string) (string, netip.Addr, error) {
	global := func(it sysinfo.Interface) netip.Addr {
		var v6 netip.Addr
		for _, a := range it.Addresses {
			if a.Scope != "global" {
				continue
			}
			p, err := netip.ParsePrefix(a.CIDR)
			if err != nil {
				continue
			}
			if p.Addr().Is4() {
				return p.Addr()
			}
			if !v6.IsValid() {
				v6 = p.Addr()
			}
		}
		return v6
	}
	byName := map[string]sysinfo.Interface{}
	var names []string
	for _, it := range ifs {
		byName[it.Name] = it
		names = append(names, it.Name)
	}
	sort.Strings(names)
	if want != "" {
		it, ok := byName[want]
		if !ok {
			return "", netip.Addr{}, fmt.Errorf("interface %q does not exist", want)
		}
		return want, global(it), nil
	}
	if it, ok := byName[defRoute]; ok && defRoute != "" {
		return defRoute, global(it), nil
	}
	for _, n := range names {
		it := byName[n]
		if it.Kind == "physical" && global(it).IsValid() {
			return n, global(it), nil
		}
	}
	for _, n := range names {
		if byName[n].Kind == "physical" {
			return n, netip.Addr{}, nil
		}
	}
	return "", netip.Addr{}, errors.New("no physical interface found; pass --mgmt-interface")
}
