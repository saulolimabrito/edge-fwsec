package sysinfo

import (
	"bufio"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// System is host identity and uptime. Unknown values are empty/nil.
type System struct {
	Hostname      string   `json:"hostname"`
	OSName        string   `json:"os_name"`
	OSVersion     string   `json:"os_version"`
	OSID          string   `json:"os_id"`
	Kernel        string   `json:"kernel"`
	Arch          string   `json:"arch"`
	UptimeSeconds *float64 `json:"uptime_seconds"`
}

// SystemInfo reads hostname, /etc/os-release, kernel release and uptime.
func (r Reader) SystemInfo(etcRoot string) System {
	if etcRoot == "" {
		etcRoot = "/etc"
	}
	s := System{Arch: runtime.GOARCH}
	s.Hostname, _ = os.Hostname()
	osr := parseOSRelease(filepath.Join(etcRoot, "os-release"))
	s.OSName, s.OSVersion, s.OSID = osr["PRETTY_NAME"], osr["VERSION_ID"], osr["ID"]
	if k, ok := readFile(filepath.Join(r.procRoot(), "sys", "kernel", "osrelease")); ok {
		s.Kernel = k
	}
	if u, ok := readFile(filepath.Join(r.procRoot(), "uptime")); ok {
		if f := strings.Fields(u); len(f) > 0 {
			if v, err := strconv.ParseFloat(f[0], 64); err == nil {
				s.UptimeSeconds = &v
			}
		}
	}
	return s
}

func (r Reader) procRoot() string {
	if r.ProcRoot == "" {
		return "/proc"
	}
	return r.ProcRoot
}

func readFile(p string) (string, bool) {
	b, err := os.ReadFile(p)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(b)), true
}

// parseOSRelease implements the os-release(5) KEY=value format with
// optional single or double quoting.
func parseOSRelease(p string) map[string]string {
	m := map[string]string{}
	f, err := os.Open(p)
	if err != nil {
		return m
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		m[k] = v
	}
	return m
}
