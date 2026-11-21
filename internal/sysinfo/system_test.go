package sysinfo

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSystemInfoFromFakeRoots(t *testing.T) {
	etc, proc := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(etc, "os-release"), []byte(
		"NAME=\"Rocky Linux\"\nVERSION_ID=\"10.3\"\nID=\"rocky\"\nPRETTY_NAME='Rocky Linux 10.3 (Red Quartz)'\n# c\n"), 0o644)
	os.MkdirAll(filepath.Join(proc, "sys", "kernel"), 0o755)
	os.WriteFile(filepath.Join(proc, "sys", "kernel", "osrelease"), []byte("6.12.0\n"), 0o644)
	os.WriteFile(filepath.Join(proc, "uptime"), []byte("123.45 99.0\n"), 0o644)
	s := Reader{ProcRoot: proc}.SystemInfo(etc)
	if s.OSID != "rocky" || s.OSVersion != "10.3" || s.OSName != "Rocky Linux 10.3 (Red Quartz)" {
		t.Fatalf("%+v", s)
	}
	if s.Kernel != "6.12.0" || s.UptimeSeconds == nil || *s.UptimeSeconds != 123.45 {
		t.Fatalf("%+v", s)
	}
	empty := Reader{ProcRoot: t.TempDir()}.SystemInfo(t.TempDir())
	if empty.UptimeSeconds != nil || empty.OSID != "" {
		t.Fatalf("missing files must yield empty values: %+v", empty)
	}
}
