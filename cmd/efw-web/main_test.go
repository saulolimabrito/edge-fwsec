package main

import (
	"slices"
	"testing"
)

func TestSplitList(t *testing.T) {
	if got := splitList(" mgmt0, ,eth2 "); !slices.Equal(got, []string{"mgmt0", "eth2"}) {
		t.Fatalf("%v", got)
	}
	if splitList("") != nil {
		t.Fatal("empty")
	}
}

func TestCertHostsIncludesLoopback(t *testing.T) {
	h := certHosts()
	if !slices.Contains(h, "localhost") || !slices.Contains(h, "127.0.0.1") {
		t.Fatalf("%v", h)
	}
}
