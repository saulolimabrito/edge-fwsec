package nft

import (
	"net/netip"
	"testing"
)

func mustPrefixes(t *testing.T, s []string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, len(s))
	for i, x := range s {
		out[i] = netip.MustParsePrefix(x)
	}
	return out
}
