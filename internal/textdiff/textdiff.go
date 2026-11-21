// Package textdiff produces a compact line diff for review screens.
package textdiff

import (
	"fmt"
	"strings"
)

// Lines returns a unified-style diff of a and b ("-" removed, "+" added,
// " " context) with ctx lines of context around changes. Empty when equal.
func Lines(a, b string, ctx int) string {
	x, y := split(a), split(b)
	n, m := len(x), len(y)
	// LCS table; rulesets are a few hundred lines, so O(n*m) is fine.
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if x[i] == y[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	type op struct {
		k byte
		s string
	}
	var ops []op
	i, j := 0, 0
	for i < n || j < m {
		switch {
		case i < n && j < m && x[i] == y[j]:
			ops = append(ops, op{' ', x[i]})
			i++
			j++
		case i < n && (j == m || lcs[i+1][j] >= lcs[i][j+1]):
			ops = append(ops, op{'-', x[i]})
			i++
		default:
			ops = append(ops, op{'+', y[j]})
			j++
		}
	}
	keep := make([]bool, len(ops))
	changed := false
	for k, o := range ops {
		if o.k != ' ' {
			changed = true
			for d := max(0, k-ctx); d <= min(len(ops)-1, k+ctx); d++ {
				keep[d] = true
			}
		}
	}
	if !changed {
		return ""
	}
	var sb strings.Builder
	gap := false
	for k, o := range ops {
		if !keep[k] {
			gap = true
			continue
		}
		if gap && sb.Len() > 0 {
			sb.WriteString("@@\n")
		}
		gap = false
		fmt.Fprintf(&sb, "%c %s\n", o.k, o.s)
	}
	return sb.String()
}

func split(s string) []string {
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}
