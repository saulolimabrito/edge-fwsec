package textdiff

import "testing"

func TestLines(t *testing.T) {
	if Lines("a\nb\n", "a\nb\n", 1) != "" {
		t.Fatal("equal inputs must give empty diff")
	}
	got := Lines("a\nb\nc\nd\ne\nf\n", "a\nb\nX\nd\ne\nf\n", 1)
	want := "  b\n- c\n+ X\n  d\n"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	got = Lines("1\n2\n3\n4\n5\n6\n7\n", "0\n1\n2\n3\n4\n5\n6\n", 0)
	if got != "+ 0\n@@\n- 7\n" {
		t.Fatalf("got %q", got)
	}
	if Lines("", "x\n", 2) != "+ x\n" {
		t.Fatal("from empty")
	}
}
