//go:build darwin

package main

import "testing"

func TestNewerRelease(t *testing.T) {
	cases := []struct {
		tag, current string
		want         bool
	}{
		{"v1.0.7", "1.0.6", true},
		{"v1.0.7", "v1.0.7", false},
		{"v1.0.7", "1.0.8", false},
		{"v2.0.0", "1.9.9", true},
		{"v1.0.7", "dev-abc123", false},
		{"v1.0.7", "1.0.6-0.20260913211146-f77a85fa150b", false},
		{"nightly", "1.0.0", false},
	}
	for _, c := range cases {
		if got := newer(c.tag, c.current); got != c.want {
			t.Errorf("newer(%q, %q) = %v, want %v", c.tag, c.current, got, c.want)
		}
	}
}
