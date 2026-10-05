package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Setting a variable keeps the rest of the file: a line that sets it is
// replaced, else its commented example, else it is added.
func TestSetEnvVar(t *testing.T) {
	for name, tc := range map[string]struct {
		before, newline, want string
	}{
		"no file":           {"", "\n", "GWC_SERVER=https://x.test\n"},
		"the example":       {"# The server.\n#GWC_SERVER=https://example\nGWC_LOG_FORMAT=json\n", "\n", "# The server.\nGWC_SERVER=https://x.test\nGWC_LOG_FORMAT=json\n"},
		"already set":       {"#GWC_SERVER=https://example\nGWC_SERVER=https://old.test\n", "\n", "#GWC_SERVER=https://example\nGWC_SERVER=https://x.test\n"},
		"not there":         {"GWC_LOG_FORMAT=json\n", "\n", "GWC_LOG_FORMAT=json\nGWC_SERVER=https://x.test\n"},
		"Windows lines":     {"# Settings\r\n#GWC_SERVER=\r\n", "\r\n", "# Settings\r\nGWC_SERVER=https://x.test\r\n"},
		"a longer name too": {"GWC_SERVER_FILE=/run/secret\n", "\n", "GWC_SERVER_FILE=/run/secret\nGWC_SERVER=https://x.test\n"},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "agent.env")
			if tc.before != "" {
				if err := os.WriteFile(path, []byte(tc.before), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := setEnvVar(path, "GWC_SERVER", "https://x.test", tc.newline); err != nil {
				t.Fatal(err)
			}
			got, _ := os.ReadFile(path)
			if string(got) != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
			if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
				t.Errorf("mode %v, want 0600", info.Mode().Perm())
			}
		})
	}
}

// Piped in, the token is the first line.
func TestReadTokenFromAPipe(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.WriteString(testKey + "\nignored\n")
	w.Close()
	got, err := readToken(r, os.Stderr)
	if err != nil || got != testKey {
		t.Errorf("got %q, %v", got, err)
	}
}
