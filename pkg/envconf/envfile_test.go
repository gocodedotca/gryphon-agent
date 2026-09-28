package envconf

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseEnvFile(t *testing.T) {
	path := writeTemp(t, `
# comment
GOWATCHER_DB_USER=gw
export GOWATCHER_DB_PASSWORD=secret
GOWATCHER_DOMAIN="example.com"
GOWATCHER_TIMEZONE='America/Halifax'
GOWATCHER_EMPTY=
`)
	vars, err := ParseEnvFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"GOWATCHER_DB_USER":     "gw",
		"GOWATCHER_DB_PASSWORD": "secret",
		"GOWATCHER_DOMAIN":      "example.com",
		"GOWATCHER_TIMEZONE":    "America/Halifax",
		"GOWATCHER_EMPTY":       "",
	}
	for k, w := range want {
		if got, ok := vars[k]; !ok || got != w {
			t.Errorf("%s = %q (present %v), want %q", k, got, ok, w)
		}
	}
	if len(vars) != len(want) {
		t.Errorf("parsed %d vars, want %d", len(vars), len(want))
	}
}

func TestParseEnvFileMissingIsNotAnError(t *testing.T) {
	vars, err := ParseEnvFile(filepath.Join(t.TempDir(), "nope"))
	if err != nil || vars != nil {
		t.Errorf("missing file: got (%v, %v), want (nil, nil)", vars, err)
	}
}

func TestParseEnvFileMalformedIsAnError(t *testing.T) {
	path := writeTemp(t, "this is not an assignment\n")
	if _, err := ParseEnvFile(path); err == nil {
		t.Error("malformed line parsed without error")
	}
}

func TestEnvWithFilePrecedence(t *testing.T) {
	fileVars := map[string]string{
		"GOWATCHER_DB_USER": "from-file",
		"GOWATCHER_DOMAIN":  "from-file",
	}
	env := map[string]string{"GOWATCHER_DB_USER": "from-env"}
	getenv := EnvWithFile(fileVars, func(k string) string { return env[k] })

	// The real environment wins over the file.
	if got := getenv("GOWATCHER_DB_USER"); got != "from-env" {
		t.Errorf("DB_USER = %q, want the environment's value", got)
	}
	// The file fills in what the environment does not set.
	if got := getenv("GOWATCHER_DOMAIN"); got != "from-file" {
		t.Errorf("DOMAIN = %q, want the file's value", got)
	}
	if got := getenv("GOWATCHER_UNSET"); got != "" {
		t.Errorf("UNSET = %q, want empty", got)
	}
}
