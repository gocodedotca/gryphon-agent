package envconf

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// ParseEnvFile reads a KEY=value file in the shape of .env.example: one
// assignment per line, blank lines and #-comment lines ignored, an optional
// "export " prefix tolerated so the same file can be sourced by a shell, and
// matching single or double quotes around a value stripped.
//
// A missing file is not an error -- the file is optional -- and reports
// (nil, nil). A present but unreadable or malformed file is an error: half a
// configuration silently applied is worse than none.
func ParseEnvFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("envconf: %s: %w", path, err)
	}
	defer f.Close()

	vars := make(map[string]string)
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")

		key, value, found := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !found || key == "" || strings.ContainsAny(key, " \t") {
			return nil, fmt.Errorf("envconf: %s:%d: not a KEY=value line", path, lineNo)
		}

		value = strings.TrimSpace(value)
		if len(value) >= 2 {
			if (value[0] == '"' && value[len(value)-1] == '"') ||
				(value[0] == '\'' && value[len(value)-1] == '\'') {
				value = value[1 : len(value)-1]
			}
		}
		vars[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("envconf: %s: %w", path, err)
	}
	return vars, nil
}

// EnvWithFile layers a parsed env file underneath a getenv function: the real
// environment wins, the file fills in what it does not set. That keeps the
// conventional precedence -- defaults < .env < environment < flags -- so a
// variable exported in the shell or set by an orchestrator is never clobbered
// by a file that happens to be in the working directory.
func EnvWithFile(vars map[string]string, getenv func(string) string) func(string) string {
	if len(vars) == 0 {
		return getenv
	}
	return func(name string) string {
		if v := getenv(name); v != "" {
			return v
		}
		return vars[name]
	}
}
