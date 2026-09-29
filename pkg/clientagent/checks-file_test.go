package clientagent

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gocodedotca/gryphon-agent/pkg/agent"
)

func fileAgeParams(path, pattern, minSize string) string {
	v := url.Values{}
	v.Set(agent.ParamPath, path)
	if pattern != "" {
		v.Set(agent.ParamPattern, pattern)
	}
	if minSize != "" {
		v.Set(agent.ParamMinSize, minSize)
	}
	return v.Encode()
}

// writeAged writes a file of size bytes last modified age ago.
func writeAged(t *testing.T, path string, size int, age time.Duration) {
	t.Helper()
	if err := os.WriteFile(path, make([]byte, size), 0o644); err != nil {
		t.Fatal(err)
	}
	when := time.Now().Add(-age)
	if err := os.Chtimes(path, when, when); err != nil {
		t.Fatal(err)
	}
}

func TestFileAge(t *testing.T) {
	watched := t.TempDir()
	outside := t.TempDir()
	backups := filepath.Join(watched, "db")
	if err := os.Mkdir(backups, 0o755); err != nil {
		t.Fatal(err)
	}
	writeAged(t, filepath.Join(backups, "monday.sql.gz"), 4096, 50*time.Hour)
	writeAged(t, filepath.Join(backups, "tuesday.sql.gz"), 2048, 3*time.Hour)
	writeAged(t, filepath.Join(backups, "notes.txt"), 10, time.Minute)
	writeAged(t, filepath.Join(watched, "empty.dump"), 0, 2*time.Hour)
	writeAged(t, filepath.Join(outside, "secret"), 100, time.Hour)
	if err := os.Mkdir(filepath.Join(watched, "nothing"), 0o755); err != nil {
		t.Fatal(err)
	}

	f := newFileWatcher([]string{watched})
	ctx := context.Background()

	t.Run("a file's age is the reading", func(t *testing.T) {
		got := f.check(ctx, fileAgeParams(filepath.Join(backups, "tuesday.sql.gz"), "", ""))
		if got.statusID != 0 || got.measurement == nil {
			t.Fatalf("got status %d, measurement %v (%s); want a reading and no verdict", got.statusID, got.measurement, got.msg)
		}
		if h := *got.measurement; h < 2.9 || h > 3.1 {
			t.Errorf("reading %g hours, want about 3", h)
		}
		if !strings.Contains(got.msg, "tuesday.sql.gz, 2 KB, modified 3 hours ago") {
			t.Errorf("message %q", got.msg)
		}
	})

	t.Run("a folder is judged by its newest matching file", func(t *testing.T) {
		got := f.check(ctx, fileAgeParams(backups, "*.sql.gz", ""))
		if got.measurement == nil || *got.measurement > 3.1 {
			t.Fatalf("got %v (%s); want tuesday's three hours", got.measurement, got.msg)
		}
		if !strings.Contains(got.msg, "newest of 2 files matching *.sql.gz: tuesday.sql.gz") {
			t.Errorf("message %q", got.msg)
		}
		// Without the pattern, the text file written a minute ago is newest.
		got = f.check(ctx, fileAgeParams(backups, "", ""))
		if got.measurement == nil || *got.measurement > 0.1 {
			t.Errorf("without a pattern: got %v (%s); want the minute-old notes.txt", got.measurement, got.msg)
		}
	})

	t.Run("missing is a problem, not unknown", func(t *testing.T) {
		for _, tc := range []struct{ path, pattern, want string }{
			{filepath.Join(watched, "gone.sql.gz"), "", "nothing at"},
			{backups, "*.tar", "no file matching *.tar"},
			{filepath.Join(watched, "nothing"), "", "no files in"},
		} {
			got := f.check(ctx, fileAgeParams(tc.path, tc.pattern, ""))
			if got.statusID != agent.StatusProblem || !strings.Contains(got.msg, tc.want) {
				t.Errorf("%s %s: got %d %q; want a problem saying %q", tc.path, tc.pattern, got.statusID, got.msg, tc.want)
			}
		}
	})

	t.Run("under the minimum size is a problem that still reads its age", func(t *testing.T) {
		got := f.check(ctx, fileAgeParams(filepath.Join(watched, "empty.dump"), "", "1024"))
		if got.statusID != agent.StatusProblem || got.measurement == nil {
			t.Fatalf("got %d %v (%s); want a problem with a reading", got.statusID, got.measurement, got.msg)
		}
		if !strings.Contains(got.msg, "empty.dump is 0 bytes, under the 1 KB minimum") {
			t.Errorf("message %q", got.msg)
		}
		// At or over it is fine.
		if got := f.check(ctx, fileAgeParams(filepath.Join(backups, "tuesday.sql.gz"), "", "2048")); got.statusID != 0 {
			t.Errorf("a file exactly the minimum size: got %d (%s)", got.statusID, got.msg)
		}
	})

	t.Run("nothing outside the watched folders is looked at", func(t *testing.T) {
		for _, path := range []string{
			filepath.Join(outside, "secret"),
			filepath.Join(watched, "..", filepath.Base(outside), "secret"),
			"relative/path",
			"",
		} {
			got := f.check(ctx, fileAgeParams(path, "", ""))
			if got.statusID != agent.StatusUnknown || got.measurement != nil {
				t.Errorf("%q: got %d %v (%s); want unknown and no reading", path, got.statusID, got.measurement, got.msg)
			}
			if strings.Contains(got.msg, "100 bytes") || strings.Contains(got.msg, "modified") {
				t.Errorf("%q: the message says something about the file: %q", path, got.msg)
			}
		}
	})

	t.Run("a link that leads outside is refused", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symbolic links need a privilege on Windows")
		}
		link := filepath.Join(watched, "escape")
		if err := os.Symlink(filepath.Join(outside, "secret"), link); err != nil {
			t.Fatal(err)
		}
		got := f.check(ctx, fileAgeParams(link, "", ""))
		if got.statusID != agent.StatusUnknown || !strings.Contains(got.msg, "leads outside") {
			t.Errorf("got %d %q; want unknown, leading outside", got.statusID, got.msg)
		}
		// And a link to a folder outside, listed as a folder's entry, is
		// passed over rather than followed.
		if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(backups, "zz.sql.gz")); err != nil {
			t.Fatal(err)
		}
		if got := f.check(ctx, fileAgeParams(backups, "*.sql.gz", "")); !strings.Contains(got.msg, "tuesday.sql.gz") {
			t.Errorf("a link in the folder was followed: %q", got.msg)
		}
	})

	t.Run("off until told where to look", func(t *testing.T) {
		got := newFileWatcher(nil).check(ctx, fileAgeParams(filepath.Join(backups, "tuesday.sql.gz"), "", ""))
		if got.statusID != agent.StatusUnknown || !strings.Contains(got.msg, "GWC_WATCH_DIRS") {
			t.Errorf("got %d %q; want unknown naming GWC_WATCH_DIRS", got.statusID, got.msg)
		}
	})
}

func TestValidateWatchDirs(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	writeAged(t, file, 1, 0)
	if err := ValidateWatchDirs([]string{dir}); err != nil {
		t.Errorf("a folder was refused: %v", err)
	}
	for _, bad := range [][]string{{file}, {filepath.Join(dir, "missing")}, {"relative"}} {
		if err := ValidateWatchDirs(bad); err == nil {
			t.Errorf("%v was accepted", bad)
		}
	}
	sep := string(filepath.ListSeparator)
	if got := SplitWatchDirs(" " + dir + sep + sep + dir + "/ "); len(got) != 2 || got[1] != dir {
		t.Errorf("SplitWatchDirs = %q", got)
	}
}
