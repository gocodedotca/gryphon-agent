package clientagent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gocodedotca/gryphon-agent/pkg/agent"
	"github.com/gocodedotca/gryphon-agent/pkg/phrase"
)

// The file-age check: how long ago a file was last written -- a backup, a
// dump, an export -- or, for a folder, the newest file in it.
//
// It is the other half of a heartbeat. A heartbeat hears from the job; this
// looks at what the job left behind, so it needs no change to the job and
// catches the job that ran, said it succeeded, and wrote nothing. The age is a
// reading, graded on the server against the check's thresholds like disk
// space. A file that is missing, or smaller than the check's minimum, is a
// problem outright: no threshold makes a missing backup acceptable.
//
// Where it may look is decided on this machine. The agent is started with the
// folders it may look in (GWC_WATCH_DIRS), and a path outside them is refused
// before anything is asked of the file system -- otherwise every Gryphon login,
// and every copy of the access key, could ask this machine whether any file
// exists and how big it is. Symbolic links are followed only as far as they
// stay inside those folders.

const (
	// maxFolderEntries bounds how much of a folder is read looking for its
	// newest file, so a folder of a million files costs a bounded amount and
	// says so rather than holding a check slot until the deadline.
	maxFolderEntries = 100_000
	folderBatch      = 1024
)

type fileWatcher struct {
	dirs []string
}

func newFileWatcher(dirs []string) *fileWatcher {
	return &fileWatcher{dirs: dirs}
}

// ValidateWatchDirs reports what is wrong with the folders a file-age check
// may look in, or nil. Each must exist and be a folder. The agent checks
// again on every run; this is for refusing a mistake at startup.
func ValidateWatchDirs(dirs []string) error {
	for _, dir := range dirs {
		if !filepath.IsAbs(dir) {
			return fmt.Errorf("watched folder %s is not an absolute path", dir)
		}
		info, err := os.Stat(dir)
		if err != nil {
			return fmt.Errorf("watched folder: %w", err)
		}
		if !info.IsDir() {
			return fmt.Errorf("watched folder %s is not a folder", dir)
		}
	}
	return nil
}

// SplitWatchDirs reads GWC_WATCH_DIRS: folders separated the way this
// system separates PATH -- colons on Unix, semicolons on Windows.
func SplitWatchDirs(s string) []string {
	var out []string
	for _, d := range filepath.SplitList(s) {
		if d = strings.TrimSpace(d); d != "" {
			out = append(out, filepath.Clean(d))
		}
	}
	return out
}

// fileUnknown and fileProblem answer with a message written with phrase.T
// at the call site.
func fileUnknown(msg string) result {
	return result{statusID: agent.StatusUnknown, msg: msg}
}

func fileProblem(msg string) result {
	return result{statusID: agent.StatusProblem, msg: msg}
}

// within reports whether path is root or something under it. filepath.Rel
// compares case-insensitively on Windows, as the file system does.
func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil || filepath.IsAbs(rel) {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// allowed reports whether path is inside a watched folder, spelled either as
// the folder was configured or as its links resolve -- /var and /private/var
// on a Mac are the same place.
func (f *fileWatcher) allowed(path string) bool {
	for _, dir := range f.dirs {
		if within(dir, path) {
			return true
		}
		if resolved, err := filepath.EvalSymlinks(dir); err == nil && within(resolved, path) {
			return true
		}
	}
	return false
}

func (f *fileWatcher) check(ctx context.Context, params string) result {
	values, err := url.ParseQuery(params)
	if err != nil {
		return unreadableSettings(err)
	}
	if len(f.dirs) == 0 {
		return fileUnknown(phrase.T("file checks are turned off on this agent: start it with GWC_WATCH_DIRS naming the folders it may look in"))
	}

	raw := strings.TrimSpace(values.Get(agent.ParamPath))
	if raw == "" || !filepath.IsAbs(raw) {
		return fileUnknown(phrase.T("{path} is not an absolute path", "path", strconv.Quote(raw)))
	}
	path := filepath.Clean(raw)
	// Before the file system is asked anything, so a path outside says
	// nothing about what is there.
	if !f.allowed(path) {
		return fileUnknown(phrase.T("{path} is not inside a folder this agent watches ({dirs})",
			"path", path, "dirs", strings.Join(f.dirs, string(filepath.ListSeparator))))
	}

	pattern := strings.TrimSpace(values.Get(agent.ParamPattern))
	if pattern != "" {
		if _, err := filepath.Match(pattern, ""); err != nil || strings.ContainsRune(pattern, filepath.Separator) {
			return fileUnknown(phrase.T("{pattern} is not a file name pattern", "pattern", strconv.Quote(pattern)))
		}
	}
	var minSize int64
	if s := strings.TrimSpace(values.Get(agent.ParamMinSize)); s != "" {
		if minSize, err = strconv.ParseInt(s, 10, 64); err != nil || minSize < 0 {
			return fileUnknown(phrase.T("{value} is not a size in bytes", "value", strconv.Quote(s)))
		}
	}

	resolved, err := filepath.EvalSymlinks(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fileProblem(phrase.T("nothing at {path}", "path", path))
	case err != nil:
		return fileUnknown(phrase.T("cannot read {path}: {err}", "path", path, "err", err))
	case !f.allowed(resolved):
		return fileUnknown(phrase.T("{path} leads outside the folders this agent watches", "path", path))
	}

	info, err := os.Stat(resolved)
	if err != nil {
		return fileUnknown(phrase.T("cannot read {path}: {err}", "path", path, "err", err))
	}

	// For a folder, the newest file in it, and how many it was the newest
	// of. Each wording is a sentence of its own: with a count of one or
	// many, with the pattern or without it.
	name, isFolder, count := filepath.Base(path), info.IsDir(), 0
	if isFolder {
		newest, n, err := newestFile(ctx, resolved, pattern)
		if err != nil {
			return fileUnknown(phrase.T("cannot read the folder {path}: {err}", "path", path, "err", err))
		}
		if newest == nil {
			if pattern != "" {
				return fileProblem(phrase.T("no file matching {pattern} in {path}", "pattern", pattern, "path", path))
			}
			return fileProblem(phrase.T("no files in {path}", "path", path))
		}
		info, name, count = newest, newest.Name(), n
	} else if !info.Mode().IsRegular() {
		return fileUnknown(phrase.T("{path} is not a file or a folder", "path", path))
	}

	age := time.Since(info.ModTime())
	if age < 0 {
		// Written by a clock ahead of this one: it is new.
		age = 0
	}
	hours := math.Round(age.Hours()*100) / 100
	args := []any{
		"name", name, "size", agent.FormatSize(info.Size()), "age", agent.HumanDuration(age),
		"count", count, "pattern", pattern, "min", agent.FormatSize(minSize),
	}

	if minSize > 0 && info.Size() < minSize {
		// A reading and a verdict both: the age still charts, and the size
		// makes it a problem whatever the age is.
		var msg string
		switch {
		case !isFolder:
			msg = phrase.T("{name} is {size}, under the {min} minimum (modified {age} ago)", args...)
		case count == 1 && pattern == "":
			msg = phrase.T("newest of 1 file: {name} is {size}, under the {min} minimum (modified {age} ago)", args...)
		case count == 1:
			msg = phrase.T("newest of 1 file matching {pattern}: {name} is {size}, under the {min} minimum (modified {age} ago)", args...)
		case pattern == "":
			msg = phrase.T("newest of {count} files: {name} is {size}, under the {min} minimum (modified {age} ago)", args...)
		default:
			msg = phrase.T("newest of {count} files matching {pattern}: {name} is {size}, under the {min} minimum (modified {age} ago)", args...)
		}
		res := measured(hours, msg, "")
		res.statusID = agent.StatusProblem
		return res
	}

	var msg string
	switch {
	case !isFolder:
		msg = phrase.T("{name}, {size}, modified {age} ago", args...)
	case count == 1 && pattern == "":
		msg = phrase.T("newest of 1 file: {name}, {size}, modified {age} ago", args...)
	case count == 1:
		msg = phrase.T("newest of 1 file matching {pattern}: {name}, {size}, modified {age} ago", args...)
	case pattern == "":
		msg = phrase.T("newest of {count} files: {name}, {size}, modified {age} ago", args...)
	default:
		msg = phrase.T("newest of {count} files matching {pattern}: {name}, {size}, modified {age} ago", args...)
	}
	return measured(hours, msg, "")
}

// newestFile is the most recently modified regular file directly in dir whose
// name matches pattern (every name, when pattern is empty), and how many
// matched. Links and subfolders are passed over: a link could lead anywhere,
// and a subfolder's own date says when something in it was added or removed,
// not when a file was written.
func newestFile(ctx context.Context, dir, pattern string) (fs.FileInfo, int, error) {
	d, err := os.Open(dir)
	if err != nil {
		return nil, 0, err
	}
	defer d.Close()

	var newest fs.FileInfo
	count, seen := 0, 0
	for {
		entries, err := d.ReadDir(folderBatch)
		for _, e := range entries {
			seen++
			if !e.Type().IsRegular() {
				continue
			}
			if pattern != "" {
				if ok, _ := filepath.Match(pattern, e.Name()); !ok {
					continue
				}
			}
			info, err := e.Info()
			if err != nil {
				// Removed between the listing and now.
				continue
			}
			count++
			if newest == nil || info.ModTime().After(newest.ModTime()) {
				newest = info
			}
		}
		if errors.Is(err, io.EOF) || len(entries) == 0 {
			return newest, count, nil
		}
		if err != nil {
			return nil, 0, err
		}
		if seen >= maxFolderEntries {
			return nil, 0, phrase.Errorf("it has more than {n} entries; point the check at a file, or a smaller folder", "n", maxFolderEntries)
		}
		if ctx.Err() != nil {
			return nil, 0, ctx.Err()
		}
	}
}
