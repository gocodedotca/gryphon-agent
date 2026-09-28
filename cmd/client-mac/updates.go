//go:build darwin

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/gocodedotca/gryphon-agent/pkg/version"
)

// releasesURL is where the latest release is asked for. GitHub's answer for
// a public repository needs no token.
const releasesURL = "https://api.github.com/repos/gocodedotca/gryphon-agent/releases/latest"

// watchForUpdates asks once shortly after launch, then once a day, and shows
// the menu item when a release newer than this build exists. It never
// downloads or installs anything: the item opens the release page, and the
// person decides. A development build (dev-<commit>) is never compared.
func (a *app) watchForUpdates() {
	current := version.Version()
	if !strings.HasPrefix(current, "v") && !isRelease(current) {
		return
	}
	time.Sleep(15 * time.Second)
	for {
		if tag, url, ok := latestRelease(); ok && newer(tag, current) {
			a.updateURL = url
			a.update.SetTitle("Update available: " + tag)
			a.update.Show()
			a.log.Info("a newer release is available", "release", tag)
		}
		time.Sleep(24 * time.Hour)
	}
}

func (a *app) openUpdate() {
	if a.updateURL == "" {
		return
	}
	if err := exec.Command("open", a.updateURL).Run(); err != nil {
		a.log.Error("cannot open the release page", "error", err)
	}
}

// latestRelease is the newest release's tag and page.
func latestRelease() (tag, url string, ok bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, releasesURL, nil)
	if err != nil {
		return "", "", false
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", appName)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", false
	}
	var release struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 1<<20)).Decode(&release); err != nil {
		return "", "", false
	}
	return release.TagName, release.HTMLURL, release.TagName != ""
}

// isRelease reports whether a version string is a plain release number.
func isRelease(v string) bool {
	_, ok := parseVersion(v)
	return ok
}

// newer reports whether tag is a later release than current.
func newer(tag, current string) bool {
	a, ok := parseVersion(tag)
	if !ok {
		return false
	}
	b, ok := parseVersion(current)
	if !ok {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return false
}

// parseVersion reads "v1.2.3" or "1.2.3" into its three numbers. Anything
// else -- a pseudo-version, a dev build, a tag with a suffix -- is not a
// release and compares as nothing.
func parseVersion(v string) ([3]int, bool) {
	var out [3]int
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}
