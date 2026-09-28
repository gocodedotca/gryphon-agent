// Package version reports the application version, shared by the server and
// the client agent binaries.
package version

import (
	"runtime/debug"
	"strings"
)

// Override is for builds that happen outside the git checkout — the Docker
// image build excludes .git — set with:
//
//	-ldflags "-X github.com/gocodedotca/gryphon-agent/pkg/version.Override=v1.0.5"
var Override string

// Version is what footers, banners and logs show. Built inside the checkout,
// the Go toolchain stamps the version from git itself: an exact tag builds as
// that tag (1.0.4), anything past it as a pseudo-version naming the commit,
// with +dirty appended for uncommitted changes.
func Version() string {
	if Override != "" {
		return strings.TrimPrefix(Override, "v")
	}

	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}

	if v := bi.Main.Version; v != "" && v != "(devel)" {
		return strings.TrimPrefix(v, "v")
	}

	// No stamped version (an older toolchain, or built outside git):
	// the commit hash is the next best identity.
	var rev, dirty string
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			if s.Value == "true" {
				dirty = "+dirty"
			}
		}
	}
	if rev != "" {
		if len(rev) > 12 {
			rev = rev[:12]
		}
		return rev + dirty
	}
	return "unknown"
}
