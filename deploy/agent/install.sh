#!/bin/sh
# Installs or updates the Gryphon client agent on Linux from a GitHub release,
# checking the download against the release's SHA256SUMS before using it.
#
#   curl -fsSLO https://raw.githubusercontent.com/gocodedotca/gryphon-agent/main/deploy/agent/install.sh
#   less install.sh          # read it first
#   sudo sh install.sh       # latest release
#   sudo sh install.sh v1.0.9
#
# A machine with apt or dnf is better served by the .deb or .rpm on the same
# release page, which carry the same files.
set -eu

REPO="gocodedotca/gryphon-agent"
VERSION="${1:-}"

fail() { echo "install.sh: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "run as root (sudo sh install.sh)"
[ "$(uname -s)" = "Linux" ] || fail "this script is for Linux; on a Mac use the Gryphon Agent app"
command -v curl >/dev/null || fail "curl is needed"
command -v sha256sum >/dev/null || fail "sha256sum is needed"

case "$(uname -m)" in
	x86_64 | amd64) ARCH=amd64 ;;
	aarch64 | arm64) ARCH=arm64 ;;
	*) fail "no build for $(uname -m)" ;;
esac

if [ -z "$VERSION" ]; then
	VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" |
		sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)
	[ -n "$VERSION" ] || fail "cannot find the latest release"
fi
NUMBER="${VERSION#v}"
ARCHIVE="gowatcher-client_${NUMBER}_linux_${ARCH}.tar.gz"
BASE="https://github.com/$REPO/releases/download/$VERSION"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

echo "Downloading $ARCHIVE ($VERSION)"
curl -fsSLO "$BASE/$ARCHIVE"
curl -fsSLO "$BASE/SHA256SUMS"
grep " $ARCHIVE\$" SHA256SUMS > expected || fail "$ARCHIVE is not in SHA256SUMS"
sha256sum -c expected >/dev/null || fail "checksum mismatch: not installing"
tar -xzf "$ARCHIVE"

install -m 0755 gowatcher-client /usr/bin/gowatcher-client
install -m 0644 deploy/agent/gryphon-agent.service /etc/systemd/system/gryphon-agent.service
install -d -m 0755 /etc/gryphon
[ -e /etc/gryphon/agent.env ] || install -m 0644 deploy/agent/agent.env /etc/gryphon/agent.env
sh deploy/agent/postinstall.sh

echo "Installed $(/usr/bin/gowatcher-client -version 2>/dev/null || echo "$VERSION")."
