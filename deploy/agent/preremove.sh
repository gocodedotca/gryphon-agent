#!/bin/sh
# Run by the .deb and .rpm before removal. The key and agent.env stay, so a
# reinstall keeps matching the host in Gryphon.
#
# Both package managers also run the *old* package's copy of this during an
# upgrade, so it acts only on a real removal: the .deb passes "remove" (or
# "deconfigure"), the .rpm passes 0. On an upgrade -- "upgrade" from the .deb,
# 1 from the .rpm -- it does nothing, and postinstall.sh restarts an agent that
# was running. Stopping it here as well would leave every upgraded agent off.
set -e
case "$1" in
remove | deconfigure | 0) ;;
*) exit 0 ;;
esac
# Only where systemd is running: not in a container or a chroot build.
if [ -d /run/systemd/system ]; then
	systemctl disable --now gryphon-agent >/dev/null 2>&1 || true
fi
