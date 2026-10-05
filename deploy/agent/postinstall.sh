#!/bin/sh
# Run by the .deb and .rpm after installing. Leaves the agent off until it is
# enrolled: it needs the token from the host's page in Gryphon.
set -e
install -d -m 0755 /etc/gryphon
if [ ! -s /etc/gryphon/agent_key ]; then
	echo "Gryphon agent: installed. Give it the token from the host's page in Gryphon,"
	echo "  which also starts it:  sudo gryphon-agent enrol"
fi
# Only systemd, as root, reads agent.env. Earlier releases installed it
# readable by every user.
if [ -e /etc/gryphon/agent.env ]; then
	chmod go-rwx /etc/gryphon/agent.env
fi
# Only where systemd is running: not in a container or a chroot build.
if [ -d /run/systemd/system ]; then
	systemctl daemon-reload || true
	# An upgrade restarts an agent that was running, so it runs the new build.
	if systemctl is-active --quiet gryphon-agent; then
		systemctl restart gryphon-agent || true
	fi
fi
