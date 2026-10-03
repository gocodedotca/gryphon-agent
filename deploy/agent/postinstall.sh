#!/bin/sh
# Run by the .deb and .rpm after installing. Makes the access key if there is
# none, and leaves the agent off: it should not listen until the reverse proxy
# and the host in Gryphon are ready for it.
set -e
install -d -m 0755 /etc/gryphon
if [ ! -s /etc/gryphon/agent_key ]; then
	umask 077
	/usr/bin/gryphon-agent -genkey > /etc/gryphon/agent_key
	chmod 0600 /etc/gryphon/agent_key
	echo "Gryphon agent: made an access key in /etc/gryphon/agent_key."
	echo "  Paste it into the host's Agent Access Key in Gryphon, then:"
	echo "  systemctl enable --now gryphon-agent"
fi
# agent.env can hold GWC_KEY_PREVIOUS while a key is rotated, and only systemd,
# as root, reads it. Earlier releases installed it readable by every user.
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
