#!/bin/sh
# Runs once, at first boot of the live session, as root (via systemd unit).
# Build-time hooks (0200-raptor-mode-manager.hook.chroot) can't know the
# live username in advance — live-config creates it at boot from the
# `username=` bootappend-live parameter — so group membership has to
# happen here instead.
set -e

LIVE_USER="user"

if id "$LIVE_USER" >/dev/null 2>&1; then
    usermod -aG raptor-admin "$LIVE_USER"
    echo "[raptor-firstboot] added $LIVE_USER to raptor-admin"
else
    echo "[raptor-firstboot] WARNING: expected live user '$LIVE_USER' not found — Security Center's SetMode calls will be denied by D-Bus policy until a user is manually added to raptor-admin"
fi

mkdir -p /etc/raptor-security
touch /etc/raptor-security/.firstboot-done
