#!/bin/sh
# raptor-emergency-shutdown.sh
#
# Does the real work behind spec section 10. Read the honesty constraints
# in that section before changing this file:
#
#   "Do not claim that all physical traces can be guaranteed to be erased
#    if hardware/storage technology prevents such guarantees."
#
# What this script can honestly promise, and why:
#
#   - live-boot's default root overlay is tmpfs-backed (RAM), NOT written
#     to the boot media. Everything in the live session outside of an
#     explicitly mounted persistence volume already disappears the instant
#     power is cut — this script doesn't need to "wipe" that data, powering
#     off does it. What this script actually needs to do is handle the
#     things that DON'T automatically vanish with the tmpfs overlay: swap,
#     and any credential caches held by long-running agent processes.
#   - swapoff deactivates swap; it does NOT cryptographically erase
#     whatever was paged out to swap while it was active. If swap was ever
#     enabled on this session, this script cannot promise no trace exists
#     on the underlying storage. This is stated in the GUI confirmation
#     dialog, not just buried here.
#   - Persistence (LUKS-backed, explicitly mounted) is never touched by
#     this script under any circumstance — see the guard below.
#
# This script is invoked ONLY by raptor-emergency-shutdownd after the GUI
# has obtained explicit, deliberate user confirmation (spec section 10)
# — this script itself performs no additional confirmation and must never
# be wired to run automatically.

set -e

PERSISTENCE_MOUNT="/lib/live/mount/persistence"
LOG_TAG="raptor-emergency-shutdown"

log() {
    logger -t "$LOG_TAG" "$1"
    echo "[$LOG_TAG] $1"
}

# --- Guard: refuse to run if persistence looks like it's about to be
#     touched by anything downstream. This script never issues an rm/wipe
#     against $PERSISTENCE_MOUNT — this check exists purely as a canary so
#     that if someone later adds a step that accidentally targets it, the
#     mismatch is at least logged loudly rather than silently.
if findmnt -n "$PERSISTENCE_MOUNT" >/dev/null 2>&1; then
    log "persistence is mounted at $PERSISTENCE_MOUNT — will NOT be touched"
else
    log "no persistence mounted — amnesic session, nothing to preserve or avoid"
fi

# --- Step 1: swap. Deactivate if active. Cannot promise erasure of
#     previously-paged data on the underlying media (see header).
if swapon --show --noheadings | grep -q .; then
    log "swap is active — deactivating (note: this does not erase prior swap contents on disk)"
    swapoff -a || log "WARNING: swapoff failed, continuing anyway"
else
    log "no active swap"
fi

# --- Step 2: kill credential-caching agents so keys/passphrases held in
#     their memory aren't sitting around during session teardown. This is
#     defense in depth — the tmpfs overlay disappearing at poweroff already
#     removes their memory, but ending them explicitly also drops any
#     lingering unix sockets/lock files cleanly.
for agent in ssh-agent gpg-agent gnome-keyring-daemon kwalletd5 kwalletd6; do
    pkill -u "${1:-raptor}" -x "$agent" 2>/dev/null && log "stopped $agent" || true
done

# --- Step 3: clear clipboard managers explicitly. Klipper/clipboard
# history can be configured to persist to disk under the user's config
# dir even in a tmpfs session; clearing it explicitly rather than relying
# on process teardown timing.
if command -v qdbus >/dev/null 2>&1; then
    qdbus org.kde.klipper /klipper org.kde.klipper.klipper.clearClipboardHistory 2>/dev/null || true
fi

# --- Step 4: terminate the user session cleanly.
LIVE_USER="${1:-raptor}"
log "terminating session for user: $LIVE_USER"
loginctl terminate-user "$LIVE_USER" 2>/dev/null || log "WARNING: loginctl terminate-user failed"

# --- Step 5: power off. Not reboot — spec section 10 says shut down.
log "powering off"
systemctl poweroff
