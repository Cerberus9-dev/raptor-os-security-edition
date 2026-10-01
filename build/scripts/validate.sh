#!/usr/bin/env bash
set -euo pipefail

ERRORS=0

echo "==> [1/4] Enforcing & Verifying Executable Permissions..."
chmod +x build/config/includes.chroot/usr/local/bin/* 2>/dev/null || true
chmod +x build/config/hooks/*.hook.chroot 2>/dev/null || true
chmod +x build/config/includes.chroot/lib/live/config/* 2>/dev/null || true

for script in build/config/includes.chroot/usr/local/bin/*; do
  if [ -f "$script" ] && [ ! -x "$script" ]; then
    echo "  [ERROR] Failed to set executable bit: $script"
    ERRORS=$((ERRORS + 1))
  fi
done

for hook in build/config/hooks/*.hook.chroot; do
  if [ -f "$hook" ] && [ ! -x "$hook" ]; then
    echo "  [ERROR] Failed to set hook executable bit: $hook"
    ERRORS=$((ERRORS + 1))
  fi
done

echo "==> [2/4] Validating Script & Policy Syntax..."
for sh_file in build/config/includes.chroot/usr/local/bin/*; do
  if file "$sh_file" | grep -q "POSIX shell script"; then
    bash -n "$sh_file" || ERRORS=$((ERRORS + 1))
  fi
done

POLICIES_JSON="build/config/includes.chroot/etc/librewolf/policies/policies.json"
if [ -f "$POLICIES_JSON" ]; then
  python3 -m json.tool "$POLICIES_JSON" >/dev/null 2>&1 || ERRORS=$((ERRORS + 1))
fi

echo "==> [3/4] Checking Essential System Configurations & Polkit Rules..."
if [ ! -f "build/config/includes.chroot/etc/nftables.conf" ]; then
  echo "  [ERROR] Missing firewall config: build/config/includes.chroot/etc/nftables.conf"
  ERRORS=$((ERRORS + 1))
fi

if [ ! -f "build/config/includes.chroot/etc/systemd/system/raptor-sdmem.service" ]; then
  echo "  [ERROR] Missing RAM wipe service unit: build/config/includes.chroot/etc/systemd/system/raptor-sdmem.service"
  ERRORS=$((ERRORS + 1))
fi

POLKIT_RULE="build/config/includes.chroot/etc/polkit-1/rules.d/50-raptor-mode-manager.rules"
if [ ! -f "$POLKIT_RULE" ]; then
  echo "  [ERROR] Missing PolicyKit rule file: $POLKIT_RULE"
  ERRORS=$((ERRORS + 1))
fi

# Check for desktop database hook
if [ ! -f "build/config/hooks/0220-raptor-desktop-database.hook.chroot" ]; then
  echo "  [ERROR] Missing desktop database hook: build/config/hooks/0220-raptor-desktop-database.hook.chroot"
  ERRORS=$((ERRORS + 1))
fi

# Check for whiskermenu config
if [ ! -f "build/config/includes.chroot/etc/xdg/xfce4/panel/whiskermenu-1.rc" ]; then
  echo "  [ERROR] Missing whiskermenu config: build/config/includes.chroot/etc/xdg/xfce4/panel/whiskermenu-1.rc"
  ERRORS=$((ERRORS + 1))
fi

# Check for loop over live-config hooks: live-config only runs EXECUTABLE
# components under /lib/live/config — a 0644 file is silently skipped and the
# desktop comes up stock. Enforced here + `chmod +x` one stage above.
for lc in build/config/includes.chroot/lib/live/config/*; do
  if [ -f "$lc" ] && [ ! -x "$lc" ]; then
    echo "  [ERROR] live-config component not executable (never runs): $lc"
    ERRORS=$((ERRORS + 1))
  fi
done

# skel-copy backup service MUST be enabled: the primary mechanism is the
# 0990 live-config hook; if that ever gets skipped the multi-user.target
# symlink below is the real-userspace safety net that makes the desktop
# theme apply. If it goes missing the two mechanisms silently diverge.
if [ ! -e "build/config/includes.chroot/etc/systemd/system/multi-user.target.wants/raptor-copy-skel.service" ]; then
  echo "  [ERROR] raptor-copy-skel.service not enabled (missing multi-user.target.wants symlink)"
  ERRORS=$((ERRORS + 1))
fi

# The per-user autostart copies must exist so the Security Center and
# welcome dialog come up automatically regardless of which skel took.
for skel_rc in \
    "build/config/includes.chroot/etc/xdg/autostart/raptor-control-center.desktop" \
    "build/config/includes.chroot/etc/skel/.config/autostart/raptor-control-center.desktop" \
    "build/config/includes.chroot/etc/skel/.config/xfce4/panel/whiskermenu-1.rc" \
    "build/config/includes.chroot/etc/skel/.config/xfce4/xfconf/xfce-perchannel-xml/xsettings.xml"; do
  if [ ! -f "$skel_rc" ]; then
    echo "  [ERROR] Missing skel/autostart payload: $skel_rc"
    ERRORS=$((ERRORS + 1))
  fi
done

# Check for raptor-security icon
if [ ! -f "build/config/includes.chroot/usr/share/icons/hicolor/48x48/apps/raptor-security.svg" ]; then
  echo "  [ERROR] Missing raptor-security icon: build/config/includes.chroot/usr/share/icons/hicolor/48x48/apps/raptor-security.svg"
  ERRORS=$((ERRORS + 1))
fi

echo "==> [4/4] Checking Package List Isolation..."
EXTRA_LISTS=$(find build/config/package-lists/ -type f ! -name 'raptor-security.list.chroot' | wc -l)
if [ "$EXTRA_LISTS" -gt 0 ]; then
  echo "  [ERROR] Redundant package list files found in build/config/package-lists/"
  ERRORS=$((ERRORS + 1))
fi

# A package list duplicated anywhere else (notably the repo root) is a trap:
# live-build only ever reads build/config/package-lists/, so the copy nobody
# reads quietly drifts out of sync and then gets edited instead of the real
# one. This repo carried exactly that — a root-level raptor-security.list.chroot
# missing librewolf/xfce4-whiskermenu-plugin/greybird-gtk-theme/
# lightdm-gtk-greeter/syslinux-utils. Catch it before it comes back.
STRAY_LISTS=$(find . -path ./.git -prune -o -type f -name '*.list.chroot' \
  ! -path './build/config/package-lists/*' ! -path './build/config/archives/*' -print)
if [ -n "$STRAY_LISTS" ]; then
  echo "  [ERROR] Package list outside build/config/package-lists/ (dead copy — live-build never reads it):"
  echo "$STRAY_LISTS" | sed 's/^/          /'
  ERRORS=$((ERRORS + 1))
fi

# The systemd init packages must be pinned in the real list, otherwise
# live-build's live-packages stage falls back to the hard-banned sysvinit path.
LIST="build/config/package-lists/raptor-security.list.chroot"
if ! grep -qx 'systemd-sysv' "$LIST" 2>/dev/null; then
  echo "  [ERROR] $LIST does not pin systemd-sysv"
  ERRORS=$((ERRORS + 1))
fi
if ! grep -qx 'live-config-systemd' "$LIST" 2>/dev/null; then
  echo "  [ERROR] $LIST does not pin live-config-systemd"
  ERRORS=$((ERRORS + 1))
fi

# live-boot is what makes the initramfs honour `boot=live`. Without it the
# image builds cleanly and then panics at boot with
# "VFS: Unable to mount root fs on unknown-block(0,0)".
if ! grep -qx 'live-boot' "$LIST" 2>/dev/null; then
  echo "  [ERROR] $LIST does not pin live-boot (image would not boot)"
  ERRORS=$((ERRORS + 1))
fi

if [ "$ERRORS" -gt 0 ]; then
  echo "[FAIL] Validation failed with $ERRORS error(s)."
  exit 1
fi
echo "[SUCCESS] All pre-build checks passed successfully."
