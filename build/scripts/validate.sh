#!/usr/bin/env bash
set -euo pipefail

ERRORS=0

echo "==> [1/4] Enforcing & Verifying Executable Permissions..."
chmod +x build/config/includes.chroot/usr/local/bin/* 2>/dev/null || true
chmod +x build/config/hooks/*.hook.chroot 2>/dev/null || true

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

if [ "$ERRORS" -gt 0 ]; then
  echo "[FAIL] Validation failed with $ERRORS error(s)."
  exit 1
fi
echo "[SUCCESS] All pre-build checks passed successfully."
