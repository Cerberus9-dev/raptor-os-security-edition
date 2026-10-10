# Raptor OS Security Edition

**Debian 12 (Bookworm) live ISO — Kodachi-style security desktop.**

## Status
- ✅ **Theme applies** — Papirus-Dark + Greybird-dark, custom panel, whisker menu
- ✅ **Apps findable** — Whisker menu with Raptor categories (Recon/Web/Passwords/Forensics), 60+ pre-installed tools
- ✅ **Dashboard auto-boots** — Security Center opens on login (immediate, ≤3s probe, crash relaunch)
- ✅ **Kodachi-style live graphs** — CPU, RAM, Net RX/TX (1s sampling, 60-sample cairo sparklines)
- ✅ **Larger app suite** — 60+ Bookworm-only tools (no Kali packages)
- ✅ **Fixed modes** — Secure / Hardened / Lockdown with nftables, DNS-over-Tor, kill-switch
- ✅ **Faster boot** — Masked bluetooth, ModemManager, avahi, CUPS, packagekit, fwupd, smartd, tty2-6; `Storage=volatile` journald
- ✅ **Hardened boot** — No panic params; `boot=live config components username=user autologin ignore_uuid live-media-timeout=30`
- ✅ **Visible boot** — `quiet` removed from all kernel cmdlines
- ✅ **Diagnostics** — `Ctrl+Alt+F2` → `cat /home/user/raptor-debug.log` (services, D-Bus, skel, dashboard log)
- ✅ **Weekly updates** — Scheduled rebuild + Internet Archive publish (IA gate via env, not secrets)

## Boot
BIOS (isolinux) and UEFI (GRUB) both use:
```
boot=live config components username=user autologin ignore_uuid live-media-timeout=30
```
Fail-safe entry adds `noapic noapm nodma nomce nolapic nosmp`.

## Build
```bash
# Local build (requires live-build, debootstrap, xorriso, grub-efi-amd64-bin, etc.)
cd build && ../auto/config && sudo lb build
```
CI: `.github/workflows/build-iso.yml` (push/PR/tag) and `update.yml` (weekly Sun 05:00 UTC).

## Verification
```bash
sha256sum raptor-security-20261010.iso
# f7e001ae69924765d569a5b7fd7b07d2f86c1458fcecd5448dca7eaec7659c03
```

## Flash
```bash
dd if=raptor-security-20261010.iso of=/dev/sdX bs=4M status=progress oflag=sync
```

## Debug a live session
1. Boot ISO
2. `Ctrl+Alt+F2`
3. Login: `user` (no password)
4. `cat /home/user/raptor-debug.log`

## License
MIT
