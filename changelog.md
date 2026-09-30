# Changelog

All notable changes to the Raptor OS project will be documented in this file.

> **Note:** No stable ISO releases currently exist. The project is under initial framework construction.

---

## [Unreleased] - `main`

### Fixed
* **Black screen at boot (regression in the 2026-09-28 ISO).** The hardened boot-append added in `fce6bd1` (`oops=panic panic=30 quiet loglevel=3 vsyscall=emulate …` + `kernel.panic_on_oops=1`/`kernel.panic=30`, grub `timeout=0`) could panic on any non-fatal kernel oops while `quiet` hid the message — presenting as a silent black screen / reboot loop on some hardware. Reverted the UEFI (both workflows) and BIOS (`auto/config`) kernel command lines to the last-known-booting form `boot=live config components username=user autologin quiet ignore_uuid live-media-timeout=30` and restored grub `set timeout=5`; removed the panic-on-oops/crash-param sysctls. The hardening flags (`init_on_alloc/free`, `page_poison`, `slab_nomerge`) also returned to their pre-`fce6bd1` defaults to get a plain, proven boot back.
* **Update Manager (weekly ISO rebuild) — backported every host-level fix from `build-iso.yml`.** The scheduled update workflow had drifted behind the push-triggered build and was failing for several independent reasons at once; all of the following are now fixed:
  * **AppArmor user-namespace restriction (the primary blocker).** Ubuntu 24.04 restricts unprivileged user namespaces; live-build's chroot stages shell out to debootstrap, which requires one. `update.yml` was missing `kernel.apparmor_restrict_unprivileged_userns=0`, so the chroot stage died on every scheduled run while push builds worked.
  * **Flaky runner apt source.** The `ubuntu-24.04` image ships its own Google-Chrome apt source whose index downloads intermittently fail hash-sum checks and hard-fail `apt-get update`. That source is now removed and `Acquire::Retries`/`http::Timeout` are set, matching `build-iso.yml`.
  * **Missing syslinux packages.** `syslinux` and `syslinux-common` were absent from the dependency list, so the files the bootloader step needs were not guaranteed to exist. Both added, plus an early assertion that the three required syslinux assets are present — failing in seconds instead of 40 minutes into a build.
  * **isolinux template was still the pre-fix version.** The step claimed "Same fix as build-iso.yml" while still re-pointing the dangling `ln -sf` symlinks and omitting `ldlinux.c32` entirely. It now materializes real `isolinux.bin`/`ldlinux.c32`/`vesamenu.c32` copies and verifies them with `file`, exactly as `build-iso.yml` does.
  * **Missing payload gate.** Added the "Assert Raptor payload is packed into the image" check, so an update build can no longer report success while shipping an ISO that silently lost `/usr/lib/raptor-security`.
  * **Ambiguous ISO discovery.** The pipeline finds its image with `find … -print -quit`, which returns an *arbitrary* match if more than one ISO is present — a stale ISO would let the run "succeed" while shipping last week's image with none of this week's security updates. Stale ISOs/checksums are now deleted up front, the rename step refuses to run unless exactly one ISO exists, and the output gets a dated product name.
  * **No-op mutation of a tracked file.** `sed -i '/--systemd/d' ../auto/config` edited a version-controlled file on every run while doing nothing at all (`--initsystem systemd` does not contain the literal `--systemd`). Replaced with a real assertion that `--initsystem systemd` is still pinned, which is the invariant that actually matters.
* **XFCE defaults now guaranteed to reach the live user.** `0210-raptor-xfce-defaults.hook.chroot` is committed executable (`100755`) and, more importantly, the defaults are re-applied by a `live-config` start hook (`lib/live/config/0990-raptor-skel`). live-config executes from the boot image's early environment, so `/home/user` unconditionally gets the Raptor theme, panel and dashboard autostart on first boot — no longer relying solely on `/etc/skel` propagation from the chroot build.
* **Dead duplicate package list.** A stray root-level `raptor-security.list.chroot` is referenced by nothing (live-build only reads `build/config/package-lists/`) and had drifted: it was missing `librewolf`, `xfce4-whiskermenu-plugin`, `greybird-gtk-theme`, `lightdm-gtk-greeter` and `syslinux-utils`, while retaining packages that were deliberately dropped. Anyone editing it would have silently changed nothing. Removed, and `validate.sh` now fails the build if a package list reappears outside `build/config/package-lists/`.

### Added
* **Dashboard auto-start stress-tested.** `raptor-dashboard-bootstrap` waits (up to 45s) for the `org.raptor.ModeManager` D-Bus service before launching the dashboard, dedups via a pidfile, and logs to `/tmp/raptor-dashboard.log`. Both `/etc/xdg/autostart` and `~/.config/autostart` run through it, so the Security Center reliably appears after login.
* **Live performance graphs (Kodachi-style).** The dashboard now draws real-time CPU, memory and network up/down sparklines (60 × 1s samples, cairo on `Gtk.DrawingArea`, sourced from `/proc/stat`, `/proc/meminfo`, `/proc/net/dev`).
* **DNS over Tor, properly.** `dnsmasq` listens on `127.0.0.1:53` and forwards to Tor's resolver (`server=127.0.0.1#9053`); NetworkManager is set to `dns=none`; Mode Manager writes `nameserver 127.0.0.1` into `/etc/resolv.conf` on every profile switch and reports "via Tor" state.
* **Faster boot.** New hook `0270-raptor-fastboot.hook.chroot` masks bluetooth, ModemManager, avahi, CUPS, packagekit, smartd, fwupd, pppd-dns, rsync and `remote-fs.target`; journald runs `Storage=volatile`. GFUEF/BIOS default timeout set to 0.
* **Hardened boot & kernel.** Boot append gained `init_on_alloc=1 init_on_free=1 slab_nomerge page_poison=1 vsyscall=emulate oops=panic panic=30` plus `autologin`, on both UEFI (grub, both workflows) and BIOS (isolinux) paths; integrity spans `init_on_alloc/free`, crash-on-oops and `suid_dumpable=0`/`core_uses_pid=1`; IPv6 disabled by default via its own sysctl drop-in.
* **Kodachi look & feel.** Papirus-Dark icon theme wired into both XFCE user profiles; the bottom panel now ships a launcher set (terminal, LibreWolf, file manager, Security Center, settings), a live CPU/RAM genmon widget, tasklist, systray and clock; a one-shot welcome card orients the user to modes, DNS-over-Tor and the app menu.
* **Larger app suite.** Added dmitry, whatweb, cewl, hashid, crunch, reaver, hostapd, guymager, dcfldd, scalpel, mtr, p7zip-full, onioncircuits, nyx, tmux, vim, swaks and `gnome-system-monitor`, each surfaced through the Raptor menu categories via new launcher entries. (`dirbuster`/`wordlists`/`exploitdb` are Kali-only and absent from Debian bookworm — deliberately left out rather than breaking `lb build`.)
* **Update manager actually delivers updates.** The weekly workflow previously only uploaded a 30-day GitHub artifact, so a successful rebuild reached nobody. It now publishes the ISO + `sha256` to the Internet Archive collection the README points at, using the official `ia` CLI (no hand-rolled upload endpoint). The step is gated on `IA_COLLECTION`/`IA_KEY`/`IA_SECRET` being configured, so a fork without credentials still gets a green build and a usable artifact. Internet Archive items are immutable, so each build uses a dated identifier.
* **Update-manager failure diagnostics.** A `if: failure()` step uploads the live-build/apt logs and the generated `build/config/auto/` state, so the next failure of this workflow can be diagnosed without re-running it blind.
* **Stronger pre-build validation.** `validate.sh` now also asserts the package list pins `systemd-sysv`, `live-config-systemd` and `live-boot` — the last one is what makes the initramfs honour `boot=live`; without it the image builds cleanly and then panics at boot with `VFS: Unable to mount root fs on unknown-block(0,0)`.

### Changed
* **Security Center Dashboard:** Replaced the GTK3 control center with a GTK4/libadwaita Kodachi-style dashboard (`raptor-security-center`) showing live system (CPU/RAM/disk/uptime), network (interfaces/DNS/public-IP-through-Tor), and security status alongside the three operational profiles.
* **Mode Manager Status:** Extended `raptor_mode_managerd.GetStatus()` with live system/network checks (CPU %, memory, disk, uptime, interfaces, DNS, public IP via Tor SOCKS).
* **Package List:** Curated a lean, verified Debian bookworm-safe pentest toolset spanning recon, scanning, web, password, wireless, and forensics; replaced `dnscrypt-proxy` (not in bookworm) with `stubby` and added `cryptsetup`/`gnome-disk-utility` for disk encryption (VeraCrypt is not packaged in Debian). Removed `veracrypt` and `burpsuite` from the apt list (handled via the third-party build hook).
* **Mode Config Files:** Added missing `secure/hardened/lockdown.{nft,sysctl.conf,services}` under `/etc/raptor-security/modes/` required by Mode Manager.
* **Daemon Wiring:** Fixed systemd `ExecStart` paths to run the actual Python daemons and enabled all Raptor D-Bus daemons + first-boot setup at build time; created the `raptor-admin` group.

---

## [Unreleased] - Initial System Blueprint

### Added
* **Base Architecture:** Configured Debian 12 (Bookworm) x86_64 `live-build` environment with XFCE desktop environment.
* **Control Center GUI:** Integrated initial Python/GTK3 `raptor-control-center` dashboard and helper scripts in `/usr/local/bin/`.
* **Security Toolchain:** Configured package manifests for security auditing (`nmap`, `wireshark`, `hashcat`, `aircrack-ng`), privacy (`librewolf`, `tor`, `dnscrypt-proxy`), and memory wiping (`secure-delete`).
* **Third-Party Repositories:** Configured automated key retrieval and repository indexing for LibreWolf (`librewolf.list.chroot`).
* **CI/CD Build Pipeline:** Created `.github/workflows/build-iso.yml` to automate ISO generation, validation, error artifact logging, and direct raw binary release publishing.
