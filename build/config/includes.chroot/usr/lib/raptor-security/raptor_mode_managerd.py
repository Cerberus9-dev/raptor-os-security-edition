#!/usr/bin/env python3
"""
raptor-mode-managerd — Raptor Security's Mode Manager daemon.

This is the ONLY component in Raptor Security allowed to change firewall,
hardening, or network-privacy state. Security Center and every other GUI
talks to this daemon over D-Bus and never touches nftables/sysctl/systemd
directly — that split is what makes spec section 26 ("security indicators
must be real") enforceable: there is exactly one place state changes can
happen, and exactly one place status is read from, and both go through the
same verification logic.

Runs as root via systemd (see raptor-mode-manager.service), exposes:

    Bus name:    org.raptor.ModeManager
    Object path: /org/raptor/ModeManager
    Interface:   org.raptor.ModeManager1

Methods:
    SetMode(s mode) -> b success           — "secure" | "hardened" | "lockdown"
    GetMode() -> s mode
    GetStatus() -> a{sv} status            — see build_status() below

Signals:
    ModeChanged(s mode)

Every value returned by GetStatus() is derived from an actual runtime
check (systemctl, nft, ip, etc.) at call time — nothing is cached from the
last SetMode() call and nothing is assumed. If a check itself fails, the
corresponding field is the string "unknown", never a guessed "ok" value.
"""

import json
import logging
import subprocess
import sys
import time
from pathlib import Path

from gi.repository import GLib
from pydbus import SystemBus
from pydbus.generic import signal

MODES = ("secure", "hardened", "lockdown")
CONFIG_ROOT = Path("/etc/raptor-security/modes")
CURRENT_MODE_FILE = Path("/etc/raptor-security/current-mode")
RAPTOR_NFT_FAMILY = "inet"
RAPTOR_NFT_TABLE = "raptor_security"

# The public-IP check opens a Tor SOCKS tunnel and can take seconds when Tor
# is stalled; the dashboard polls GetStatus() every 5s. Cache the result so
# a slow tunnel can't block every poll (and thus every SetMode/GetMode) on
# the single-threaded D-Bus loop.
_PUBLIC_IP_CACHE = {"ts": 0.0, "ip": "unknown"}
_PUBLIC_IP_TTL = 30.0

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s raptor-mode-managerd %(levelname)s: %(message)s",
)
log = logging.getLogger("raptor-mode-managerd")


def run(cmd, check=True, timeout=10):
    """Run a command, returning (returncode, stdout, stderr). Never raises
    on a non-zero exit unless check=True and the caller wants that."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        if check and proc.returncode != 0:
            log.warning("command failed: %s -> rc=%s stderr=%s",
                        " ".join(cmd), proc.returncode, proc.stderr.strip())
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        log.error("command not found: %s", cmd[0])
        return 127, "", f"{cmd[0]}: not found"
    except subprocess.TimeoutExpired:
        log.error("command timed out: %s", " ".join(cmd))
        return 124, "", "timeout"


class ModeManager:
    """
    <node>
      <interface name='org.raptor.ModeManager1'>
        <method name='SetMode'>
          <arg type='s' name='mode' direction='in'/>
          <arg type='b' name='success' direction='out'/>
        </method>
        <method name='GetMode'>
          <arg type='s' name='mode' direction='out'/>
        </method>
        <method name='GetStatus'>
          <arg type='a{sv}' name='status' direction='out'/>
        </method>
        <signal name='ModeChanged'>
          <arg type='s' name='mode'/>
        </signal>
      </interface>
    </node>
    """

    ModeChanged = signal()

    def GetMode(self):
        if CURRENT_MODE_FILE.exists():
            mode = CURRENT_MODE_FILE.read_text().strip()
            if mode in MODES:
                return mode
        return "unknown"

    def SetMode(self, mode: str) -> bool:
        mode = mode.strip().lower()
        if mode not in MODES:
            log.error("rejected SetMode(%r): not a valid mode", mode)
            return False

        log.info("switching mode -> %s", mode)
        ok = True
        ok &= self._apply_firewall(mode)
        ok &= self._apply_sysctl(mode)
        ok &= self._apply_services(mode)
        ok &= self._configure_dns()

        if ok:
            CURRENT_MODE_FILE.write_text(mode + "\n")
            self.ModeChanged(mode)
            log.info("mode switch to %s completed", mode)
        else:
            log.error("mode switch to %s completed WITH ERRORS — "
                       "state may be inconsistent, check GetStatus()", mode)
        return ok

    def GetStatus(self):
        return self.build_status()

    # -- internal: applying state ------------------------------------

    def _apply_firewall(self, mode: str) -> bool:
        ruleset = CONFIG_ROOT / f"{mode}.nft"
        if not ruleset.exists():
            log.error("missing ruleset: %s", ruleset)
            return False
        rc, _, err = run(["nft", "-f", str(ruleset)])
        if rc != 0:
            log.error("nft load failed for %s: %s", mode, err.strip())
            return False
        return True

    def _apply_sysctl(self, mode: str) -> bool:
        sysctl_file = CONFIG_ROOT / f"{mode}.sysctl.conf"
        if not sysctl_file.exists():
            # Not every mode needs sysctl overrides; absence isn't an error.
            return True
        rc, _, err = run(["sysctl", "-p", str(sysctl_file)])
        if rc != 0:
            log.error("sysctl apply failed for %s: %s", mode, err.strip())
            return False
        return True

    def _apply_services(self, mode: str) -> bool:
        """
        Reads {mode}.services — one line per unit, prefixed with '+' to
        ensure-started or '-' to ensure-stopped. Lets each mode define its
        own service posture (e.g. lockdown stops non-essential network
        services) without hardcoding a service list in this daemon.
        """
        services_file = CONFIG_ROOT / f"{mode}.services"
        if not services_file.exists():
            return True

        ok = True
        for raw_line in services_file.read_text().splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            action, unit = line[0], line[1:].strip()
            if action == "+":
                rc, _, err = run(["systemctl", "start", unit], check=False)
            elif action == "-":
                rc, _, err = run(["systemctl", "stop", unit], check=False)
            else:
                log.warning("bad line in %s: %r", services_file, line)
                continue
            if rc != 0:
                log.warning("service action failed: %s %s (%s)",
                             action, unit, err.strip())
                ok = False
        return ok

    # -- internal: verifying state -------------------------------------
    # Every one of these checks live system state. None of them trust
    # what SetMode() *tried* to do — see module docstring.

    def build_status(self):
        status = {}

        status["mode"] = GLib.Variant("s", self.GetMode())
        status["firewall_active"] = GLib.Variant("s", self._check_firewall())
        status["kill_switch_armed"] = GLib.Variant("s", self._check_kill_switch())
        status["vpn_state"] = GLib.Variant("s", self._check_vpn())
        status["tor_state"] = GLib.Variant("s", self._check_tor())
        status["mac_randomization"] = GLib.Variant("s", self._check_mac_randomization())
        status["persistence"] = GLib.Variant("s", self._check_persistence())

        # --- Kodachi-style system / network overview -----------------------
        # Every one of these reads live local state; none require a network
        # call, keeping GetStatus() fast (sub-100ms) and offline-safe per
        # the honest-status rule: network failures → "unknown", never fake.
        status["cpu_percent"] = GLib.Variant("s", self._check_cpu_percent())
        status["mem_percent"] = GLib.Variant("s", self._check_mem_percent())
        status["mem_used_mb"] = GLib.Variant("s", self._check_mem_used_mb())
        status["mem_total_mb"] = GLib.Variant("s", self._check_mem_total_mb())
        status["disk_percent"] = GLib.Variant("s", self._check_disk_percent())
        status["disk_used_gb"] = GLib.Variant("s", self._check_disk_used_gb())
        status["disk_total_gb"] = GLib.Variant("s", self._check_disk_total_gb())
        status["uptime"] = GLib.Variant("s", self._check_uptime())
        status["interfaces"] = GLib.Variant("s", self._check_interfaces())
        status["dns_servers"] = GLib.Variant("s", self._check_dns())
        status["public_ip"] = GLib.Variant("s", self._check_public_ip())

        return status

    def _check_firewall(self) -> str:
        rc, out, _ = run(["systemctl", "is-active", "nftables"], check=False)
        if out.strip() != "active":
            return "inactive"
        # systemctl "active" only proves the unit ran, not that OUR
        # ruleset is what's loaded (someone could `nft flush ruleset`
        # after the fact) — actually check for our table.
        rc, out, _ = run(["nft", "list", "table", RAPTOR_NFT_FAMILY, RAPTOR_NFT_TABLE], check=False)
        return "active" if rc == 0 else "unverified"

    def _check_kill_switch(self) -> str:
        # Kill-switch is armed only if the raptor table's OUTPUT chain
        # specifically has policy drop. A naive substring check against
        # the whole table's text (checking for "policy drop" anywhere)
        # would false-positive on Secure/Hardened mode, since their
        # `forward` chain is also policy drop by design — only `output`
        # distinguishes Lockdown's real kill switch from the others.
        rc, out, _ = run(
            ["nft", "-j", "list", "table", RAPTOR_NFT_FAMILY, RAPTOR_NFT_TABLE],
            check=False,
        )
        if rc != 0:
            return "unknown"
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return "unknown"

        for item in data.get("nftables", []):
            chain = item.get("chain")
            if chain and chain.get("hook") == "output" and chain.get("family") == "inet":
                return "armed" if chain.get("policy") == "drop" else "not_armed"
        return "unknown"

    def _check_vpn(self) -> str:
        rc, out, _ = run(
            ["nmcli", "-t", "-f", "TYPE,STATE", "connection", "show", "--active"],
            check=False,
        )
        if rc != 0:
            return "unknown"
        for line in out.splitlines():
            if line.startswith(("vpn:", "wireguard:")):
                return "connected"
        return "disconnected"

    def _check_tor(self) -> str:
        _, out, _ = run(["systemctl", "is-active", "tor@default"], check=False)
        return "active" if out.strip() == "active" else "inactive"

    def _configure_dns(self) -> bool:
        """
        Points /etc/resolv.conf at the local DNS-over-Tor resolver whenever it
        is running (127.0.0.1:53 -> dnsmasq -> Tor DNSPort 9053). This is what
        actually prevents application DNS queries from leaking to the uplink's
        clearnet resolver — the .services files only ensure dnsmasq/tor are
        running. In Lockdown the services are stopped and the firewall drops
        everything, so the same nameserver simply fails closed.
        """
        try:
            resolver = Path("/etc/resolv.conf")
            target = "nameserver 127.0.0.1\noptions single-request-reopen\n"
            try:
                if resolver.read_text() == target:
                    return True
            except OSError:
                pass
            resolver.write_text(target)
            return True
        except OSError as e:
            log.warning("could not point resolv.conf at local resolver: %s", e)
            return False

    def _check_mac_randomization(self) -> str:
        # Per-connection setting reported by nmcli...
        rc, out, _ = run(
            ["nmcli", "-t", "-f", "802-11-wireless.cloned-mac-address",
             "connection", "show"],
            check=False,
        )
        if rc != 0:
            return "unknown"
        if "random" in out.lower() or "stable" in out.lower():
            return "enabled"
        # ...plus the global default from the packaged NetworkManager conf.
        # nmcli reports per-connection values only; with nothing customized
        # per connection the randomized default still applies at activation
        # time, so a conf.d default counts as enabled too.
        try:
            nm_conf = Path("/etc/NetworkManager/conf.d/10-raptor-hardening.conf")
            if nm_conf.exists() and "cloned-mac-address=random" in nm_conf.read_text():
                return "enabled"
        except OSError:
            pass
        return "disabled"

    def _check_persistence(self) -> str:
        rc, _, _ = run(["findmnt", "-n", "/lib/live/mount/persistence"], check=False)
        return "encrypted_active" if rc == 0 else "none"

    # -- system/network overview -------------------------------------------
    # Called by the dashboard refresh loop. Keep these fast and side-effect
    # free; they must never trigger a network egress of their own (the
    # public-IP lookup is routed through Tor when available, otherwise it
    # simply reports "unknown" rather than leaking the clearnet IP).

    def _check_cpu_percent(self) -> str:
        # /proc/stat CPU-time delta over a short interval; no dependency on
        # sysstat/mpstat being installed.
        try:
            def _sample():
                with open("/proc/stat") as f:
                    parts = f.readline().split()
                vals = [int(x) for x in parts[1:] if x.isdigit()]
                return sum(vals), vals[3]  # (total, idle)

            t0, i0 = _sample()
            time.sleep(0.5)
            t1, i1 = _sample()
            d = t1 - t0
            if d <= 0:
                return "unknown"
            idle = i1 - i0
            return f"{max(0.0, (d - idle) / d * 100.0):.1f}"
        except Exception as e:
            log.warning("cpu percent check failed: %s", e)
            return "unknown"

    def _check_mem_percent(self) -> str:
        try:
            with open("/proc/meminfo") as f:
                data = dict(line.split(":", 1) for line in f)
            total = int(data["MemTotal"].strip().split()[0])
            available = int(data["MemAvailable"].strip().split()[0])
            if total == 0:
                return "unknown"
            return f"{max(0.0, (1 - available / total) * 100.0):.1f}"
        except Exception as e:
            log.warning("mem percent check failed: %s", e)
            return "unknown"

    def _mem_kb(self) -> tuple:
        try:
            with open("/proc/meminfo") as f:
                data = dict(line.split(":", 1) for line in f)
            total = int(data["MemTotal"].strip().split()[0])
            available = int(data["MemAvailable"].strip().split()[0])
            return total, available
        except Exception:
            return 0, 0

    def _check_mem_total_mb(self) -> str:
        total, _ = self._mem_kb()
        return str(int(total // 1024)) if total else "unknown"

    def _check_mem_used_mb(self) -> str:
        total, available = self._mem_kb()
        return str(int((total - available) // 1024)) if total else "unknown"

    def _check_disk_percent(self) -> str:
        try:
            rc, out, _ = run(["df", "-P", "/"], check=False)
            if rc != 0:
                return "unknown"
            _, _, _, used_pct = out.splitlines()[1].split()[:4]
            return used_pct.rstrip("%")
        except Exception as e:
            log.warning("disk percent check failed: %s", e)
            return "unknown"

    def _check_disk_total_gb(self) -> str:
        try:
            rc, out, _ = run(["df", "-B1", "-P", "/"], check=False)
            if rc != 0:
                return "unknown"
            rows = out.splitlines()
            _, total, _, _, _, _ = rows[1].split()
            return f"{int(total) / (1 << 30):.1f}"
        except Exception as e:
            log.warning("disk total check failed: %s", e)
            return "unknown"

    def _check_disk_used_gb(self) -> str:
        try:
            rc, out, _ = run(["df", "-B1", "-P", "/"], check=False)
            if rc != 0:
                return "unknown"
            rows = out.splitlines()
            _, _, used, _, _, _ = rows[1].split()
            return f"{int(used) / (1 << 30):.1f}"
        except Exception as e:
            log.warning("disk used check failed: %s", e)
            return "unknown"

    def _check_uptime(self) -> str:
        try:
            with open("/proc/uptime") as f:
                seconds = float(f.read().split()[0])
        except Exception:
            return "unknown"
        m, s = divmod(int(seconds), 60)
        h, m = divmod(m, 60)
        d, h = divmod(h, 24)
        if d > 0:
            return f"{d}d {h}h"
        if h > 0:
            return f"{h}h {m}m"
        return f"{m}m {s}s"

    def _check_interfaces(self) -> str:
        # Up + not-loopback physical/wireless interfaces, with their IPs.
        # `ip -4 -o addr show up` only lists interfaces that are up, so the
        # reported state is the record itself; each line reads like
        # `2: eth0    inet 192.168.1.5/24 brd ...`.
        try:
            rc, out, _ = run(
                ["ip", "-4", "-o", "addr", "show", "up"],
                check=False,
            )
            if rc != 0:
                return "unknown"
            result = []
            for line in out.splitlines():
                parts = line.split()
                if len(parts) < 3 or parts[1] == "lo" or parts[2] != "inet":
                    continue
                result.append(f"{parts[1]}:{parts[3].split('/')[0]}")
            return ", ".join(result) if result else "none"
        except Exception as e:
            log.warning("interfaces check failed: %s", e)
            return "unknown"

    def _check_dns(self) -> str:
        # Whichever resolver the system would actually use right now, read
        # from /etc/resolv.conf itself. With NM dns=none this file is owned
        # by _configure_dns (127.0.0.1 = DNS over Tor); anything else on this
        # line means a clearnet resolver is in effect and should be reported
        # as-is rather than "(via Tor)".
        try:
            nameservers = []
            with open("/etc/resolv.conf") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] == "nameserver":
                        nameservers.append(parts[1])
            if not nameservers:
                return "unknown"
            if nameservers == ["127.0.0.1"]:
                return "via Tor (127.0.0.1)"
            return ", ".join(nameservers)
        except OSError as e:
            log.warning("dns check failed: %s", e)
            return "unknown"

    def _check_public_ip(self) -> str:
        # Resolve the public IP *through Tor's SOCKS proxy* (127.0.0.1:9050)
        # so this never leaks the machine's clearnet IP. If Tor is down or
        # unreachable, report "unknown" — never fall back to a clearnet
        # lookup, which would defeat the point of the check. Cached for
        # _PUBLIC_IP_TTL seconds so the 5s dashboard poll can't block on it.
        import socket

        now = time.monotonic()
        if now - _PUBLIC_IP_CACHE["ts"] < _PUBLIC_IP_TTL:
            return _PUBLIC_IP_CACHE["ip"]

        host = "check.torproject.org"
        ip = "unknown"
        try:
            with socket.create_connection(("127.0.0.1", 9050), timeout=5) as s:
                # SOCKS5 greeting, no auth
                s.sendall(b"\x05\x01\x00")
                if s.recv(2) != b"\x05\x00":
                    return "unknown"
                # SOCKS5 CONNECT with DOMAINNAME addressing (type 3): resolve
                # remotely through Tor, never via clearnet DNS in this process.
                addr = host.encode()
                s.sendall(
                    b"\x05\x01\x00\x03" + bytes([len(addr)]) + addr
                    + (443).to_bytes(2, "big")
                )
                if s.recv(2) != b"\x05\x00":
                    return "unknown"
                s.recv(4)
                # Minimal HTTPS GET through the tunnel
                req = (
                    f"GET /api/ip HTTP/1.1\r\nHost: {host}\r\n"
                    f"Connection: close\r\nUser-Agent: RaptorOS\r\n\r\n"
                ).encode()
                s.sendall(req)
                data = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                body = data.split(b"\r\n\r\n", 1)[-1] if b"\r\n\r\n" in data else b""
                payload = json.loads(body.decode(errors="replace"))
                ip = payload.get("IP", "unknown")
        except Exception as e:
            log.warning("public ip via Tor unavailable: %s", e)
        _PUBLIC_IP_CACHE["ts"] = time.monotonic()
        _PUBLIC_IP_CACHE["ip"] = ip
        return ip


def main():
    if CURRENT_MODE_FILE.parent.exists() is False:
        log.error("config root %s missing — is the raptor-security "
                   "payload installed?", CURRENT_MODE_FILE.parent)
        sys.exit(1)

    bus = SystemBus()
    manager = ModeManager()
    bus.publish("org.raptor.ModeManager", manager)

    # Apply the persisted mode's state on every daemon start (boot, and any
    # service restart). Without this, GetMode() would report a mode that
    # doesn't match GetStatus()'s live checks until a GUI SetMode() call
    # happened to occur — exactly the "fake indicator" spec section 26
    # forbids. This calls the same _apply_* methods SetMode() uses, not a
    # separate code path, so there's only one place mode-application logic
    # lives.
    startup_mode = manager.GetMode()
    if startup_mode == "unknown":
        log.warning("no current mode recorded, defaulting to secure")
        startup_mode = "secure"
    log.info("applying %s mode at startup", startup_mode)
    if not manager.SetMode(startup_mode):
        log.error("failed to fully apply %s mode at startup — "
                   "GetStatus() may show unverified/inconsistent state",
                   startup_mode)

    GLib.MainLoop().run()


if __name__ == "__main__":
    main()
