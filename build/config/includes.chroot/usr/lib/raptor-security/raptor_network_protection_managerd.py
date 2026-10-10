#!/usr/bin/env python3
"""
raptor-network-protection-managerd — Raptor Security's Network Protection
Manager.

Spec section 5 (Network dashboard panel) and section 12 (Networking).
Named "NetworkProtectionManager" rather than "NetworkManager" specifically
to avoid any confusion with the actual org.freedesktop.NetworkManager bus
name this daemon itself queries.

    Bus name:    org.raptor.NetworkProtectionManager
    Object path: /org/raptor/NetworkProtectionManager
    Interface:   org.raptor.NetworkProtectionManager1

Methods:
    GetStatus() -> a{sv}
    ListOpenPorts() -> aa{sv}
    SetMACRandomization(b enabled) -> b success
    SetIPv6Enabled(b enabled) -> b success

COUPLING GAP, same pattern as VPN Manager's: Mode Manager's Lockdown mode
(lockdown.sysctl.conf) already force-disables IPv6 as part of its
hardening posture. If a user calls SetIPv6Enabled(True) here while in
Lockdown, this daemon will honor it — nothing here checks current mode
first, and Mode Manager's sysctl file will simply get silently
overridden until the next mode switch reapplies it. Not resolved here;
options are (a) this daemon queries Mode Manager's GetMode() before
allowing changes that a mode's hardening explicitly wants pinned, or
(b) accept the override and treat it as the user consciously punching a
hole in Lockdown — which needs to be surfaced in the GUI either way, not
silently allowed.
"""

import json
import logging
import subprocess

from gi.repository import GLib
from pydbus import SystemBus

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s raptor-network-protection-managerd %(levelname)s: %(message)s",
)
log = logging.getLogger("raptor-network-protection-managerd")


def run(cmd, check=False, timeout=10):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        if check and proc.returncode != 0:
            log.error("command failed: %s -> rc=%s stderr=%s",
                      " ".join(cmd), proc.returncode, proc.stderr.strip())
        return proc.returncode, proc.stdout, proc.stderr
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return 1, "", str(e)


class NetworkProtectionManager:
    """
    <node>
      <interface name='org.raptor.NetworkProtectionManager1'>
        <method name='GetStatus'>
          <arg type='a{sv}' name='status' direction='out'/>
        </method>
        <method name='ListOpenPorts'>
          <arg type='aa{sv}' name='ports' direction='out'/>
        </method>
        <method name='SetMACRandomization'>
          <arg type='b' name='enabled' direction='in'/>
          <arg type='b' name='success' direction='out'/>
        </method>
        <method name='SetIPv6Enabled'>
          <arg type='b' name='enabled' direction='in'/>
          <arg type='b' name='success' direction='out'/>
        </method>
      </interface>
    </node>
    """

    def GetStatus(self):
        interfaces = self._list_interfaces()
        active_conn = self._active_connection()
        ipv4 = self._ipv4_address(active_conn.get("device", "")) if active_conn else ""
        dns_servers = self._dns_servers()
        ipv6_enabled = self._ipv6_enabled()
        if active_conn:
            mac_random = self._mac_randomization_state(active_conn.get("device", ""))
        else:
            mac_random = "unknown"

        return {
            "interfaces": GLib.Variant("as", interfaces),
            "active_connection_name": GLib.Variant(
                "s", active_conn.get("name", "") if active_conn else ""
            ),
            "active_device": GLib.Variant(
                "s", active_conn.get("device", "") if active_conn else ""
            ),
            "ipv4_address": GLib.Variant("s", ipv4),
            "dns_servers": GLib.Variant("as", dns_servers),
            "ipv6_enabled": GLib.Variant("b", ipv6_enabled),
            "mac_randomization": GLib.Variant("s", mac_random),
        }

    def ListOpenPorts(self):
        # `ss` output parsing is inherently a bit fragile across versions;
        # this covers the common `ss -tulnp` column layout on Debian's iproute2.
        rc, out, _ = run(["ss", "-tulnp"])
        if rc != 0:
            log.error("ss failed — cannot enumerate open ports")
            return []

        ports = []
        for line in out.splitlines()[1:]:  # skip header
            parts = line.split()
            if len(parts) < 5:
                continue
            proto = parts[0]
            local_addr = parts[4]
            if ":" not in local_addr:
                continue
            addr, _, port = local_addr.rpartition(":")
            process = ""
            for p in parts:
                if p.startswith("users:"):
                    process = p
                    break
            ports.append({
                "protocol": GLib.Variant("s", proto),
                "address": GLib.Variant("s", addr),
                "port": GLib.Variant("s", port),
                "process": GLib.Variant("s", process),
            })
        return ports

    def SetMACRandomization(self, enabled: bool) -> bool:
        value = "random" if enabled else "permanent"
        # Applies to future wifi connections via NM's global default —
        # does NOT retroactively re-randomize an already-active connection
        # without a reconnect. Not attempting to force a reconnect here;
        # that's a connectivity-interrupting side effect a GUI action
        # should warn about explicitly, not do silently as a side effect
        # of a settings toggle.
        rc, _, err = run([
            "nmcli", "connection", "modify", "--global",
            "wifi.cloned-mac-address", value
        ], check=True)
        if rc != 0:
            log.error("failed to set MAC randomization: %s", err)
            return False
        return True

    def SetIPv6Enabled(self, enabled: bool) -> bool:
        value = "0" if enabled else "1"  # disable_ipv6: 0 = enabled, 1 = disabled
        rc, _, err = run(
            ["sysctl", "-w", f"net.ipv6.conf.all.disable_ipv6={value}"], check=True
        )
        if rc != 0:
            log.error("failed to set IPv6 state: %s", err)
            return False
        rc2, _, _ = run(
            ["sysctl", "-w", f"net.ipv6.conf.default.disable_ipv6={value}"], check=True
        )
        return rc2 == 0

    # -- internal checks -------------------------------------------------

    def _list_interfaces(self):
        rc, out, _ = run(["ip", "-j", "link", "show"])
        if rc != 0:
            return []
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return []
        return [i.get("ifname", "") for i in data if i.get("ifname") != "lo"]

    def _active_connection(self):
        rc, out, _ = run(
            ["nmcli", "-t", "-f", "NAME,TYPE,DEVICE", "connection", "show", "--active"]
        )
        if rc != 0:
            return None
        for line in out.splitlines():
            parts = line.split(":")
            if len(parts) >= 3 and parts[2]:
                return {"name": parts[0], "type": parts[1], "device": parts[2]}
        return None

    def _ipv4_address(self, device):
        if not device:
            return ""
        rc, out, _ = run(["ip", "-j", "-4", "addr", "show", "dev", device])
        if rc != 0:
            return ""
        try:
            data = json.loads(out)
            for entry in data:
                for addr in entry.get("addr_info", []):
                    return addr.get("local", "")
        except (json.JSONDecodeError, IndexError):
            pass
        return ""

    def _dns_servers(self):
        # NOTE: relies on systemd-resolved being both installed AND the
        # active resolver — on a stock Debian NetworkManager setup this is
        # NOT guaranteed by default (NM may write /etc/resolv.conf directly
        # instead). The /etc/resolv.conf fallback below is what actually
        # carries this on an unconfigured system; resolvectl is the
        # preferred path only if something explicitly wires NM to use
        # systemd-resolved. Flagging rather than assuming.
        rc, out, _ = run(["resolvectl", "status"])
        if rc != 0:
            # resolvectl not present/active — fall back to /etc/resolv.conf
            try:
                with open("/etc/resolv.conf") as f:
                    return [line.split()[1] for line in f if line.startswith("nameserver")]
            except OSError:
                return []
        servers = []
        for raw_line in out.splitlines():
            line = raw_line.strip()
            if line.startswith("DNS Servers:"):
                servers.extend(line.split(":", 1)[1].split())
        return servers

    def _ipv6_enabled(self) -> bool:
        rc, out, _ = run(["sysctl", "-n", "net.ipv6.conf.all.disable_ipv6"])
        if rc != 0:
            # unknown -> assume the worst case for a privacy-focused OS:
            # IPv6 might be enabled, so report it as enabled.
            return True
        return out.strip() == "0"

    def _mac_randomization_state(self, device) -> str:
        if not device:
            return "unknown"
        rc, out, _ = run(["nmcli", "-t", "-f", "GENERAL.HWADDR", "device", "show", device])
        rc2, out2, _ = run(["ethtool", "-P", device])
        if rc != 0 or rc2 != 0:
            return "unknown"
        current_mac = out.split(":", 1)[-1].strip().lower() if ":" in out else ""
        permanent_mac = out2.strip().lower().replace("permanent address:", "").strip()
        if not current_mac or not permanent_mac:
            return "unknown"
        return "enabled" if current_mac != permanent_mac else "disabled"


def main():
    bus = SystemBus()
    bus.publish("org.raptor.NetworkProtectionManager", NetworkProtectionManager())
    log.info("raptor-network-protection-managerd started")
    GLib.MainLoop().run()


if __name__ == "__main__":
    main()
