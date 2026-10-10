#!/usr/bin/env python3
"""
raptor-vpn-managerd — Raptor Security's VPN Manager.

Spec sections 5, 7, 12: dashboard VPN state, VPN controls in every mode,
VPN management under Networking. Deliberately built as a thin wrapper
around NetworkManager (`nmcli`) rather than reimplementing connection
management — NM already handles OpenVPN and WireGuard profile storage,
credentials, and reconnection behavior correctly, and Raptor Security
already depends on NetworkManager for base networking (see
raptor-base.list.chroot). Reinventing that here would be worse, not more
"Raptor."

    Bus name:    org.raptor.VPNManager
    Object path: /org/raptor/VPNManager
    Interface:   org.raptor.VPNManager1

Methods:
    GetStatus() -> a{sv}
    ListProfiles() -> aa{sv}
    Connect(s profile_name) -> b success
    Disconnect() -> b success
    ImportProfile(s file_path) -> b success

IMPORTANT — the Lockdown kill switch coupling this does NOT yet solve:
build/config/includes.chroot/etc/raptor-security/modes/lockdown.nft
hardcodes `oifname { "tun0", "wg0" }`
as the only interfaces allowed to originate outbound connections. This
daemon can tell you the REAL interface name a connection came up on via
GetStatus()'s `interface` field, but nothing here pushes that name back
into Mode Manager's nftables set dynamically — if NetworkManager ever
names a tunnel something other than tun0/wg0 (it can, e.g. multiple
simultaneous VPN profiles), Lockdown's kill switch will silently block
it rather than allow it. Documented in docs/ARCHITECTURE.md as a known
gap rather than solved here; solving it means either (a) VPN Manager
calling Mode Manager to `nft add element` the real interface name into a
named set at connect time, or (b) constraining VPN profiles to always
force the interface name to tun0/wg0 via NetworkManager's
`interface-name` connection setting. Not deciding that trade-off here.
"""

import logging
import subprocess

from gi.repository import GLib
from pydbus import SystemBus

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s raptor-vpn-managerd %(levelname)s: %(message)s",
)
log = logging.getLogger("raptor-vpn-managerd")

VPN_TYPES = ("vpn", "wireguard")


def run(cmd, check=False, timeout=30):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        if check and proc.returncode != 0:
            log.error("command failed: %s -> rc=%s stderr=%s",
                      " ".join(cmd), proc.returncode, proc.stderr.strip())
        return proc.returncode, proc.stdout, proc.stderr
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return 1, "", str(e)


class VPNManager:
    """
    <node>
      <interface name='org.raptor.VPNManager1'>
        <method name='GetStatus'>
          <arg type='a{sv}' name='status' direction='out'/>
        </method>
        <method name='ListProfiles'>
          <arg type='aa{sv}' name='profiles' direction='out'/>
        </method>
        <method name='Connect'>
          <arg type='s' name='profile_name' direction='in'/>
          <arg type='b' name='success' direction='out'/>
        </method>
        <method name='Disconnect'>
          <arg type='b' name='success' direction='out'/>
        </method>
        <method name='ImportProfile'>
          <arg type='s' name='file_path' direction='in'/>
          <arg type='b' name='success' direction='out'/>
        </method>
      </interface>
    </node>
    """

    def GetStatus(self):
        rc, out, _ = run([
            "nmcli", "-t", "-f", "NAME,TYPE,DEVICE", "connection", "show", "--active"
        ])
        if rc != 0:
            return {
                "connected": GLib.Variant("b", False),
                "profile_name": GLib.Variant("s", ""),
                "interface": GLib.Variant("s", ""),
                "vpn_type": GLib.Variant("s", ""),
            }

        for line in out.splitlines():
            parts = line.split(":")
            if len(parts) < 3:
                continue
            name, conn_type, device = parts[0], parts[1], parts[2]
            if conn_type in VPN_TYPES:
                return {
                    "connected": GLib.Variant("b", True),
                    "profile_name": GLib.Variant("s", name),
                    "interface": GLib.Variant("s", device),
                    "vpn_type": GLib.Variant("s", conn_type),
                }

        return {
            "connected": GLib.Variant("b", False),
            "profile_name": GLib.Variant("s", ""),
            "interface": GLib.Variant("s", ""),
            "vpn_type": GLib.Variant("s", ""),
        }

    def ListProfiles(self):
        rc, out, _ = run(["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"])
        if rc != 0:
            return []

        profiles = []
        for line in out.splitlines():
            parts = line.split(":")
            if len(parts) < 2:
                continue
            name, conn_type = parts[0], parts[1]
            if conn_type in VPN_TYPES:
                profiles.append({
                    "name": GLib.Variant("s", name),
                    "type": GLib.Variant("s", conn_type),
                })
        return profiles

    def Connect(self, profile_name: str) -> bool:
        known = {p["name"].unpack() for p in self.ListProfiles()}
        if profile_name not in known:
            log.error("rejected Connect(%r): not a known VPN profile", profile_name)
            return False

        log.info("bringing up VPN profile: %s", profile_name)
        rc, _, err = run(["nmcli", "connection", "up", profile_name], check=True, timeout=30)
        if rc != 0:
            log.error("VPN connect failed: %s", err)
            return False
        return True

    def Disconnect(self) -> bool:
        status = self.GetStatus()
        profile_name = status["profile_name"].unpack()
        if not profile_name:
            log.info("Disconnect called but no VPN is active")
            return True

        log.info("bringing down VPN profile: %s", profile_name)
        rc, _, err = run(["nmcli", "connection", "down", profile_name], check=True)
        if rc != 0:
            log.error("VPN disconnect failed: %s", err)
            return False
        return True

    def ImportProfile(self, file_path: str) -> bool:
        if not file_path.startswith("/") or ".." in file_path:
            log.error("rejected suspicious file_path: %r", file_path)
            return False

        if file_path.endswith(".ovpn"):
            conn_type = "openvpn"
        elif file_path.endswith(".conf"):
            conn_type = "wireguard"
        else:
            log.error("unrecognized VPN profile extension for %s "
                      "(expected .ovpn or .conf)", file_path)
            return False

        log.info("importing %s profile from %s", conn_type, file_path)
        rc, _, err = run(
            ["nmcli", "connection", "import", "type", conn_type, "file", file_path],
            check=True,
        )
        if rc != 0:
            log.error("VPN profile import failed: %s", err)
            return False
        return True


def main():
    bus = SystemBus()
    bus.publish("org.raptor.VPNManager", VPNManager())
    log.info("raptor-vpn-managerd started")
    GLib.MainLoop().run()


if __name__ == "__main__":
    main()
