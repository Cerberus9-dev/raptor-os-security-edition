#!/usr/bin/env python3
"""
raptor-tor-managerd — Raptor Security's Tor Manager.

Spec sections 5, 7, 12: dashboard Tor state, Tor controls in every mode,
Tor management under Networking.

    Bus name:    org.raptor.TorManager
    Object path: /org/raptor/TorManager
    Interface:   org.raptor.TorManager1

Methods:
    GetStatus() -> a{sv}
    Start() -> b success
    Stop() -> b success
    NewIdentity() -> b success

GetStatus()'s honesty boundary, spelled out because it's easy to overclaim
here: this checks (a) whether the tor@default systemd unit is active, and
(b) whether something is actually listening on the configured SOCKS port.
It does NOT verify a circuit is actually built and traffic is flowing
through Tor — that requires either parsing Tor's own bootstrap log lines
or making a real network request through the SOCKS proxy, both of which
add either log-scraping fragility or a live network dependency to a
status check that's supposed to be simple and fast. `circuit_status` is
therefore reported as "unknown" rather than guessed at from
active+listening, per spec section 26 ("if something cannot be verified,
display Unknown... never fake security").

NewIdentity() talks to Tor's control port directly (raw socket, minimal
protocol implementation) rather than depending on a third-party control
library, to avoid an unverified pip/apt package dependency — same
rationale as VPN Manager wrapping nmcli instead of a Python NM binding.
"""

import logging
import socket
import subprocess
from pathlib import Path

from gi.repository import GLib
from pydbus import SystemBus

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s raptor-tor-managerd %(levelname)s: %(message)s",
)
log = logging.getLogger("raptor-tor-managerd")

TOR_UNIT = "tor@default"
SOCKS_HOST = "127.0.0.1"
SOCKS_PORT = 9050
CONTROL_HOST = "127.0.0.1"
CONTROL_PORT = 9051
# Debian's tor package uses a DataDirectory of /var/lib/tor, and unless a
# CookieAuthFile is configured the control cookie is written under it
# (tor's default is `$DataDirectory/control.authcookie`). Some releases
# instead land it in a runtime directory. Probe the candidates in order so
# NewIdentity() survives tor releases that move the cookie.
def _find_control_cookie() -> tuple:
    for candidate in (
        Path("/var/lib/tor/control.authcookie"),
        Path("/run/tor/control.authcookie"),
        Path("/var/run/tor/control.authcookie"),
    ):
        if candidate.exists():
            return candidate.read_bytes()
    return b""


def run(cmd, check=False, timeout=15):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        if check and proc.returncode != 0:
            log.error("command failed: %s -> rc=%s stderr=%s",
                      " ".join(cmd), proc.returncode, proc.stderr.strip())
        return proc.returncode, proc.stdout, proc.stderr
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return 1, "", str(e)


def check_port_listening(host, port, timeout=1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


class TorManager:
    """
    <node>
      <interface name='org.raptor.TorManager1'>
        <method name='GetStatus'>
          <arg type='a{sv}' name='status' direction='out'/>
        </method>
        <method name='Start'>
          <arg type='b' name='success' direction='out'/>
        </method>
        <method name='Stop'>
          <arg type='b' name='success' direction='out'/>
        </method>
        <method name='NewIdentity'>
          <arg type='b' name='success' direction='out'/>
        </method>
      </interface>
    </node>
    """

    def GetStatus(self):
        _, out, _ = run(["systemctl", "is-active", TOR_UNIT])
        service_active = out.strip() == "active"
        socks_listening = check_port_listening(SOCKS_HOST, SOCKS_PORT) if service_active else False

        return {
            "service_active": GLib.Variant("b", service_active),
            "socks_listening": GLib.Variant("b", socks_listening),
            "socks_address": GLib.Variant(
                "s", f"{SOCKS_HOST}:{SOCKS_PORT}" if socks_listening else ""
            ),
            "circuit_status": GLib.Variant("s", "unknown"),
            # ^ deliberately not "active" — see module docstring. A GUI
            # should render this field distinctly from a true/false state,
            # not fold it into the same green/red treatment as the others.
        }

    def Start(self) -> bool:
        rc, _, err = run(["systemctl", "start", TOR_UNIT], check=True)
        if rc != 0:
            log.error("failed to start tor: %s", err)
            return False
        return True

    def Stop(self) -> bool:
        rc, _, err = run(["systemctl", "stop", TOR_UNIT], check=True)
        if rc != 0:
            log.error("failed to stop tor: %s", err)
            return False
        return True

    def NewIdentity(self) -> bool:
        """
        Sends SIGNAL NEWNYM over the control port to request new circuits.
        This does NOT retroactively protect anything about the identity
        already used on existing circuits — it only affects NEW
        connections going forward. Not stating that distinction to the
        caller is exactly the kind of overclaim spec section 26 warns
        against for security controls generally.
        """
        cookie_hex = _find_control_cookie().hex()
        if not cookie_hex:
            log.error("tor control auth cookie not found — is ControlPort/"
                      "CookieAuthentication enabled in torrc?")
            return False

        try:
            with socket.create_connection((CONTROL_HOST, CONTROL_PORT), timeout=5) as sock:
                f = sock.makefile("rwb")

                f.write(f"AUTHENTICATE {cookie_hex}\r\n".encode())
                f.flush()
                auth_reply = f.readline().decode(errors="replace").strip()
                if not auth_reply.startswith("250"):
                    log.error("tor control AUTHENTICATE failed: %s", auth_reply)
                    return False

                f.write(b"SIGNAL NEWNYM\r\n")
                f.flush()
                signal_reply = f.readline().decode(errors="replace").strip()
                if not signal_reply.startswith("250"):
                    log.error("tor control SIGNAL NEWNYM failed: %s", signal_reply)
                    return False

                f.write(b"QUIT\r\n")
                f.flush()

            log.info("requested new Tor identity (NEWNYM)")
            return True
        except OSError as e:
            log.error("tor control port connection failed: %s", e)
            return False


def main():
    bus = SystemBus()
    bus.publish("org.raptor.TorManager", TorManager())
    log.info("raptor-tor-managerd started")
    GLib.MainLoop().run()


if __name__ == "__main__":
    main()
