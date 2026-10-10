#!/usr/bin/env python3
"""
raptor-dbus-helper — CLI bridge to the Raptor Security D-Bus daemons.

Usage:
    raptor-dbus-helper.py <Service> <method> [args...]
    raptor-dbus-helper.py ModeManager SetMode secure
    raptor-dbus-helper.py ModeManager GetMode
    raptor-dbus-helper.py TorManager NewIdentity

Prints the method's return value (JSON for dicts) to stdout. Exits non-zero
and prints the error to stderr if the service is unreachable or the call
fails, so the shell CLIs can rely on it under `set -euo pipefail`.

This is the ONLY place the CLI tools touch D-Bus; daemons stay the single
owner of firewall/mode/tor state (spec section 26).
"""

import json
import sys

from pydbus import SystemBus

SERVICES = {
    "ModeManager": ("org.raptor.ModeManager", "/org/raptor/ModeManager"),
    "TorManager": ("org.raptor.TorManager", "/org/raptor/TorManager"),
    "NetworkProtectionManager": (
        "org.raptor.NetworkProtectionManager",
        "/org/raptor/NetworkProtectionManager",
    ),
}


def main(argv):
    if len(argv) < 2:
        print(
            "usage: raptor-dbus-helper.py <Service> <method> [args...]",
            file=sys.stderr,
        )
        return 2
    service, method = argv[0], argv[1]
    args = argv[2:]
    try:
        name, path = SERVICES[service]
    except KeyError:
        print(f"unknown service {service} (known: {', '.join(SERVICES)})", file=sys.stderr)
        return 2
    try:
        bus = SystemBus()
        obj = bus.get(name, path)
        fn = getattr(obj, method)
        ret = fn(*args) if args else fn()
    except Exception as e:
        print(f"error calling {service}.{method}: {e}", file=sys.stderr)
        return 1
    if ret is not None:
        print(json.dumps(ret) if isinstance(ret, dict) else ret)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
