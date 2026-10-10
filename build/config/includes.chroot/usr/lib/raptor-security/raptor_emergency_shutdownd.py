#!/usr/bin/env python3
"""
raptor-emergency-shutdownd — Raptor Security's Emergency Shutdown Manager.

Spec section 10. Deliberately a SEPARATE component from Mode Manager
(spec section 27 lists them as distinct modules) — mode changes and
"destroy this session and power off" are different enough in blast radius
that they shouldn't share a D-Bus method surface or a code path where a
bug in one can plausibly trigger the other.

    Bus name:    org.raptor.EmergencyShutdown
    Object path: /org/raptor/EmergencyShutdown
    Interface:   org.raptor.EmergencyShutdown1

Methods:
    GetPersistenceInfo() -> a{sv}
        Lets the GUI show an accurate "here's what will/won't be
        preserved" statement BEFORE asking for confirmation — spec
        section 10: "The UI should explain exactly what is being cleared."
    TriggerEmergencyShutdown(s live_user, b confirmed) -> b accepted
        `confirmed` must be explicitly True. This is a safety rail against
        a caller invoking the method without meaning to — it is NOT a
        substitute for the GUI's own confirmation dialog with Cancel /
        Shut Down & Clear Session buttons (spec section 10). Any caller
        that sets confirmed=True without having actually shown the user
        that dialog is misusing this API, not something this daemon can
        detect from the D-Bus call alone.

This process does not know how to "undo" — by design there is no
CancelShutdown() method once TriggerEmergencyShutdown has been called,
because past the confirmation dialog, spec section 10's flow is one-way.
The confirmation step is what CAN be cancelled, and that happens entirely
client-side in the GUI before this method is ever called.
"""

import logging
import subprocess

from gi.repository import GLib
from pydbus import SystemBus

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s raptor-emergency-shutdownd %(levelname)s: %(message)s",
)
log = logging.getLogger("raptor-emergency-shutdownd")

SCRIPT_PATH = "/usr/lib/raptor-security/raptor-emergency-shutdown.sh"
PERSISTENCE_MOUNT = "/lib/live/mount/persistence"


def run(cmd, check=False, timeout=10):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return proc.returncode, proc.stdout, proc.stderr
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return 1, "", str(e)


class EmergencyShutdownManager:
    """
    <node>
      <interface name='org.raptor.EmergencyShutdown1'>
        <method name='GetPersistenceInfo'>
          <arg type='a{sv}' name='info' direction='out'/>
        </method>
        <method name='TriggerEmergencyShutdown'>
          <arg type='s' name='live_user' direction='in'/>
          <arg type='b' name='confirmed' direction='in'/>
          <arg type='b' name='accepted' direction='out'/>
        </method>
      </interface>
    </node>
    """

    def GetPersistenceInfo(self):
        rc, _, _ = run(["findmnt", "-n", PERSISTENCE_MOUNT])
        persistence_active = rc == 0

        rc, out, _ = run(["swapon", "--show", "--noheadings"])
        swap_active = bool(out.strip())

        return {
            "persistence_active": GLib.Variant("b", persistence_active),
            "persistence_will_be_preserved": GLib.Variant("b", True),
            "swap_active": GLib.Variant("b", swap_active),
            "swap_erasure_guaranteed": GLib.Variant("b", False),
            # ^ always False — see raptor-emergency-shutdown.sh header.
            # Never flip this to True; it would be exactly the kind of
            # overclaimed guarantee spec section 10 explicitly forbids.
        }

    def TriggerEmergencyShutdown(self, live_user: str, confirmed: bool) -> bool:
        if not confirmed:
            log.warning("TriggerEmergencyShutdown called with confirmed=False — refusing")
            return False

        if not live_user or "/" in live_user or ".." in live_user:
            log.error("rejected suspicious live_user value: %r", live_user)
            return False

        log.warning("EMERGENCY SHUTDOWN triggered for user=%s — session teardown "
                    "and poweroff starting now", live_user)

        # Fire-and-forget: this process is about to terminate the very
        # session (and D-Bus daemon) that's running it, so we don't wait
        # around for the script to return before replying — the script's
        # own logging (via logger/syslog) is the durable record, not this
        # method call's return value.
        subprocess.Popen(["/bin/sh", SCRIPT_PATH, live_user])
        return True


def main():
    bus = SystemBus()
    bus.publish("org.raptor.EmergencyShutdown", EmergencyShutdownManager())
    log.info("raptor-emergency-shutdownd started")
    GLib.MainLoop().run()


if __name__ == "__main__":
    main()
