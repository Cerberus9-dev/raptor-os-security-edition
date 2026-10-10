#!/usr/bin/env python3
"""
raptor-persistence-managerd — Raptor Security's Persistence Manager.

Spec sections 10 and 23: the system must clearly distinguish Live session
data (tmpfs, gone at poweroff) from encrypted persistent storage
(LUKS-backed, explicitly opted into). This daemon is the one place that
distinction is actually implemented and checked — Mode Manager and
Emergency Shutdown both currently do their own `findmnt` check against
the same mount point rather than calling this daemon; see
docs/ARCHITECTURE.md for why that duplication was left as-is rather than
introducing a startup-ordering dependency between three root daemons for
one filesystem check. If persistence detection logic gets more
complicated than "is this mount point present," that's the trigger to
revisit and have them call GetStatus() here instead.

    Bus name:    org.raptor.PersistenceManager
    Object path: /org/raptor/PersistenceManager
    Interface:   org.raptor.PersistenceManager1

Methods:
    GetStatus() -> a{sv}
    ListCandidateDevices() -> aa{sv}
        Removable block devices that could host a persistence volume.
        Read-only — does not touch anything.
    CreatePersistence(s device_path, s passphrase) -> b success
        DESTRUCTIVE. Formats device_path with LUKS and ext4, labels it,
        and writes the live-boot persistence.conf it needs to be picked
        up at next boot. See the security note in CreatePersistence's
        docstring below before wiring a GUI button to this.
"""

import logging
import subprocess
from pathlib import Path

from gi.repository import GLib
from pydbus import SystemBus

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s raptor-persistence-managerd %(levelname)s: %(message)s",
)
log = logging.getLogger("raptor-persistence-managerd")

PERSISTENCE_MOUNT = "/lib/live/mount/persistence"
PERSISTENCE_LABEL = "persistence"
LUKS_MAPPER_NAME = "raptor_persistence"


def run(cmd, check=False, timeout=30, input_text=None):
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, input=input_text, check=False
        )
        if check and proc.returncode != 0:
            log.error("command failed: %s -> rc=%s stderr=%s",
                      " ".join(cmd), proc.returncode, proc.stderr.strip())
        return proc.returncode, proc.stdout, proc.stderr
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return 1, "", str(e)


class PersistenceManager:
    """
    <node>
      <interface name='org.raptor.PersistenceManager1'>
        <method name='GetStatus'>
          <arg type='a{sv}' name='status' direction='out'/>
        </method>
        <method name='ListCandidateDevices'>
          <arg type='aa{sv}' name='devices' direction='out'/>
        </method>
        <method name='CreatePersistence'>
          <arg type='s' name='device_path' direction='in'/>
          <arg type='s' name='passphrase' direction='in'/>
          <arg type='b' name='success' direction='out'/>
        </method>
      </interface>
    </node>
    """

    def GetStatus(self):
        rc, out, _ = run(["findmnt", "-n", "-o", "SOURCE,FSTYPE,SIZE,AVAIL", PERSISTENCE_MOUNT])
        active = rc == 0

        encrypted = False
        source = ""
        fstype = ""
        avail = ""
        if active:
            parts = out.split()
            source = parts[0] if len(parts) > 0 else ""
            fstype = parts[1] if len(parts) > 1 else ""
            avail = parts[3] if len(parts) > 3 else ""
            # If the mounted source is a /dev/mapper/* device, it's coming
            # through dm-crypt — that's our actual "encrypted" evidence,
            # not just an assumption based on how it was set up.
            encrypted = source.startswith("/dev/mapper/")

        return {
            "active": GLib.Variant("b", active),
            "encrypted": GLib.Variant("b", encrypted),
            "mount_point": GLib.Variant("s", PERSISTENCE_MOUNT if active else ""),
            "source_device": GLib.Variant("s", source),
            "filesystem": GLib.Variant("s", fstype),
            "available_space": GLib.Variant("s", avail),
        }

    def ListCandidateDevices(self):
        # Only removable, non-boot-media block devices — persistence
        # should never be offered against the disk the live session
        # itself is running from.
        rc, out, _ = run([
            "lsblk", "-J", "-o", "NAME,PATH,SIZE,RM,TYPE,MOUNTPOINT,MODEL"
        ])
        if rc != 0:
            log.error("lsblk failed, returning empty candidate list")
            return []

        import json
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            log.error("failed to parse lsblk output")
            return []

        candidates = []
        for dev in data.get("blockdevices", []):
            if dev.get("type") != "disk" or dev.get("rm") not in (True, "1", 1):
                continue
            # Skip whatever device the live session's own root is on.
            for part in dev.get("children", []) or []:
                if part.get("mountpoint") in ("/", "/run/live/medium"):
                    break
            else:
                candidates.append({
                    "path": GLib.Variant("s", dev.get("path", "")),
                    "size": GLib.Variant("s", dev.get("size", "")),
                    "model": GLib.Variant("s", dev.get("model") or "unknown"),
                })
        return candidates

    def CreatePersistence(self, device_path: str, passphrase: str) -> bool:
        """
        DESTRUCTIVE: formats device_path (must be a whole-disk removable
        device path from ListCandidateDevices, e.g. /dev/sdb — NOT a
        partition, NOT the boot device) with a single LUKS-encrypted ext4
        partition, and writes the live-boot persistence.conf the live
        session needs to pick it up at next boot.

        SECURITY NOTE this daemon cannot fix on its own: `passphrase`
        arrives as a plain D-Bus method argument. Any process running as
        root (or with CAP_SYS_PTRACE against this daemon) can observe it —
        this is no different from how many system daemons handle
        passphrases via D-Bus, but it's still not as good as a real
        polkit-mediated secret-passing mechanism or an in-process prompt
        agent. Flagging rather than pretending this is already solved —
        do not treat this method as safe against a malicious co-resident
        process with root.
        """
        if not device_path.startswith("/dev/") or ".." in device_path:
            log.error("rejected suspicious device_path: %r", device_path)
            return False

        candidates = {d["path"].unpack() for d in self.ListCandidateDevices()}
        if device_path not in candidates:
            log.error("refusing CreatePersistence on %s — not in candidate "
                      "device list (not removable, or looks like boot media)",
                      device_path)
            return False

        if not passphrase or len(passphrase) < 8:
            log.error("refusing CreatePersistence — passphrase too short")
            return False

        log.warning("CreatePersistence: about to DESTROY all data on %s", device_path)

        rc, _, err = run(["wipefs", "-a", device_path], check=True)
        if rc != 0:
            log.error("wipefs failed: %s", err)
            return False

        rc, _, err = run(["parted", "-s", device_path, "mklabel", "gpt",
                          "mkpart", "primary", "0%", "100%"], check=True)
        if rc != 0:
            log.error("parted failed: %s", err)
            return False

        partition = device_path + "1"

        rc, _, err = run(
            ["cryptsetup", "luksFormat", "--batch-mode", partition, "-"],
            check=True, input_text=passphrase,
        )
        if rc != 0:
            log.error("luksFormat failed: %s", err)
            return False

        rc, _, err = run(
            ["cryptsetup", "luksOpen", partition, LUKS_MAPPER_NAME, "-"],
            check=True, input_text=passphrase,
        )
        if rc != 0:
            log.error("luksOpen failed: %s", err)
            return False

        mapper_path = f"/dev/mapper/{LUKS_MAPPER_NAME}"
        rc, _, err = run(["mkfs.ext4", "-L", PERSISTENCE_LABEL, mapper_path], check=True)
        if rc != 0:
            log.error("mkfs.ext4 failed: %s", err)
            run(["cryptsetup", "luksClose", LUKS_MAPPER_NAME], check=False)
            return False

        # live-boot's persistence.conf format: mount, then a list of
        # union-mount specs. "/ union" is the minimal whole-filesystem
        # persistence config — refine to a narrower include/exclude list
        # later if wanted (spec doesn't require narrowing this now).
        mount_tmp = Path("/mnt/raptor-persistence-setup")
        mount_tmp.mkdir(parents=True, exist_ok=True)
        rc, _, err = run(["mount", mapper_path, str(mount_tmp)], check=True)
        if rc == 0:
            (mount_tmp / "persistence.conf").write_text("/ union\n")
            run(["umount", str(mount_tmp)], check=False)
        else:
            log.error("mount for persistence.conf write failed: %s", err)

        run(["cryptsetup", "luksClose", LUKS_MAPPER_NAME], check=False)

        log.info("persistence created on %s", partition)
        return rc == 0


def main():
    bus = SystemBus()
    bus.publish("org.raptor.PersistenceManager", PersistenceManager())
    log.info("raptor-persistence-managerd started")
    GLib.MainLoop().run()


if __name__ == "__main__":
    main()
