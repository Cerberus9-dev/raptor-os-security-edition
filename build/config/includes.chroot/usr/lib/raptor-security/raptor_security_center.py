#!/usr/bin/env python3
"""
Raptor Security Center — Kodachi-style security dashboard for Raptor OS.

Renders Mode Manager's GetStatus() as a two-panel overview:

  * Security panel — mode selector + the state Mode Manager verifies live
    (firewall, kill switch, VPN, Tor, MAC randomization, persistence).
  * System panel  — CPU %, memory, root disk, uptime.
  * Network panel — up interfaces, DNS servers, and the public IP as seen
    *through Tor* (never the clearnet IP).

It is a pure view. It never touches nftables, sysctl, or systemd directly,
and never renders a status it hasn't just fetched from GetStatus() — see
the module docstring in raptor_mode_managerd.py for why that split exists
and why every unverifiable value renders neutral/"unknown" rather than
fake-good (spec section 26).
"""

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk  # noqa: E402
from pydbus import SystemBus  # noqa: E402

BUS_NAME = "org.raptor.ModeManager"
OBJECT_PATH = "/org/raptor/ModeManager"

SHUTDOWN_BUS_NAME = "org.raptor.EmergencyShutdown"
SHUTDOWN_OBJECT_PATH = "/org/raptor/EmergencyShutdown"

MODES = ["secure", "hardened", "lockdown"]
MODE_LABELS = {"secure": "Secure", "hardened": "Hardened", "lockdown": "Lockdown"}

STATUS_FIELD_LABELS = {
    "firewall_active": "Firewall",
    "kill_switch_armed": "Kill Switch",
    "vpn_state": "VPN",
    "tor_state": "Tor",
    "mac_randomization": "MAC Randomization",
    "persistence": "Persistence",
}

# Values that render as a "good/expected" state per field. Everything else
# (including "unknown") renders neutral — never green (section 26).
GOOD_VALUES = {
    "firewall_active": {"active"},
    "kill_switch_armed": {"armed", "not_armed"},
    "vpn_state": {"connected"},
    "tor_state": {"active"},
    "mac_randomization": {"enabled"},
    "persistence": {"encrypted_active", "none"},
}

SYSTEM_FIELDS = [
    ("cpu_percent", "CPU"),
    ("mem_percent", "Memory"),
    ("disk_percent", "Disk"),
    ("uptime", "Uptime"),
    ("interfaces", "Interfaces"),
    ("dns_servers", "DNS"),
    ("public_ip", "Public IP (via Tor)"),
]


class SecurityCenterWindow(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title="Raptor Security Center")
        self.set_default_size(860, 620)

        try:
            self.bus = SystemBus()
            self.manager = self.bus.get(BUS_NAME, OBJECT_PATH)
            self.dbus_available = True
        except Exception as e:
            self.manager = None
            self.dbus_available = False
            self._dbus_error = str(e)

        try:
            self.shutdown_manager = self.bus.get(
                SHUTDOWN_BUS_NAME, SHUTDOWN_OBJECT_PATH
            )
            self.shutdown_available = True
        except Exception as e:
            self.shutdown_manager = None
            self.shutdown_available = False
            self._shutdown_dbus_error = str(e)

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        root.set_margin_top(24)
        root.set_margin_bottom(24)
        root.set_margin_start(24)
        root.set_margin_end(24)

        header = Adw.HeaderBar()
        toolbar_view = Adw.ToolbarView()
        toolbar_view.add_top_bar(header)
        toolbar_view.set_content(root)
        self.set_content(toolbar_view)

        if not self.dbus_available:
            banner = Adw.Banner(
                title=f"Cannot reach Mode Manager: {self._dbus_error}. "
                      f"Status shown is unavailable, not fake-good.",
                revealed=True,
            )
            root.append(banner)

        scroller = Gtk.ScrolledWindow(vexpand=True)
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        root.append(scroller)

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=20)
        scroller.set_child(content)

        self._build_mode_header(content)
        self._build_security_panel(content)
        self._build_system_panel(content)
        self._build_network_panel(content)
        self._build_emergency(content)

        self.refresh_status()
        GLib.timeout_add_seconds(5, self._on_timer_tick)

    # -- layout helpers ----------------------------------------------------

    def _panel(self, parent, title):
        frame = Adw.PreferencesGroup(title=title)
        parent.append(frame)
        return frame

    def _row(self, parent, label):
        row = Adw.ActionRow(title=label)
        parent.add(row)
        return row

    def _build_mode_header(self, parent):
        self.mode_label = Gtk.Label(label="Current mode: unknown")
        self.mode_label.add_css_class("title-1")
        parent.append(self.mode_label)

        mode_switcher = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL,
                                spacing=8, homogeneous=True)
        self.mode_buttons = {}
        for mode in MODES:
            btn = Gtk.ToggleButton(label=MODE_LABELS[mode])
            btn.connect("clicked", self._on_mode_button_clicked, mode)
            mode_switcher.append(btn)
            self.mode_buttons[mode] = btn
        parent.append(mode_switcher)

        self.lockdown_notice = Adw.Banner(
            title="Lockdown blocks all outbound traffic except through an "
                  "active VPN or Tor tunnel. Ordinary apps that need direct "
                  "internet access will stop working until you leave Lockdown."
        )
        self.lockdown_notice.revealed = False
        parent.append(self.lockdown_notice)

    def _build_security_panel(self, parent):
        panel = self._panel(parent, "Security Status")
        self.status_rows = {}
        for field, label in STATUS_FIELD_LABELS.items():
            row = self._row(panel, label)
            self.status_rows[field] = row
            row.set_activatable(False)

    def _build_system_panel(self, parent):
        panel = self._panel(parent, "System")
        self.system_rows = {}
        for field, label in [("cpu_percent", "CPU"),
                             ("mem_percent", "Memory"),
                             ("disk_percent", "Disk"),
                             ("uptime", "Uptime")]:
            row = self._row(panel, label)
            row.set_activatable(False)
            self.system_rows[field] = row

    def _build_network_panel(self, parent):
        panel = self._panel(parent, "Network")
        self.network_rows = {}
        for field, label in [("interfaces", "Interfaces"),
                             ("dns_servers", "DNS Servers"),
                             ("public_ip", "Public IP (via Tor)")]:
            row = self._row(panel, label)
            row.set_activatable(False)
            self.network_rows[field] = row

    def _build_emergency(self, parent):
        emergency_btn = Gtk.Button(label="Emergency Shutdown & Clear Session")
        emergency_btn.add_css_class("destructive-action")
        emergency_btn.connect("clicked", self._on_emergency_shutdown_clicked)
        parent.append(emergency_btn)

    # -- D-Bus interaction -----------------------------------------------

    def _on_mode_button_clicked(self, button, mode):
        if not self.dbus_available:
            return
        success = self.manager.SetMode(mode)
        if not success:
            button.set_active(False)
            print(f"[security-center] Failed to switch to {MODE_LABELS[mode]}")
        self.refresh_status()

    def _on_timer_tick(self):
        self.refresh_status()
        return True  # keep the timer running

    def refresh_status(self):
        if not self.dbus_available:
            return

        current_mode = self.manager.GetMode()
        self.mode_label.set_label(
            f"Current mode: {MODE_LABELS.get(current_mode, current_mode)}"
        )
        for mode, btn in self.mode_buttons.items():
            btn.set_active(mode == current_mode)
        self.lockdown_notice.revealed = (current_mode == "lockdown")

        status = self.manager.GetStatus()

        for field, row in self.status_rows.items():
            value = status.get(field, "unknown")
            row.set_subtitle(str(value.value if hasattr(value, "value") else value))

        for field, row in self.system_rows.items():
            value = status.get(field, "unknown")
            row.set_subtitle(str(value.value if hasattr(value, "value") else value))

        for field, row in self.network_rows.items():
            value = status.get(field, "unknown")
            row.set_subtitle(str(value.value if hasattr(value, "value") else value))

    # -- Emergency Shutdown ----------------------------------------------

    def _on_emergency_shutdown_clicked(self, button):
        if not self.shutdown_available:
            print(f"[security-center] Cannot reach Emergency Shutdown Manager: "
                  f"{self._shutdown_dbus_error}")
            return

        info = self.shutdown_manager.GetPersistenceInfo()
        persistence_active = info.get("persistence_active", False)
        swap_active = info.get("swap_active", False)

        body_lines = [
            "This will terminate the current session and clear temporary "
            "session data where supported.",
        ]
        if persistence_active:
            body_lines.append(
                "Encrypted persistence is mounted and will remain untouched."
            )
        else:
            body_lines.append(
                "No persistence volume is mounted — this session is fully "
                "amnesic already."
            )
        if swap_active:
            body_lines.append(
                "\u26a0 Swap is currently active. Deactivating it does not "
                "erase data already written to swap on disk — this session "
                "cannot guarantee no trace remains if swap was used."
            )

        # Adw.AlertDialog / Adw.MessageDialog only exist in libadwaita >= 1.3
        # (message for the latter: 1.5); bookworm ships 1.2, so any use would
        # crash at click time. Fall back to a plain Gtk modal that exposes the
        # same "response" signalling contract.
        dialog = ConfirmDialog(
            heading="\u26a0 Emergency Shutdown",
            body="\n\n".join(body_lines),
        )
        dialog.connect("response", self._on_emergency_dialog_response)
        dialog.present(self)

    def _on_emergency_dialog_response(self, dialog, response):
        if response != "shutdown":
            return
        live_user = GLib.get_user_name() or "user"
        accepted = self.shutdown_manager.TriggerEmergencyShutdown(
            live_user, True
        )
        if not accepted:
            print("[security-center] Emergency Shutdown was refused — "
                  "check permissions/logs")


class ConfirmDialog(Gtk.Window):
    """Plain Gtk modal confirmation exposing a "response" signal.

    libadwaita in bookworm is 1.2, which predates Adw.AlertDialog (1.3) and
    Adw.MessageDialog (1.5). Those classes and their ResponseAppearance API
    are therefore unavailable on the target OS; this window provides the same
    two-button, "cancel" default, response-signal contract without them.
    """

    __gsignals__ = {
        "response": (GLib.SignalFlags.RUN_LAST, None, (str,)),
    }

    RESPONSES = [
        ("shutdown", "Shut Down & Clear Session", "destructive-action"),
        ("cancel", "Cancel", None),
    ]

    def __init__(self, heading, body, **kwargs):
        super().__init__(**kwargs)
        self.set_title(heading)
        self.set_default_size(420, -1)
        self.set_resizable(False)
        self.set_modal(True)

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        content.set_margin_top(24)
        content.set_margin_bottom(24)
        content.set_margin_start(24)
        content.set_margin_end(24)

        title_label = Gtk.Label(label=heading, xalign=0)
        title_label.add_css_class("title-1")
        title_label.set_wrap(True)
        content.append(title_label)

        body_label = Gtk.Label(label=body, xalign=0)
        body_label.set_wrap(True)
        body_label.set_wrap_mode(3)  # GTK WrapMode.WORD_CHAR
        body_label.set_xalign(0)
        content.append(body_label)

        button_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        button_box.set_halign(Gtk.Align.END)
        for response_id, label, css_class in self.RESPONSES:
            button = Gtk.Button(label=label)
            if css_class:
                button.add_css_class(css_class)
            if response_id == "cancel":
                button.set_can_default(True)
                self.set_default_widget(button)
            button.connect("clicked", self._on_button, response_id)
            button_box.append(button)
        content.append(button_box)

        self.set_child(content)
        self.connect("close-request", self._on_close_request)

    def _on_button(self, button, response_id):
        self._respond(response_id)

    def _on_close_request(self, window):
        self._respond("cancel")
        return True

    def _respond(self, response_id):
        self.emit("response", response_id)
        self.destroy()


class SecurityCenterApp(Adw.Application):
    def __init__(self):
        super().__init__(application_id="org.raptor.SecurityCenter")

    def do_activate(self):
        win = self.props.active_window
        if not win:
            win = SecurityCenterWindow(self)
        win.present()


if __name__ == "__main__":
    import sys
    app = SecurityCenterApp()
    sys.exit(app.run(sys.argv))
