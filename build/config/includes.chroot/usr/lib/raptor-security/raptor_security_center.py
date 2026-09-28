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

from collections import deque  # noqa: E402

try:
    import cairo  # noqa: E402
except ImportError:  # pragma: no cover - python3-cairo absent
    cairo = None

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
        self._build_graphs(content)
        self._build_network_panel(content)
        self._build_emergency(content)

        self.refresh_status()
        GLib.timeout_add_seconds(5, self._on_timer_tick)
        # Live graphs sample on their own faster tick; 1s gives a useful
        # 60-sample (1 min) window without any real cost.
        self._net_prev = {"rx": 0, "tx": 0}
        GLib.timeout_add_seconds(1, self._on_graph_tick)

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

    # -- live performance graphs ------------------------------------------

    def _build_graphs(self, parent):
        if cairo is None:
            return

        section = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        heading = Gtk.Label(label="Live Performance", xalign=0)
        heading.add_css_class("title-4")
        section.append(heading)

        grid = Gtk.Grid(column_spacing=16, row_spacing=16, hexpand=True)
        grid.set_halign(Gtk.Align.FILL)
        self.cpu_graph = MetricGraph("CPU", "%", "{:.0f}%", (0.36, 0.72, 0.98))
        self.mem_graph = MetricGraph("Memory", "%", "{:.0f}%", (0.42, 0.88, 0.62))
        self.net_rx_graph = MetricGraph("Net down", "KB/s", "{:.1f}", (0.98, 0.55, 0.35))
        self.net_tx_graph = MetricGraph("Net up", "KB/s", "{:.1f}", (0.93, 0.42, 0.72))

        self.cpu_graph.set_ylabel("%")
        self.mem_graph.set_ylabel("%")
        self.net_rx_graph.set_ylabel("KB/s")
        self.net_tx_graph.set_ylabel("KB/s")
        grid.attach(self.cpu_graph.widget, 0, 0, 1, 1)
        grid.attach(self.mem_graph.widget, 1, 0, 1, 1)
        grid.attach(self.net_rx_graph.widget, 0, 1, 1, 1)
        grid.attach(self.net_tx_graph.widget, 1, 1, 1, 1)
        section.append(grid)
        parent.append(section)

    def _on_graph_tick(self):
        self._sample_cpu()
        self._sample_memory()
        self._sample_network()
        return True  # keep ticking

    def _sample_cpu(self):
        try:
            with open("/proc/stat") as f:
                parts = f.readline().split()
            vals = [int(x) for x in parts[1:] if x.isdigit()]
            if len(vals) < 4:
                return
            total = sum(vals)
            idle = vals[3]
            prev = getattr(self, "_cpu_prev", None)
            self._cpu_prev = (total, idle)
            if prev:
                d_total = total - prev[0]
                d_idle = idle - prev[1]
                if d_total > 0:
                    pct = max(0.0, min(100.0, (1 - d_idle / d_total) * 100.0))
                    self.cpu_graph.push(pct)
        except OSError:
            pass

    def _sample_memory(self):
        try:
            with open("/proc/meminfo") as f:
                data = dict(line.split(":", 1) for line in f)
            total = int(data["MemTotal"].strip().split()[0])
            available = int(data["MemAvailable"].strip().split()[0])
            if total > 0:
                pct = max(0.0, min(100.0, (1 - available / total) * 100.0))
                self.mem_graph.push(pct)
        except (OSError, KeyError, ValueError):
            pass

    def _sample_network(self):
        try:
            rx = tx = 0
            with open("/proc/net/dev") as f:
                f.readline(); f.readline()
                for line in f:
                    if ":" not in line:
                        continue
                    name, rest = line.split(":", 1)
                    if name.strip() == "lo":
                        continue
                    fields = rest.split()
                    rx += int(fields[0])
                    tx += int(fields[8])
            prev = self._net_prev
            d_rx = max(0, rx - prev["rx"]) / 1024.0
            d_tx = max(0, tx - prev["tx"]) / 1024.0
            prev["rx"], prev["tx"] = rx, tx
            self.net_rx_graph.push(d_rx)
            self.net_tx_graph.push(d_tx)
        except (OSError, IndexError, ValueError):
            pass

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


class MetricGraph:
    """A small labeled cairo sparkline updating in place.

    Uses a Gtk.DrawingArea redrawn on every push(); the draw callbacks scale
    samples to the widget's current width so a stretched window just draws
    more history. Falls back gracefully anywhere cairo is missing by being
    replaced with a plain bar at construction time (see SecurityCenterWindow
    respecting the module-level cairo guard).
    """

    BG = (0.055, 0.062, 0.075)
    GRID = (0.25, 0.28, 0.33)

    def __init__(self, title, unit, fmt, color, history=60):
        self.title = title
        self.unit = unit
        self.fmt = fmt
        self.color = color
        self.whole_color = tuple(1 - c for c in color)
        self.samples = deque(maxlen=history)

        self.widget = Gtk.DrawingArea()
        self.widget.set_hexpand(True)
        self.widget.set_vexpand(False)
        self.widget.set_size_request(240, 72)
        self.widget.set_draw_func(self._draw, None)

    def set_ylabel(self, text):
        pass  # width of the legend text is configured via the title

    def push(self, value):
        self.samples.append(value)
        self.widget.queue_draw()

    def _draw(self, area, ctx, width, height, data):
        ctx.set_source_rgb(*self.BG)
        ctx.paint()

        if not self.samples:
            self._draw_label(ctx, width, "idle")
            return

        lo = float(min(self.samples))
        hi = float(max(self.samples))
        if hi > lo:
            span = hi - lo
        else:
            span = max(hi, 1.0)
        pad = span * 0.1
        lo -= pad
        hi += pad
        span = (hi - lo) or 1.0

        # gridlines
        ctx.set_source_rgba(1, 1, 1, 0.05)
        ctx.set_line_width(1)
        for frac in (0.25, 0.5, 0.75):
            y = height - (height * frac)
            ctx.move_to(0, y)
            ctx.line_to(width, y)
            ctx.stroke()

        # area under the line
        ctx.move_to(0, height)
        for i, v in enumerate(self.samples):
            x = (i / (len(self.samples) - 1)) * width
            y = height - ((v - lo) / span) * (height - 12)
            ctx.line_to(x, y)
        ctx.line_to(width, height)
        ctx.close_path()
        ctx.set_source_rgba(self.color[0], self.color[1], self.color[2], 0.18)
        ctx.fill()

        # the line
        ctx.new_path()
        for i, v in enumerate(self.samples):
            x = (i / (len(self.samples) - 1)) * width
            y = height - ((v - lo) / span) * (height - 12)
            if i == 0:
                ctx.move_to(x, y)
            else:
                ctx.line_to(x, y)
        ctx.set_source_rgb(*self.color)
        ctx.set_line_width(1.6)
        ctx.stroke()

        self._draw_label(ctx, width, self.fmt.format(self.samples[-1]))

    def _draw_label(self, ctx, width, value_text):
        ctx.select_font_face("Sans",
                             cairo.FONT_SLANT_NORMAL,
                             cairo.FONT_WEIGHT_NORMAL)
        ctx.set_font_size(11)
        text = f"{self.title}: {value_text}"
        ctx.set_source_rgba(1, 1, 1, 0.85)
        ctx.move_to(6, 14)
        ctx.show_text(text)


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
