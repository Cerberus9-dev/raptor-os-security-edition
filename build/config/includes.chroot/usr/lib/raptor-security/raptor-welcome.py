#!/usr/bin/env python3
"""First-login welcome card for Raptor OS (shown once per session user).

Kodachi-style orientation: explains modes, DNS-over-Tor, the Security
Center and where the app drawer lives. Only shows while the marker file
~/.config/raptor/welcomed is absent, then writes it.
"""
import os
import sys

MARK = os.path.expanduser("~/.config/raptor/welcomed")
if os.path.exists(MARK):
    raise SystemExit(0)

import gi  # noqa: E402

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk  # noqa: E402

TIPS = [
    ("Raptor Security Center",
     "The lock icon on the panel (or `raptor-security-center`) opens mode "
     "switching, DNS/Tor status, the firewall and the kill switch."),
    ("Modes",
     "NetworkProtection Manager and the Security Center cycle Secure "
     "\u2192 Hardened \u2192 Lockdown. Lockdown stops Tor and blocks "
     "non-loopback traffic."),
    ("DNS over Tor",
     "DNS is forced through Tor (127.0.0.1:53) by default. Turn Tor itself "
     "off only in NetworkProtection Manager if you need a plain DNS path."),
    ("Dark theme ready",
     "Greybird-dark with Papirus-Dark icons is already active; change it in "
     "Settings \u25b8 Appearance."),
    ("Finding apps",
     "Whisker menu is the red button on the bottom-left panel. Raptor tools "
     "are grouped under Raptor / Recon / Web / Passwords."),
]


class WelcomeWindow(Adw.Window):
    def __init__(self):
        super().__init__()
        self.set_title("Welcome to Raptor OS")
        self.set_default_size(560, 460)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_margin_top(24)
        box.set_margin_bottom(24)
        box.set_margin_start(28)
        box.set_margin_end(28)

        heading = Gtk.Label(label="Raptor OS Security Edition", xalign=0)
        heading.add_css_class("title-1")
        box.append(heading)

        sub = Gtk.Label(label=" The live session is locked down and ready.",
                        xalign=0)
        sub.add_css_class("dim-label")
        box.append(sub)
        box.append(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL))

        for title, body in TIPS:
            row = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            t = Gtk.Label(label=title, xalign=0)
            t.add_css_class("heading")
            b = Gtk.Label(label=body, xalign=0, wrap=True)
            b.add_css_class("body")
            row.append(t)
            row.append(b)
            box.append(row)

        spacer = Gtk.Box()
        spacer.set_vexpand(True)
        box.append(spacer)

        cta = Gtk.Button(label="Open Security Center")
        cta.add_css_class("suggested-action")
        cta.connect("clicked", self._on_open_center)
        dismiss = Gtk.Button(label="Resume session")
        dismiss.add_css_class("pill")
        dismiss.connect("clicked", lambda *_: self.close())

        buttons = Gtk.Box(spacing=8)
        buttons.set_halign(Gtk.Align.END)
        buttons.append(dismiss)
        buttons.append(cta)
        box.append(buttons)

        self.set_content(box)

    def _on_open_center(self, *_):
        import subprocess
        try:
            subprocess.Popen(["raptor-security-center"],
                             start_new_session=True)
        except OSError:
            pass
        self.close()

    def close(self, *_):
        try:
            os.makedirs(os.path.dirname(MARK), exist_ok=True)
            open(MARK, "w").write("shown\n")
        except OSError:
            pass
        super().close()


def main():
    app = Adw.Application(application_id="org.raptor.Welcome")
    app.connect("activate", lambda a: _show(a))
    app.run(sys.argv)


def _show(app):
    w = WelcomeWindow()
    w.set_application(app)
    w.present()


if __name__ == "__main__":
    main()