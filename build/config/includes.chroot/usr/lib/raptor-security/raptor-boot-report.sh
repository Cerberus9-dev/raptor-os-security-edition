#!/bin/sh
# One-shot: snapshots the live desktop state to $HOME/raptor-boot-report.txt
# the first time the user logs in. The report is a plain text file any user
# can open with the file manager, so a broken (or healthy) session can be
# diagnosed without a terminal — paste its contents back to the dev loop.
set -u

REPORT="$HOME/raptor-boot-report.txt"
SELF_DESKTOP="$HOME/.config/autostart/raptor-bootreport.desktop"

if [ -s "$REPORT" ]; then
    rm -f "$SELF_DESKTOP" 2>/dev/null
    exit 0
fi

# let the session settle before probing
sleep 20

{
    echo "== Raptor live boot report ($(date -Is)) =="
    echo "user: $(id -un 2>/dev/null)   home: $HOME"
    echo "desktop session:  ${XDG_CURRENT_DESKTOP:-<unset>}"
    echo "session type:     ${XDG_SESSION_TYPE:-<unset>}"
    echo
    echo "-- display manager --"
    systemctl is-active lightdm 2>/dev/null || echo "lightdm: inactive/failed"
    echo
    echo "-- session pieces (running?) --"
    for p in xfce4-session xfce4-panel xfsettingsd xfdesktop xfwm4; do
        if pgrep -x "$p" >/dev/null 2>&1; then
            echo "  running: $p"
        else
            echo "  NOT running: $p"
        fi
    done
    echo
    echo "-- xfconf channels in effect --"
    if command -v xfconf-query >/dev/null 2>&1; then
        echo "  theme:      $(xfconf-query -c xsettings -p /Net/ThemeName 2>/dev/null || echo '<unset>')"
        echo "  icons:      $(xfconf-query -c xsettings -p /Net/IconThemeName 2>/dev/null || echo '<unset>')"
        echo "  wallpaper:  $(xfconf-query -c xfce4-desktop -p /backdrop/screen0/monitor0/workspace0/last-image 2>/dev/null || echo '<unset>')"
        echo "  panels:     $(xfconf-query -c xfce4-panel -p /panels 2>/dev/null | tr -d '[:space:]' || echo '<unset>')"
    else
        echo "  xfconf-query not installed"
    fi
    echo
    echo "-- per-channel xml files in \$HOME --"
    ls -la "$HOME/.config/xfce4/xfconf/xfce-perchannel-xml/" 2>/dev/null \
        || echo "  no ~/.config/xfce4/xfconf/xfce-perchannel-xml (home not seeded)"
    echo
    echo "-- security-center dashboard --"
    command -v raptor-security-center 2>/dev/null || echo "  raptor-security-center: missing"
    pgrep -af "raptor-security-center" 2>/dev/null || echo "  not running"
    echo
    echo "-- lightdm autologin config --"
    cat /etc/lightdm/lightdm.conf.d/80-raptor-autologin.conf 2>/dev/null \
        || echo "  no autologin conf"
    echo
    echo "-- kernel cmdline --"
    cat /proc/cmdline
    echo
} > "$REPORT" 2>&1

# one-shot: hide ourselves from subsequent logins
rm -f "$SELF_DESKTOP" "$HOME/.config/autostart/raptor-bootreport.desktop" 2>/dev/null
exit 0