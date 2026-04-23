#!/usr/bin/env python3
# ------------------------------------------------------------------------------------
# Developed by Carpathian, LLC.
# Website:    https://carpathian.ai
# Repository: https://github.com/Carpathian-LLC/carpathian-wg-vpn
# ------------------------------------------------------------------------------------
# File: linux/connect.py
# ------------------------------------------------------------------------------------
# Notes:
# - Lightweight WireGuard TUI for Linux.
# - Usage: sudo python3 connect.py [config_name]
# - Configs are auto-discovered from ../configs/*.conf
# - Supports wireguard-tools installed via apt, dnf, pacman, zypper, or manual.
# ------------------------------------------------------------------------------------

# Imports:
import curses
import subprocess
import time
import sys
import re
import os
import shutil
from datetime import datetime
from pathlib import Path

CONFIG_DIR = Path(__file__).resolve().parent.parent / "configs"
REFRESH_HZ = 1.5

# ------------------------------------------------------------------------------------
# Binary discovery (standard Linux paths + PATH fallback)
# ------------------------------------------------------------------------------------

PREFIXES = ["/usr/bin", "/usr/local/bin", "/usr/sbin", "/usr/local/sbin"]

def find_binaries():
    for p in PREFIXES:
        wg, wgq = f"{p}/wg", f"{p}/wg-quick"
        if os.path.exists(wg) and os.path.exists(wgq):
            return wg, wgq
    wg, wgq = shutil.which("wg"), shutil.which("wg-quick")
    if wg and wgq:
        return wg, wgq
    return None, None

WG, WG_QUICK = find_binaries()

# ------------------------------------------------------------------------------------
# Curses colour pairs (terminal-native; readable on light and dark backgrounds)
# ------------------------------------------------------------------------------------

C_HEADER, C_UP, C_DOWN, C_DIM, C_ACCENT, C_KEY, C_BORDER = range(1, 8)

def init_colors():
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(C_HEADER, curses.COLOR_WHITE,  curses.COLOR_BLUE)
    curses.init_pair(C_UP,     curses.COLOR_GREEN,  -1)
    curses.init_pair(C_DOWN,   curses.COLOR_RED,    -1)
    curses.init_pair(C_DIM,    -1,                  -1)
    curses.init_pair(C_ACCENT, curses.COLOR_CYAN,   -1)
    curses.init_pair(C_KEY,    curses.COLOR_YELLOW, -1)
    curses.init_pair(C_BORDER, -1,                  -1)

def run(cmd):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except Exception as e:
        return "", str(e), 1

def list_configs():
    if not CONFIG_DIR.is_dir():
        return []
    return sorted(p.stem for p in CONFIG_DIR.glob("*.conf") if p.stem != "example")

def pick_config(stdscr, names, active=frozenset()):
    """Simple arrow-key menu. Returns selected name or None."""
    curses.curs_set(0)
    idx = 0
    while True:
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        stdscr.addstr(0, 0, " CARPATHIAN · WireGuard · select config ".ljust(w),
                      curses.color_pair(C_HEADER) | curses.A_BOLD)
        for i, n in enumerate(names):
            attr = curses.color_pair(C_ACCENT) | curses.A_BOLD if i == idx else curses.color_pair(C_DIM) | curses.A_DIM
            prefix = "▶ " if i == idx else "  "
            try:
                stdscr.addstr(2 + i, 2, prefix + n, attr)
                if n in active:
                    stdscr.addstr("  [active]", curses.color_pair(C_UP) | curses.A_BOLD)
            except curses.error:
                pass
        try:
            stdscr.addstr(h - 2, 2, "[↑/↓] move   [enter] select   [q] quit",
                          curses.color_pair(C_DIM) | curses.A_DIM)
        except curses.error:
            pass
        stdscr.refresh()
        k = stdscr.getch()
        if k in (curses.KEY_UP, ord('k')):
            idx = (idx - 1) % len(names)
        elif k in (curses.KEY_DOWN, ord('j')):
            idx = (idx + 1) % len(names)
        elif k in (curses.KEY_ENTER, 10, 13):
            return names[idx]
        elif k in (ord('q'), ord('Q')):
            return None

# ------------------------------------------------------------------------------------
# WireGuard helpers
# ------------------------------------------------------------------------------------

def get_active_interfaces():
    """Return the names of currently active WireGuard tunnel interfaces."""
    out, _, rc = run([WG, "show", "interfaces"])
    if rc == 0 and out.strip():
        return out.strip().split()
    return []

def get_active_iface(config_name):
    """Resolve config_name to the live kernel interface, or None.

    On Linux, wg-quick names the interface after the config file stem
    (e.g. example_conf.conf → interface 'example_conf'), so the
    interface name matches the config name directly.
    """
    return config_name if config_name in get_active_interfaces() else None

def get_active_configs(names):
    """Return the subset of config names whose tunnels are currently up."""
    active = get_active_interfaces()
    return [n for n in names if n in active]

def is_up(config_name):
    return get_active_iface(config_name) is not None

def get_wg_stats(config_name, iface=None):
    if iface is None:
        iface = get_active_iface(config_name)
    stats = {
        "interface": iface or config_name,
        "public_key": "—", "listen_port": "—", "peer": "—",
        "endpoint": "—", "allowed_ips": "—",
        "rx_bytes": 0, "tx_bytes": 0, "latest_handshake": None,
    }
    if not iface:
        return stats
    out, _, rc = run([WG, "show", iface])
    if rc != 0 or not out:
        return stats
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("public key:"):
            stats["public_key"] = line.split(":", 1)[1].strip()
        elif line.startswith("listening port:"):
            stats["listen_port"] = line.split(":", 1)[1].strip()
        elif line.startswith("peer:"):
            stats["peer"] = line.split(":", 1)[1].strip()
        elif line.startswith("endpoint:"):
            stats["endpoint"] = line.split(":", 1)[1].strip()
        elif line.startswith("allowed ips:"):
            stats["allowed_ips"] = line.split(":", 1)[1].strip()
        elif line.startswith("transfer:"):
            m = re.search(r"([\d.]+)\s*(\w+)\s+received.*?([\d.]+)\s*(\w+)\s+sent", line)
            if m:
                stats["rx_bytes"] = parse_transfer(m.group(1), m.group(2))
                stats["tx_bytes"] = parse_transfer(m.group(3), m.group(4))
        elif line.startswith("latest handshake:"):
            stats["latest_handshake"] = line.split(":", 1)[1].strip()
    return stats

def parse_transfer(val, unit):
    v = float(val); unit = unit.lower()
    if "kib" in unit or "kb" in unit: return v * 1024
    if "mib" in unit or "mb" in unit: return v * 1024 ** 2
    if "gib" in unit or "gb" in unit: return v * 1024 ** 3
    return v

def fmt_bytes(b):
    if b >= 1024**3: return f"{b/1024**3:.2f} GiB"
    if b >= 1024**2: return f"{b/1024**2:.2f} MiB"
    if b >= 1024:    return f"{b/1024:.1f} KiB"
    return f"{int(b)} B"

def truncate(s, n):
    return s if len(s) <= n else s[:n-1] + "…"

def toggle_tunnel(config_path, currently_up):
    action = "down" if currently_up else "up"
    out, err, rc = run([WG_QUICK, action, str(config_path)])
    if rc == 0:
        return True, f"Tunnel {action}"
    return False, err or f"wg-quick {action} failed (rc={rc})"

# ------------------------------------------------------------------------------------
# Drawing helpers
# ------------------------------------------------------------------------------------

def hline(win, y, x, w, ch="─"):
    try: win.addstr(y, x, ch * w, curses.color_pair(C_BORDER) | curses.A_DIM)
    except curses.error: pass

def box(win, y, x, h, w):
    attr = curses.color_pair(C_BORDER) | curses.A_DIM
    try:
        win.addstr(y,     x, "┌" + "─"*(w-2) + "┐", attr)
        win.addstr(y+h-1, x, "└" + "─"*(w-2) + "┘", attr)
        for i in range(1, h-1):
            win.addstr(y+i, x,     "│", attr)
            win.addstr(y+i, x+w-1, "│", attr)
    except curses.error: pass

def label(win, y, x, key, val, maxw=40):
    try:
        win.addstr(y, x, key, curses.color_pair(C_DIM) | curses.A_DIM)
        win.addstr(y, x+len(key), truncate(str(val), maxw - len(key)),
                   curses.color_pair(C_ACCENT))
    except curses.error: pass

# ------------------------------------------------------------------------------------
# Main TUI loop
# ------------------------------------------------------------------------------------

def tui(stdscr, config_name, config_path):
    init_colors()
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.timeout(int(REFRESH_HZ * 1000))

    status_msg, status_good = "", True
    up, stats, tick = False, {}, 0

    while True:
        h, w = stdscr.getmaxyx()
        stdscr.erase()

        title = f" CARPATHIAN · WireGuard · {config_name} "
        stdscr.addstr(0, 0, title.ljust(w), curses.color_pair(C_HEADER) | curses.A_BOLD)
        ts = datetime.now().strftime("%H:%M:%S")
        try: stdscr.addstr(0, w - len(ts) - 1, ts, curses.color_pair(C_HEADER))
        except curses.error: pass

        if up:
            badge, bcolor = " ● CONNECTED ", curses.color_pair(C_UP) | curses.A_BOLD
        else:
            badge, bcolor = " ○ DISCONNECTED ", curses.color_pair(C_DOWN) | curses.A_BOLD
        try: stdscr.addstr(2, 2, badge, bcolor)
        except curses.error: pass

        row = 4
        if up and stats:
            bw = min(w - 4, 72)
            box(stdscr, row, 2, 7, bw)
            try: stdscr.addstr(row, 4, " Connection ", curses.color_pair(C_ACCENT) | curses.A_BOLD)
            except curses.error: pass
            label(stdscr, row+1, 4, "Interface  : ", stats.get("interface", config_name), bw-6)
            label(stdscr, row+2, 4, "Endpoint   : ", stats.get("endpoint","—"), bw-6)
            label(stdscr, row+3, 4, "Allowed IPs: ", stats.get("allowed_ips","—"), bw-6)
            label(stdscr, row+4, 4, "Handshake  : ", stats.get("latest_handshake") or "—", bw-6)
            label(stdscr, row+5, 4, "Pub key    : ", truncate(stats.get("public_key","—"), 38), bw-6)
            row += 8

            box(stdscr, row, 2, 4, bw)
            try: stdscr.addstr(row, 4, " Traffic ", curses.color_pair(C_ACCENT) | curses.A_BOLD)
            except curses.error: pass
            rx, tx = stats.get("rx_bytes", 0), stats.get("tx_bytes", 0)
            try:
                stdscr.addstr(row+1, 4, "↓ RX  ", curses.color_pair(C_UP) | curses.A_BOLD)
                stdscr.addstr(fmt_bytes(rx).ljust(14), curses.color_pair(C_ACCENT))
                stdscr.addstr("  ↑ TX  ", curses.color_pair(C_DOWN) | curses.A_BOLD)
                stdscr.addstr(fmt_bytes(tx), curses.color_pair(C_ACCENT))
            except curses.error: pass
            row += 6
        else:
            try: stdscr.addstr(row, 4, "No active tunnel. Press [c] to connect.",
                               curses.color_pair(C_DIM) | curses.A_DIM)
            except curses.error: pass
            row += 2

        if status_msg:
            color = curses.color_pair(C_UP) if status_good else curses.color_pair(C_DOWN)
            try: stdscr.addstr(row, 2, f"  {status_msg}", color)
            except curses.error: pass
            row += 1

        footer_y = h - 2
        keys = [("[c]", "connect" if not up else "disconnect"), ("[r]", "refresh"), ("[q]", "quit")]
        fx = 2
        for k, desc in keys:
            try:
                stdscr.addstr(footer_y, fx, k, curses.color_pair(C_KEY) | curses.A_BOLD)
                stdscr.addstr(f" {desc}  ", curses.color_pair(C_DIM) | curses.A_DIM)
                fx += len(k) + len(desc) + 3
            except curses.error: pass
        hline(stdscr, footer_y - 1, 0, w)
        stdscr.refresh()

        key = stdscr.getch()
        if key in (ord('q'), ord('Q')):
            break
        elif key in (ord('c'), ord('C')):
            ok, msg = toggle_tunnel(config_path, up)
            status_msg = "" if ok else msg
            status_good = ok
        elif key in (ord('r'), ord('R')):
            status_msg = ""

        iface = get_active_iface(config_name)
        up = iface is not None
        stats = get_wg_stats(config_name, iface=iface) if up else {}
        tick += 1

def picker_wrapper(stdscr, names, active=frozenset()):
    init_colors()
    return pick_config(stdscr, names, active=active)

def main():
    if not WG or not WG_QUICK:
        print("WireGuard tools not found on this system.\n")
        print("Install with one of:")
        print("  Debian/Ubuntu:  sudo apt install wireguard-tools")
        print("  Fedora/RHEL:    sudo dnf install wireguard-tools")
        print("  Arch Linux:     sudo pacman -S wireguard-tools")
        print("  openSUSE:       sudo zypper install wireguard-tools")
        print(f"\nThen re-run: sudo python3 {sys.argv[0]}")
        sys.exit(1)

    if os.geteuid() != 0:
        print(f"This tool requires root. Run with: sudo python3 {sys.argv[0]}")
        sys.exit(1)

    names = list_configs()
    if not names:
        print(f"No configs found in {CONFIG_DIR}. Add *.conf files there.")
        sys.exit(1)

    active = get_active_configs(names)

    if len(sys.argv) > 1:
        chosen = sys.argv[1]
        if chosen not in names:
            print(f"Config '{chosen}' not found. Available: {', '.join(names)}")
            sys.exit(1)
    elif len(active) == 1:
        chosen = active[0]
    elif len(names) == 1:
        chosen = names[0]
    else:
        chosen = curses.wrapper(picker_wrapper, names, frozenset(active))
        if not chosen:
            sys.exit(0)

    config_path = CONFIG_DIR / f"{chosen}.conf"
    try:
        curses.wrapper(tui, chosen, config_path)
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
