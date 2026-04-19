#!/usr/bin/env python3
# ------------------------------------------------------------------------------------
# Developed by Carpathian, LLC.
# Website:    https://carpathian.ai
# Repository: https://github.com/Carpathian-LLC/carpathian-wg-vpn
# ------------------------------------------------------------------------------------
# File: windows/connect.py
# ------------------------------------------------------------------------------------
# Notes:
# - Lightweight WireGuard TUI for Windows.
# - Usage: python connect.py [config_name]   (run from an Administrator terminal)
# - Configs are auto-discovered from ..\configs\*.conf
# - Requires: pip install windows-curses
# ------------------------------------------------------------------------------------

# Imports:
import curses
import subprocess
import time
import sys
import re
import os
import ctypes
import shutil
from datetime import datetime
from pathlib import Path

CONFIG_DIR = Path(__file__).resolve().parent.parent / "configs"
REFRESH_HZ = 1.5

# ------------------------------------------------------------------------------------
# Binary discovery
# ------------------------------------------------------------------------------------

INSTALL_DIRS = [
    r"C:\Program Files\WireGuard",
    r"C:\Program Files (x86)\WireGuard",
]

def find_binaries():
    for d in INSTALL_DIRS:
        wg, wgx = os.path.join(d, "wg.exe"), os.path.join(d, "wireguard.exe")
        if os.path.exists(wg) and os.path.exists(wgx):
            return wg, wgx
    wg, wgx = shutil.which("wg.exe"), shutil.which("wireguard.exe")
    if wg and wgx:
        return wg, wgx
    return None, None

WG, WIREGUARD = find_binaries()

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

# ------------------------------------------------------------------------------------
# Carpathian palette and curses colour pairs
# ------------------------------------------------------------------------------------
# Brand hex: blue #1B8FF2, pink #F11C6B, green #22C55E, red #EF4444, amber #EAB308, fg #EDEDED

C_HEADER, C_UP, C_DOWN, C_DIM, C_ACCENT, C_KEY, C_BORDER, C_TITLE = range(1, 9)

def init_colors():
    curses.start_color()
    curses.use_default_colors()
    blue, pink, green, red, amber, fg = (
        curses.COLOR_BLUE, curses.COLOR_MAGENTA, curses.COLOR_GREEN,
        curses.COLOR_RED, curses.COLOR_YELLOW, curses.COLOR_WHITE,
    )
    if curses.can_change_color() and curses.COLORS >= 256:
        scale = lambda r, g, b: (r*1000//255, g*1000//255, b*1000//255)
        for idx, rgb in [(16, (0x1B, 0x8F, 0xF2)), (17, (0xF1, 0x1C, 0x6B)),
                         (18, (0x22, 0xC5, 0x5E)), (19, (0xEF, 0x44, 0x44)),
                         (20, (0xEA, 0xB3, 0x08)), (21, (0xED, 0xED, 0xED))]:
            curses.init_color(idx, *scale(*rgb))
        blue, pink, green, red, amber, fg = 16, 17, 18, 19, 20, 21
    curses.init_pair(C_HEADER, curses.COLOR_WHITE, blue)
    curses.init_pair(C_UP,     green, -1)
    curses.init_pair(C_DOWN,   red,   -1)
    curses.init_pair(C_DIM,    fg,    -1)
    curses.init_pair(C_ACCENT, blue,  -1)
    curses.init_pair(C_KEY,    amber, -1)
    curses.init_pair(C_BORDER, blue,  -1)
    curses.init_pair(C_TITLE,  pink,  -1)

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

def pick_config(stdscr, names):
    curses.curs_set(0)
    idx = 0
    while True:
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        stdscr.addstr(0, 0, " CARPATHIAN - WireGuard - select config ".ljust(w),
                      curses.color_pair(C_HEADER) | curses.A_BOLD)
        for i, n in enumerate(names):
            attr = curses.color_pair(C_ACCENT) | curses.A_BOLD if i == idx else curses.color_pair(C_DIM)
            prefix = "> " if i == idx else "  "
            try: stdscr.addstr(2 + i, 2, prefix + n, attr)
            except curses.error: pass
        try: stdscr.addstr(h - 2, 2, "[up/down] move   [enter] select   [q] quit", curses.color_pair(C_DIM))
        except curses.error: pass
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

def get_active_iface(config_name):
    """On Windows, the interface name matches the tunnel service name (config stem)."""
    out, _, rc = run([WG, "show", "interfaces"])
    if rc == 0 and out.strip():
        ifaces = out.strip().split()
        if config_name in ifaces:
            return config_name
        return ifaces[0] if ifaces else None
    return None

def is_up(config_name):
    return get_active_iface(config_name) is not None

def get_wg_stats(config_name):
    iface = get_active_iface(config_name)
    stats = {
        "interface": iface or config_name,
        "public_key": "-", "listen_port": "-", "peer": "-",
        "endpoint": "-", "allowed_ips": "-",
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
    return s if len(s) <= n else s[:n-1] + "..."

def toggle_tunnel(config_name, config_path, currently_up):
    if currently_up:
        out, err, rc = run([WIREGUARD, "/uninstalltunnelservice", config_name])
        action = "down"
    else:
        out, err, rc = run([WIREGUARD, "/installtunnelservice", str(config_path)])
        action = "up"
    if rc == 0:
        return True, f"Tunnel {action}"
    return False, err or f"wireguard.exe {action} failed (rc={rc})"

# ------------------------------------------------------------------------------------
# Drawing helpers
# ------------------------------------------------------------------------------------

def hline(win, y, x, w, ch="-"):
    try: win.addstr(y, x, ch * w, curses.color_pair(C_BORDER))
    except curses.error: pass

def box(win, y, x, h, w):
    try:
        win.addstr(y,     x, "+" + "-"*(w-2) + "+", curses.color_pair(C_BORDER))
        win.addstr(y+h-1, x, "+" + "-"*(w-2) + "+", curses.color_pair(C_BORDER))
        for i in range(1, h-1):
            win.addstr(y+i, x,     "|", curses.color_pair(C_BORDER))
            win.addstr(y+i, x+w-1, "|", curses.color_pair(C_BORDER))
    except curses.error: pass

def label(win, y, x, key, val, maxw=40):
    try:
        win.addstr(y, x, key, curses.color_pair(C_DIM))
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
    up, stats = False, {}

    while True:
        h, w = stdscr.getmaxyx()
        stdscr.erase()

        title = f" CARPATHIAN - WireGuard - {config_name} "
        stdscr.addstr(0, 0, title.ljust(w), curses.color_pair(C_HEADER) | curses.A_BOLD)
        ts = datetime.now().strftime("%H:%M:%S")
        try: stdscr.addstr(0, w - len(ts) - 1, ts, curses.color_pair(C_HEADER))
        except curses.error: pass

        if up:
            badge, bcolor = " * CONNECTED ", curses.color_pair(C_UP) | curses.A_BOLD
        else:
            badge, bcolor = " o DISCONNECTED ", curses.color_pair(C_DOWN) | curses.A_BOLD
        try: stdscr.addstr(2, 2, badge, bcolor)
        except curses.error: pass

        row = 4
        if up and stats:
            bw = min(w - 4, 72)
            box(stdscr, row, 2, 7, bw)
            try: stdscr.addstr(row, 4, " Connection ", curses.color_pair(C_ACCENT) | curses.A_BOLD)
            except curses.error: pass
            label(stdscr, row+1, 4, "Interface  : ", config_name, bw-6)
            label(stdscr, row+2, 4, "Endpoint   : ", stats.get("endpoint","-"), bw-6)
            label(stdscr, row+3, 4, "Allowed IPs: ", stats.get("allowed_ips","-"), bw-6)
            label(stdscr, row+4, 4, "Handshake  : ", stats.get("latest_handshake") or "-", bw-6)
            label(stdscr, row+5, 4, "Pub key    : ", truncate(stats.get("public_key","-"), 38), bw-6)
            row += 8

            box(stdscr, row, 2, 4, bw)
            try: stdscr.addstr(row, 4, " Traffic ", curses.color_pair(C_ACCENT) | curses.A_BOLD)
            except curses.error: pass
            rx, tx = stats.get("rx_bytes", 0), stats.get("tx_bytes", 0)
            try:
                stdscr.addstr(row+1, 4, "RX  ", curses.color_pair(C_UP) | curses.A_BOLD)
                stdscr.addstr(fmt_bytes(rx).ljust(14), curses.color_pair(C_ACCENT))
                stdscr.addstr("  TX  ", curses.color_pair(C_DOWN) | curses.A_BOLD)
                stdscr.addstr(fmt_bytes(tx), curses.color_pair(C_ACCENT))
            except curses.error: pass
            row += 6
        else:
            try: stdscr.addstr(row, 4, "No active tunnel. Press [c] to connect.", curses.color_pair(C_DIM))
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
                stdscr.addstr(f" {desc}  ", curses.color_pair(C_DIM))
                fx += len(k) + len(desc) + 3
            except curses.error: pass
        hline(stdscr, footer_y - 1, 0, w)
        stdscr.refresh()

        key = stdscr.getch()
        if key in (ord('q'), ord('Q')):
            break
        elif key in (ord('c'), ord('C')):
            status_msg, status_good = "Working...", True
            stdscr.refresh()
            ok, msg = toggle_tunnel(config_name, config_path, up)
            status_msg, status_good = msg, ok
            time.sleep(0.8)
        elif key in (ord('r'), ord('R')):
            status_msg = ""

        up = is_up(config_name)
        stats = get_wg_stats(config_name) if up else {}

def picker_wrapper(stdscr, names):
    init_colors()
    return pick_config(stdscr, names)

def main():
    if not WG or not WIREGUARD:
        print("WireGuard not found. Install it from:")
        print("  https://www.wireguard.com/install/")
        print("  or: winget install WireGuard.WireGuard")
        sys.exit(1)

    if not is_admin():
        print("This tool requires Administrator. Run your terminal as Administrator and retry.")
        sys.exit(1)

    names = list_configs()
    if not names:
        print(f"No configs found in {CONFIG_DIR}. Add *.conf files there.")
        sys.exit(1)

    if len(sys.argv) > 1:
        chosen = sys.argv[1]
        if chosen not in names:
            print(f"Config '{chosen}' not found. Available: {', '.join(names)}")
            sys.exit(1)
    elif len(names) == 1:
        chosen = names[0]
    else:
        chosen = curses.wrapper(picker_wrapper, names)
        if not chosen:
            sys.exit(0)

    config_path = CONFIG_DIR / f"{chosen}.conf"
    try:
        curses.wrapper(tui, chosen, config_path)
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
