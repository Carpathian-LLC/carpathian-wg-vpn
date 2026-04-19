#!/usr/bin/env python3
# ------------------------------------------------------------------------------------
# Developed by Carpathian, LLC.
# Website:    https://carpathian.ai
# Repository: https://github.com/Carpathian-LLC/carpathian-wg-vpn
# ------------------------------------------------------------------------------------
# File: windows/connect.py
# ------------------------------------------------------------------------------------
# Notes:
# - Lightweight WireGuard TUI for Windows. Standard library only (msvcrt + ANSI).
# - Usage: python connect.py [config_name]   (run from an Administrator terminal)
# - Configs are auto-discovered from ..\configs\*.conf
# ------------------------------------------------------------------------------------

import os
import re
import sys
import time
import ctypes
import msvcrt
import shutil
import subprocess
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
# ANSI colours and terminal control (Windows 10+ after enable_vt_mode)
# ------------------------------------------------------------------------------------

ESC = "\x1b["
RESET    = ESC + "0m"
BOLD     = ESC + "1m"
DIM      = ESC + "2m"
FG_RED   = ESC + "31m"
FG_GREEN = ESC + "32m"
FG_YELLOW= ESC + "33m"
FG_CYAN  = ESC + "36m"
FG_WHITE = ESC + "97m"   # bright white
BG_BLUE  = ESC + "44m"
CLEAR    = ESC + "2J"
HOME     = ESC + "H"
CLR_LINE = ESC + "K"
CLR_DOWN = ESC + "J"
HIDE_CUR = ESC + "?25l"
SHOW_CUR = ESC + "?25h"

def goto(y, x):
    return f"{ESC}{y+1};{x+1}H"

def enable_vt_mode():
    """Turn on ANSI escape processing on the Windows console."""
    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_ulong()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            # 0x4 = ENABLE_VIRTUAL_TERMINAL_PROCESSING
            kernel32.SetConsoleMode(handle, mode.value | 0x4)
    except Exception:
        pass

def term_size():
    s = shutil.get_terminal_size((80, 24))
    return s.lines, s.columns

# ------------------------------------------------------------------------------------
# Keyboard input (non-blocking, with timeout)
# ------------------------------------------------------------------------------------

def read_key(timeout_sec):
    """Poll for a keypress for up to timeout_sec. Returns:
       ('char', b'x') | ('arrow', 'up'/'down') | ('enter',) | None
    """
    end = time.monotonic() + timeout_sec
    while time.monotonic() < end:
        if msvcrt.kbhit():
            ch = msvcrt.getch()
            if ch in (b'\x00', b'\xe0'):
                ch2 = msvcrt.getch()
                arrows = {b'H': 'up', b'P': 'down', b'K': 'left', b'M': 'right'}
                return ('arrow', arrows.get(ch2))
            if ch in (b'\r', b'\n'):
                return ('enter',)
            return ('char', ch)
        time.sleep(0.02)
    return None

# ------------------------------------------------------------------------------------
# WireGuard helpers
# ------------------------------------------------------------------------------------

_NO_WINDOW = 0x08000000

def run(cmd):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=8,
                           creationflags=_NO_WINDOW)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except Exception as e:
        return "", str(e), 1

def list_configs():
    if not CONFIG_DIR.is_dir():
        return []
    return sorted(p.stem for p in CONFIG_DIR.glob("*.conf") if p.stem != "example")

def get_active_interfaces():
    """Return the names of currently active WireGuard tunnel interfaces."""
    out, _, rc = run([WG, "show", "interfaces"])
    if rc == 0 and out.strip():
        return out.strip().split()
    return []

def get_active_iface(config_name):
    return config_name if config_name in get_active_interfaces() else None

def is_up(config_name):
    return get_active_iface(config_name) is not None

def get_wg_stats(config_name, iface=None):
    if iface is None:
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
    return s if len(s) <= n else s[:max(1, n-1)] + "..."

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

def write(*parts):
    sys.stdout.write("".join(parts))

def flush():
    sys.stdout.flush()

def put(y, x, s):
    """Returns a single positioned string; callers concat and flush once per frame."""
    return goto(y, x) + s

def box(y, x, h, w):
    parts = [put(y, x, DIM + "+" + "-"*(w-2) + "+" + RESET)]
    for i in range(1, h-1):
        parts.append(put(y+i, x,     DIM + "|" + RESET))
        parts.append(put(y+i, x+w-1, DIM + "|" + RESET))
    parts.append(put(y+h-1, x, DIM + "+" + "-"*(w-2) + "+" + RESET))
    return "".join(parts)

def label(y, x, key, val, maxw):
    v = truncate(str(val), maxw - len(key))
    return put(y, x, DIM + key + RESET + FG_CYAN + v + RESET)

# ------------------------------------------------------------------------------------
# Config picker
# ------------------------------------------------------------------------------------

def pick_config(names, active=frozenset()):
    idx = 0
    write(HIDE_CUR, CLEAR, HOME)
    flush()
    try:
        while True:
            rows, cols = term_size()
            header = " CARPATHIAN - WireGuard - select config "
            header_padded = header + " " * max(0, cols - len(header))
            frame = [HOME, BG_BLUE + FG_WHITE + BOLD + header_padded + RESET, CLR_LINE]
            for i, n in enumerate(names):
                badge = (FG_GREEN + "  [active]" + RESET) if n in active else ""
                if i == idx:
                    frame.append(put(2 + i, 2, FG_CYAN + BOLD + "> " + n + RESET + badge + CLR_LINE))
                else:
                    frame.append(put(2 + i, 2, DIM + "  " + n + RESET + badge + CLR_LINE))
            frame.append(put(rows - 2, 2, DIM + "[up/down] move   [enter] select   [q] quit" + RESET + CLR_LINE))
            frame.append(CLR_DOWN)
            write(*frame)
            flush()

            k = read_key(3600)
            if k is None:
                continue
            if k[0] == 'arrow':
                if k[1] == 'up':   idx = (idx - 1) % len(names)
                elif k[1] == 'down': idx = (idx + 1) % len(names)
            elif k[0] == 'enter':
                return names[idx]
            elif k[0] == 'char':
                c = k[1].lower()
                if c in (b'q',): return None
                if c == b'k': idx = (idx - 1) % len(names)
                if c == b'j': idx = (idx + 1) % len(names)
    finally:
        write(SHOW_CUR, RESET)
        flush()

# ------------------------------------------------------------------------------------
# Main TUI loop
# ------------------------------------------------------------------------------------

def tui(config_name, config_path):
    write(HIDE_CUR, CLEAR, HOME)
    flush()

    status_msg, status_good = "", True
    up, stats = False, {}
    last_refresh = 0.0
    redraw_deadline = 1.0 / REFRESH_HZ

    try:
        while True:
            # Refresh stats at REFRESH_HZ.
            now = time.monotonic()
            if now - last_refresh >= redraw_deadline:
                iface = config_name if config_name in get_active_interfaces() else None
                up = iface is not None
                stats = get_wg_stats(config_name, iface=iface) if up else {}
                last_refresh = now

            rows, cols = term_size()
            frame = [HOME]

            # Header
            title = f" CARPATHIAN - WireGuard - {config_name} "
            title_padded = title + " " * max(0, cols - len(title))
            frame.append(BG_BLUE + FG_WHITE + BOLD + title_padded + RESET + CLR_LINE)
            ts = datetime.now().strftime("%H:%M:%S")
            frame.append(put(0, max(0, cols - len(ts) - 1), BG_BLUE + FG_WHITE + ts + RESET))

            # Status badge
            if up:
                frame.append(put(2, 2, FG_GREEN + BOLD + " * CONNECTED " + RESET + CLR_LINE))
            else:
                frame.append(put(2, 2, FG_RED + BOLD + " o DISCONNECTED " + RESET + CLR_LINE))

            # Clear rows between badge and body
            frame.append(put(3, 0, CLR_LINE))

            row = 4
            if up and stats:
                bw = min(cols - 4, 72)
                frame.append(box(row, 2, 7, bw))
                frame.append(put(row, 4, FG_CYAN + BOLD + " Connection " + RESET))
                frame.append(label(row+1, 4, "Interface  : ", config_name,                       bw-6))
                frame.append(label(row+2, 4, "Endpoint   : ", stats.get("endpoint","-"),         bw-6))
                frame.append(label(row+3, 4, "Allowed IPs: ", stats.get("allowed_ips","-"),      bw-6))
                frame.append(label(row+4, 4, "Handshake  : ", stats.get("latest_handshake") or "-", bw-6))
                frame.append(label(row+5, 4, "Pub key    : ", truncate(stats.get("public_key","-"), 38), bw-6))
                row += 8

                frame.append(box(row, 2, 4, bw))
                frame.append(put(row, 4, FG_CYAN + BOLD + " Traffic " + RESET))
                rx, tx = stats.get("rx_bytes", 0), stats.get("tx_bytes", 0)
                frame.append(put(row+1, 4,
                    FG_GREEN + BOLD + "RX  " + RESET +
                    FG_CYAN + fmt_bytes(rx).ljust(14) + RESET +
                    FG_RED + BOLD + "  TX  " + RESET +
                    FG_CYAN + fmt_bytes(tx) + RESET))
                row += 5
            else:
                frame.append(put(row, 4, DIM + "No active tunnel. Press [c] to connect." + RESET + CLR_LINE))
                row += 2

            if status_msg:
                color = FG_GREEN if status_good else FG_RED
                frame.append(put(row, 2, color + "  " + status_msg + RESET + CLR_LINE))

            # Footer
            footer_y = rows - 2
            frame.append(put(footer_y - 1, 0, DIM + "-" * cols + RESET))
            keys_list = [("[c]", "connect" if not up else "disconnect"),
                         ("[r]", "refresh"),
                         ("[q]", "quit")]
            footer_line = ""
            for k, desc in keys_list:
                footer_line += FG_YELLOW + BOLD + k + RESET + DIM + f" {desc}  " + RESET
            frame.append(put(footer_y, 2, footer_line + CLR_LINE))

            # Clear any leftover content below the footer.
            frame.append(put(rows - 1, 0, CLR_DOWN))
            write(*frame)
            flush()

            # Wait for a key, or for the next refresh tick.
            wait = max(0.05, redraw_deadline - (time.monotonic() - last_refresh))
            k = read_key(wait)
            if k is None:
                continue
            if k[0] == 'char':
                c = k[1].lower()
                if c == b'q':
                    break
                elif c == b'c':
                    ok, msg = toggle_tunnel(config_name, config_path, up)
                    status_msg = "" if ok else msg
                    status_good = ok
                    last_refresh = 0.0
                elif c == b'r':
                    status_msg = ""
    finally:
        write(SHOW_CUR, RESET, "\n")
        flush()

# ------------------------------------------------------------------------------------
# main
# ------------------------------------------------------------------------------------

def main():
    if not WG or not WIREGUARD:
        print("WireGuard not found. Install it first:\n")
        print("  winget install WireGuard.WireGuard")
        print("  or download the MSI: https://www.wireguard.com/install/\n")
        print(f"Then re-run: python {sys.argv[0]}")
        sys.exit(1)

    if not is_admin():
        print("This tool requires Administrator.")
        print("Open PowerShell via Win+X -> Terminal (Admin), then re-run the command.")
        sys.exit(1)

    names = list_configs()
    if not names:
        print(f"No configs found in {CONFIG_DIR}. Drop a *.conf file there (see configs/example.conf).")
        sys.exit(1)

    enable_vt_mode()

    active = [a for a in get_active_interfaces() if a in names]

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
        chosen = pick_config(names, active=frozenset(active))
        if not chosen:
            sys.exit(0)

    config_path = CONFIG_DIR / f"{chosen}.conf"
    try:
        tui(chosen, config_path)
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
