# carpathian-wg-vpn — Windows

A lightweight WireGuard TUI for **Windows only**. Uses only the Python standard library.

---

### Step 1 — Install Python

Open PowerShell and run:

```powershell
winget install Python.Python.3.14
```

> ⚠️ **You MUST close this PowerShell window and open a new one** after Python installs.

**Verify it worked.** In a *fresh* PowerShell window:

```powershell
python --version
```

You should see `Python 3.14.x`. If not, see [Troubleshooting](#troubleshooting) below.

### Step 2 — Install WireGuard

```powershell
winget install WireGuard.WireGuard
```

Or download the MSI from <https://www.wireguard.com/install/>.

### Step 3 — Add your WireGuard config

Copy your `.conf` file into the [`configs/`](../configs/) folder at the repo root.

---

## Running the TUI

### Step 1 — Open PowerShell **as Administrator**

1. Press `Win` + `X`
2. Click **Terminal (Admin)** (or **Windows PowerShell (Admin)** on older Windows)
3. Click **Yes** on the UAC prompt

Administrator is required because the script calls `wireguard.exe /installtunnelservice`, which registers a Windows service.

### Step 2 — Go to the repo's `windows` folder

If you cloned into `Documents\GitHub`:

```powershell
cd "$HOME\Documents\GitHub\carpathian-wg-vpn\windows"
```

### Step 3 — Run the TUI

```powershell
# Start the first config in the folder or select from a list if there's multiple
python connect.py

# open a specific config by name
python connect.py example_conf
```

---

## Keys

- `c` — connect / disconnect
- `r` — clear status message
- `q` — quit
- `↑/↓` — navigate in the config picker

## How it works

- Connect: `wireguard.exe /installtunnelservice <path-to-conf>`
- Disconnect: `wireguard.exe /uninstalltunnelservice <name>`
- Status: parsed from `wg.exe show`

The tunnel service name matches the config file stem (e.g. `example_conf.conf` → service `example_conf`).

The script looks for `wg.exe` and `wireguard.exe` in:

- `C:\Program Files\WireGuard\`
- `C:\Program Files (x86)\WireGuard\`
- anywhere on `PATH`
