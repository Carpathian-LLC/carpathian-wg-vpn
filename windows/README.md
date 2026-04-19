# carpathian-wg-vpn — Windows

A lightweight WireGuard TUI for **Windows only**.

## Install WireGuard

```powershell
winget install WireGuard.WireGuard
```

Or download the MSI from <https://www.wireguard.com/install/>.

The script looks for `wg.exe` and `wireguard.exe` in:

- `C:\Program Files\WireGuard\`
- `C:\Program Files (x86)\WireGuard\`
- anywhere on `PATH`

## Install Python curses shim

Windows Python doesn't ship curses by default:

```powershell
pip install windows-curses
```

## Usage

Drop your `.conf` files in [`..\configs\`](../configs/) then run from an **Administrator** terminal:

```powershell
python connect.py              # picker (or auto-selects if only one config)
python connect.py usc1         # open a specific config by name
```

Administrator is required because `wireguard.exe /installtunnelservice` registers a Windows service.

## How it works

- Connect: `wireguard.exe /installtunnelservice <path-to-conf>`
- Disconnect: `wireguard.exe /uninstalltunnelservice <name>`
- Status: parsed from `wg.exe show`

The tunnel service name matches the config file stem (e.g. `usc1.conf` → service `usc1`).

## Keys

- `c` — connect / disconnect
- `r` — clear status message
- `q` — quit
- `↑/↓` — navigate in the config picker
