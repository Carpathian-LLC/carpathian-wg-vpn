# carpathian-wg-vpn — macOS

A lightweight WireGuard TUI for **macOS only**.

## Install WireGuard

Either package manager works — the script auto-detects both:

```bash
brew install wireguard-tools
# or
sudo port install wireguard-tools
```

## Usage

Drop your `.conf` files in [`../configs/`](../configs/) then:

```bash
sudo python3 connect.py              # picker (or auto-selects if only one config)
sudo python3 connect.py usc1         # open a specific config by name
```

Root is required because `wg-quick` creates a `utun` interface and modifies routes.

## Keys

- `c` — connect / disconnect
- `r` — clear status message
- `q` — quit
- `↑/↓` — navigate in the config picker
