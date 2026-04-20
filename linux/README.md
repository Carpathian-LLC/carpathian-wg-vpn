# carpathian-wg-vpn — Linux

A lightweight WireGuard TUI for **Linux only**.

## Install WireGuard

Use your distribution's package manager:

```bash
# Debian / Ubuntu
sudo apt install wireguard-tools

# Fedora / RHEL / CentOS
sudo dnf install wireguard-tools

# Arch Linux
sudo pacman -S wireguard-tools

# openSUSE
sudo zypper install wireguard-tools
```

> **Note:** On older kernels (< 5.6) you may also need to install the `wireguard` DKMS module.
> Modern kernels (5.6+) include WireGuard natively — only `wireguard-tools` is needed.

## Usage

Drop your `.conf` files in [`../configs/`](../configs/) then:

```bash
sudo python3 connect.py              # picker (or auto-selects if only one config)
sudo python3 connect.py example_conf # open a specific config by name
```

Root is required because `wg-quick` creates a network interface and modifies routes.

## Keys

- `c` — connect / disconnect
- `r` — clear status message
- `q` — quit
- `↑/↓` — navigate in the config picker

## How it works

- Connect / Disconnect: `wg-quick up|down <path-to-conf>`
- Status: parsed from `wg show`

On Linux, `wg-quick` names the tunnel interface after the config file stem (e.g. `example_conf.conf` → interface `example_conf`).
