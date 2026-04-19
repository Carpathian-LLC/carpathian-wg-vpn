# carpathian-wg-vpn

A lightweight Python utility and terminal UI for WireGuard tunnels, built for systems that can't run the official WireGuard app. Supports macOS and Windows.

## Platforms

- [macOS](./macos/) — uses Homebrew or MacPorts `wireguard-tools`
- [Windows](./windows/) — uses the official WireGuard installer

## Layout

```
carpathian-wg-vpn/
├── configs/       # drop your *.conf files here (shared by both platforms)
├── macos/         # sudo python3 connect.py [config_name]
└── windows/       # python connect.py [config_name]   (Administrator)
```

## Configs

Put your WireGuard `.conf` files in [`configs/`](./configs/). The TUI auto-discovers them:

- If one config exists, it is selected automatically.
- If multiple exist, an arrow-key picker appears.
- Pass a name on the CLI (`connect.py example_conf`) to skip the picker.

**Config files contain private keys.** They are gitignored by default — do not commit them.

## Requirements

WireGuard must already be installed on your system. If the TUI can't find it, it will print the install command for your platform. See the per-platform READMEs for details.

---

Built for [Carpathian](https://carpathian.ai) Open Source.

- [Threads](https://www.threads.net/@carpathianai)
- [X](https://x.com/carpathianai)
- [LinkedIn](https://www.linkedin.com/company/carpathianai/)
- [Reddit](https://www.reddit.com/r/carpathianai/)
