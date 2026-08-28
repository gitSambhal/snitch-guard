# Changelog

All notable changes to **SnitchGuard** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-08-28

### Added
- **Automated Multi-Platform GitHub Actions Release Pipeline (`.github/workflows/release.yml`):**
  - Continuous integration & release workflow triggered on push/merge to `main`/`master` and tag releases (`v*`).
  - Cross-compilation matrix for elevated Go daemon (`linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`).
  - Automated Neutralinojs desktop packaging generating native standalone bundles with launcher scripts.
  - Automated release artifact packaging (`.tar.gz` and `.zip`) and SHA-256 checksums (`SHA256SUMS.txt`).
  - Automated GitHub Releases creation with changelog notes and attached binary downloads.

## [1.0.0] - 2026-08-28

### Added
- **Elevated Go Daemon (`daemon/`):**
  - High-performance Rule Engine with wildcard domain matching (`*.example.com`), process path filtering, IP CIDR, and JSON file persistence (`firewall_rules.json`).
  - TLS ClientHello SNI (Server Name Indication) parser extracting destination hostnames from raw packet headers.
  - HTTP Host header parser for plaintext traffic.
  - Socket-to-PID and Process Resolver with cross-platform architecture hooks (Linux `/proc`, macOS `libproc`, Windows `iphlpapi.dll`).
  - Internal WebSocket IPC server (`ws://127.0.0.1:9095/ws`) for low-latency bidirectional communication with the desktop client.
  - Transparent TCP proxy & interceptor with bidirectional streaming pipes and bandwidth accounting.
- **Neutralinojs Desktop GUI (`ui/`):**
  - Real-time Connection Alert Modal popup with 30s countdown, wildcard domain toggle, and 4-way decision buttons (*Allow Once*, *Allow Always*, *Deny Once*, *Deny Always*).
  - Live Outbound Traffic Monitor with process icon, PID, remote host, protocol, transfer rates, and instant process block buttons.
  - Rule Manager with search filters, manual rule creator, and delete actions.
  - Traffic Simulator for injecting mock packets from `curl`, `Spotify`, `VS Code`, and suspicious beacon binaries.
  - Window controls and System Tray integration using `Neutralino.os` and `Neutralino.window`.
- **Developer Documentation & Tooling:**
  - `neutralino.config.json` configuring native permissions, window dimensions, and tray settings.
  - `Makefile` with targets for `build`, `run-daemon` (with sudo), `ui`, `test`, and `clean`.
  - Comprehensive `README.md` with system architecture diagrams and production kernel driver integration guides (eBPF on Linux, NetworkExtension on macOS, WFP on Windows).
  - Author attribution for **Suhail Akhtar** ([https://suhail.top](https://suhail.top)).
