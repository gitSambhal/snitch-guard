# SnitchGuard - Cross-Platform Host Application Firewall

> **Author:** [Suhail Akhtar](https://suhail.top)  
> **Architecture:** Elevated Go System Daemon (`daemon/`) + Lightweight Neutralinojs Desktop Client (`ui/`)  
> **Version:** `v1.0.0`

---

## 1. System Architecture Overview

SnitchGuard is a host-based application firewall (Little Snitch / LuLu clone) engineered with a clean separation of concerns:

```
+-------------------------------------------------------------------------+
|                  OS Kernel Network Interception Layer                   |
|  Linux: eBPF (sock_ops) | macOS: NetworkExtension | Windows: WFP Callout |
+------------------------------------+------------------------------------+
                                     | (Socket / Packet Redirection)
                                     v
+-------------------------------------------------------------------------+
|                    Elevated Go System Daemon (daemon/)                  |
|                                                                         |
|  +---------------------+   +---------------------+   +----------------+ |
|  | Traffic Interceptor |-->| TLS SNI Host Parser |-->| Rule Engine    | |
|  | (127.0.0.1:9096)    |   | & Process Resolver  |   | (JSON Storage) | |
|  +---------------------+   +---------------------+   +-------+--------+ |
|                                                              | (Verdict)|
|  +-----------------------------------------------------------v--------+ |
|  |             IPC WebSocket Server (ws://127.0.0.1:9095)             | |
+--+-----------------------------+--------------------------------------+--+
                                 | Bidirectional JSON Messages
                                 v
+-------------------------------------------------------------------------+
|                 Neutralinojs Desktop Client (ui/)                      |
|                                                                         |
|  - Real-Time Connection Alert Modal (Allow/Deny Once/Always)            |
|  - Live Traffic Bandwidth & Active Process Monitor                      |
|  - Stateful Rule Manager & Wildcard Domain Editor                      |
|  - System Tray Minimization & Window Management (`Neutralino.os`)       |
+-------------------------------------------------------------------------+
```

---

## 2. Project Directory Structure

```text
├── neutralino.config.json     # Neutralino window geometry, tray, & permissions
├── ui/
│   ├── index.html             # Desktop client GUI & alert modal
│   ├── css/
│   │   └── style.css          # Dark cyberpunk UI theme
│   └── js/
│       ├── app.js             # WebSocket IPC client & Neutralino API logic
│       └── neutralino.js      # Neutralino client bindings
├── daemon/
│   ├── go.mod                 # Go module definition
│   ├── main.go                # Elevated daemon server & IPC WebSocket hub
│   ├── rules.go               # Stateful rule evaluation engine & persistence
│   ├── interceptor.go         # Traffic interceptor & TLS ClientHello SNI parser
│   └── process.go             # Socket-to-PID and executable binary resolver
├── Makefile                   # Build & execution automation
├── CHANGELOG.md               # Version history
└── README.md                  # System architecture & documentation
```

---

## 3. Production Kernel Driver Integration Blueprint

### Linux: eBPF (`sock_ops` / `cgroup_skb`)
In production Linux systems:
1. Load a BPF program of type `BPF_PROG_TYPE_SOCK_OPS` into the root cgroup `/sys/fs/cgroup`.
2. Intercept `BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB` when processes invoke the `connect()` syscall.
3. Access process metadata in-kernel via `bpf_get_current_pid_tgid()`.
4. Hold the socket in a pending state or redirect the initial SYN payload to the Go daemon listener via `bpf_msg_redirect_hash`.

### macOS: NetworkExtension Framework (`NEFilterDataProvider`)
In production macOS systems:
1. Create a `SystemExtension` providing an `NEFilterDataProvider`.
2. Override `handleNewFlow(_ flow: NEFilterSocketFlow) -> NEFilterNewFlowVerdict`.
3. Inspect `flow.remoteEndpoint` and query the Mach-O binary audit token `flow.sourceAppAuditToken`.
4. Return `NEFilterNewFlowVerdict.pause()` while emitting an IPC event to the daemon. Once the user clicks "Allow" or "Deny", call `resumeFlow(_:with:)` with `.allow()` or `.drop()`.

### Windows: Windows Filtering Platform (WFP)
In production Windows environments:
1. Develop a kernel-mode WFP callout driver registering at `FWPM_LAYER_ALE_AUTH_CONNECT_V4`.
2. In the `classifyFn` callback, inspect `FWPS_INCOMING_VALUES0` for `PROCESS_ID` and `IP_REMOTE_ADDRESS`.
3. Call `FwpsPendOperation0` to suspend the outgoing TCP handshake.
4. Send an asynchronous event via an inverted call I/O ring to the Go daemon. Upon verdict, invoke `FwpsCompleteOperation0(verdict)`.

---

## 4. Quick Start & Execution

### Prerequisites
- Go 1.22+ (`go version`)
- Neutralino CLI (`npm install -g @neutralinojs/neu` or `npx @neutralinojs/neu`)

### 1. Compile & Run the Elevated Daemon
```bash
# Compile and start daemon with root privileges
make run-daemon
# Or manually:
cd daemon && go run . --ws-port=9095 --proxy-port=9096
```

### 2. Launch the Neutralino Desktop App
```bash
# In a separate terminal:
make ui
# Or directly via Neutralino CLI:
neu run
```

### 3. Unified Packaging & Single-Command Native Runner
```bash
# Package UI + Go daemon into unified native app
make package

# Run the native app (auto-starts daemon + launches Neutralino window with live traffic)
make run-native
```

---

## 5. Automated Multi-Platform GitHub Actions Release

The repository includes an automated release workflow (`.github/workflows/release.yml`) that triggers whenever code is pushed or merged to `main` (or when a version tag `v*` is published):

1. **Cross-compilation Matrix:** Builds the elevated Go daemon for:
   - Linux x86_64 (`linux/amd64`)
   - Linux ARM64 (`linux/arm64`)
   - macOS Intel (`darwin/amd64`)
   - macOS Apple Silicon (`darwin/arm64`)
   - Windows x64 (`windows/amd64`)
2. **Neutralino Packaging:** Builds release binaries with embedded launcher scripts and asset archives.
3. **Automated GitHub Release:** Publishes standalone `.tar.gz` and `.zip` packages alongside `SHA256SUMS.txt` checksums.

---

## 6. IPC WebSocket Protocol Specification

The Neutralino desktop GUI and the Go daemon communicate via an internal WebSocket on `ws://127.0.0.1:9095/ws`:

| Message Type | Direction | Payload Description |
| :--- | :--- | :--- |
| `ALERT_PROMPT` | Daemon &rarr; UI | Outbound flow waiting for user verdict (`id`, `pid`, `process_name`, `domain`, `remote_ip`, `port`, `protocol`) |
| `DECISION` | UI &rarr; Daemon | User choice (`flow_id`, `action`: "allow"/"block", `duration`: "once"/"session"/"always", `apply_wildcard`: bool) |
| `TRAFFIC_EVENT` | Daemon &rarr; UI | Live connection state change (`bytes_sent`, `bytes_recv`, `state`: "allowed"/"blocked"/"closed") |
| `GET_RULES` | UI &rarr; Daemon | Request full rule list |
| `RULE_LIST` | Daemon &rarr; UI | Array of all active firewall rules |
| `DELETE_RULE` | UI &rarr; Daemon | Delete rule by ID (`{ id: string }`) |
| `SIMULATE_TRAFFIC` | UI &rarr; Daemon | Inject synthetic test connection flow |

---

## 6. Author
Developed by **[Suhail Akhtar](https://suhail.top)**.
All rights reserved. Released under the MIT License.
