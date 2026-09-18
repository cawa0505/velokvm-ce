# VeloKVM Community Edition (velokvm-ce)

[![License: GPL-3.0-or-later](https://img.shields.io/badge/License-GPL--3.0--or--later-blue.svg)](LICENSE)
[![Protocol: Noise_IK](https://img.shields.io/badge/Security-Noise__IK%200--RTT-brightgreen.svg)]()
[![Fast-Path: Zero-Allocation](https://img.shields.io/badge/Fast--Path-1000Hz%20HID-orange.svg)]()

VeloKVM Community Edition provides high-performance, low-latency cross-machine input and clipboard synchronization for Linux/Wayland environments. It combines the 1000Hz HID input architecture of [lan-mouse](https://github.com/cawa0505/lan-mouse) with VeloKVM's dedicated, encrypted zero-trust transport channel.

---

## Architecture Overview: VeloKVM & lan-mouse Integration

A common failure mode in software KVM solutions is head-of-line (HoL) blocking: routing multi-megabyte clipboard transfers through the same pipe as 1000Hz mouse motion leads to cursor stutter and dropped HID frames.

VeloKVM and `lan-mouse` establish a strict separation of concerns across two orthogonal planes:

```
+-------------------------------------------------------------------------------+
|                             OS Interface Layer                                |
|  [lan-mouse] (Wayland ext-data-control-v1 / wl-clipboard)                     |
|  - Capture: Monitors clipboard changes without UI dependency                  |
|  - Injection: Writes received payloads safely into local Wayland selection    |
+---------------------------------------+---------------------------------------+
                                        | Clean in-memory boundary
                                        v
+-------------------------------------------------------------------------------+
|                          VeloKVM Transport Layer                              |
|  1. HID Fast-Path Channel (UDP Port 9021)                                     |
|     - 16-byte fixed repr(C, packed) binary protocol                           |
|     - Zero heap allocation, 1000Hz ultra-low jitter stream                    |
|                                                                               |
|  2. Async Bulk Clipboard Channel (TCP Port 9022)                              |
|     - Noise_IK (Curve25519 + ChaCha20-Poly1305 + BLAKE2s) 0-RTT encryption    |
|     - Static public key mutual authorization (Fail-Closed default)            |
|     - 64 KiB chunked stream with Offer -> Chunk -> Complete framing           |
|     - Independent TCP connection: zero interference with 1000Hz mouse motion  |
+-------------------------------------------------------------------------------+
```

### Community Edition vs Commercial Edition

| Feature | Community Edition (`velokvm-ce`) | Commercial Enterprise Edition |
| :--- | :--- | :--- |
| **HID Fast-Path** | UDP 9021 Direct Fast-Path | UDP 9021 Hardware-Offloaded Fast-Path |
| **Clipboard Transport** | Dedicated TCP 9022 + Noise_IK | Chunked UDP 9022 + Solo5 Zero-Trust ROM |
| **Security Root** | Mutual Static Public Key Whitelist | Solo5 Unikernel (`no_std`, x86_64-unknown-none) |
| **Network Boundary** | Host-to-Host LAN Mesh | `tap0` Virtual Segment with Hardware Token Isolation |
| **License** | GPL-3.0-or-later / MIT dual-boundary | Commercial Proprietary |

---

## Performance Summary

Benchmarked on physical Wayland workstations running `niri` (Wayland compositor) across local and LAN setups:

* **TC-01: Micro-Payload Latency (< 128 Bytes URL / Snippet)**
  * Round-trip / pipeline latency: **3.3 ms – 4.9 ms** (Target was `< 5 ms`)
  * Deterministic UTF-8 integrity across multiple rounds with zero frame drops.
* **TC-02: Bulk Code Snippet (100 KB Payload)**
  * Total transport time: **3.8 ms** across 7 streaming chunks (16 KiB default window).
  * Main execution loop remained completely non-blocking.
* **HID Isolation**:
  * Sustained 1000Hz mouse movement experienced **0.00% jitter or lag** during concurrent 100 KB and 1 MiB clipboard transfers over TCP 9022.

Detailed test logs, methodology, and raw metrics can be found in [docs/BENCHMARK.md](docs/BENCHMARK.md).

---

## Quick Start & Installation

Full step-by-step setup guides, systemd user service configurations, and multi-machine pairing instructions are documented in [docs/INSTALL.md](docs/INSTALL.md).

```bash
# 1. Build the clipboard transport service
cargo build --release -p velokvm-host

# 2. Generate local station keypair
velokvm-clipboard-service genkey station.key

# 3. Start receiving daemon with peer whitelist
velokvm-clipboard-service serve \
  --key station.key \
  --listen 0.0.0.0:9022 \
  --allow ~/.config/velokvm/allow.txt

# 4. Push clipboard content to remote station
velokvm-clipboard-service push \
  --peer 192.168.1.100:9022 \
  --key station.key \
  --peer-key <REMOTE_PUBLIC_KEY_HEX> \
  --text "Hello from VeloKVM"
```

---

## Roadmap & Community Contributions

- [x] Phase 1: 16-byte fixed `repr(C, packed)` binary HID fast-path protocol.
- [x] Phase 2: Dedicated Noise_IK TCP 9022 asynchronous bulk channel.
- [x] Phase 2: Linux Wayland clipboard injection bridge (`wl-clipboard`).
- [x] Phase 3: Direct integration with `lan-mouse` (`cawa0505/lan-mouse`) embedded clipboard sync service:
  - Watcher + Responder background threads via `velokvm-proto`.
  - Asynchronous Wayland selection lifecycle management.
  - Seamless automatic cross-machine clipboard sync (<kbd>Ctrl</kbd>+<kbd>C</kbd> / <kbd>Ctrl</kbd>+<kbd>V</kbd>) verified across physical workstations.
- [ ] Phase 4: Bi-directional delta compression and extended MIME types (image/png).

Contributions and PRs are welcome! Please ensure all pull requests preserve the zero-allocation invariants of the fast-path protocol.
