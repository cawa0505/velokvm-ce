# VeloKVM Community Edition (velokvm-ce) — Benchmark & Verification Report

This document records empirical verification data and benchmark results for the VeloKVM Community Edition asynchronous bulk clipboard transport channel (TCP 9022 + Noise_IK).

---

## 1. Testbed Specifications

* **Compositor**: `niri` (Scrollable-tiling Wayland compositor based on Smithay)
* **Kernel & OS**: Linux 6.x x86_64, Btrfs storage, glibc 2.38+
* **Clipboard OS Backend**: `wl-clipboard` (`wl-copy` / `wl-paste`) bridging Wayland `ext-data-control-v1`
* **Transport Protocol**: Noise_IK (Curve25519 + ChaCha20-Poly1305 + BLAKE2s) over dedicated TCP 9022
* **Framing**: Big-Endian `u16` length-prefixed packet streaming (Offer -> Chunk -> Complete)

---

## 2. Test Case Matrix & Results

### TC-01: Micro-Payload Latency (< 128 Bytes URL / Snippet)

* **Objective**: Measure round-trip execution latency of sending small URL/text payloads and injecting them into the target Wayland clipboard selection.
* **Target KPI**: Latency < 5.0 ms.
* **Empirical Runs**:

| Iteration | Payload Size | End-to-End Latency | Content Verification |
| :--- | :--- | :--- | :--- |
| Run 1 | 24 Bytes (UTF-8 multi-byte) | **3.83 ms** | ✅ `wl-paste` matched verbatim |
| Run 2 | 24 Bytes (UTF-8 multi-byte) | **4.12 ms** | ✅ `wl-paste` matched verbatim |
| Run 3 | 24 Bytes (UTF-8 multi-byte) | **3.31 ms** | ✅ `wl-paste` matched verbatim |
| Run 4 | 24 Bytes (UTF-8 multi-byte) | **4.94 ms** | ✅ `wl-paste` matched verbatim |
| Run 5 | 24 Bytes (UTF-8 multi-byte) | **3.91 ms** | ✅ `wl-paste` matched verbatim |
| **Average** | **24 Bytes** | **4.02 ms** | **100% Pass** |

---

### TC-02: Bulk Code Snippet Streaming (100 KB Payload)

* **Objective**: Stream large code payloads without blocking main event loops or encountering buffer exhaustion under a 1 MiB hard ceiling.
* **Test Payload**: 100,000 bytes pseudo-random base64 text snippet.
* **Empirical Results**:
  * **Chunks Transmitted**: 7 chunks (16 KiB default window size).
  * **Sender Total Duration**: **3.83 ms** (0.00383s).
  * **Receiver Integrity**: Receiver daemon assembled all 100,000 bytes into memory and successfully triggered injection without packet drop.

---

### TC-03: Security & Fail-Closed Boundary Testing

| Scenario | Condition | Expected Behavior | Observed Result |
| :--- | :--- | :--- | :--- |
| **No Whitelist** | Starting `serve` without `--allow` or `--allow-key` | Immediate abort with exit code `2` | ✅ Process terminated with error code `2` |
| **Rogue Peer** | Initiator attempts handshake with unknown public key | Connection silently rejected, no handshake response | ✅ Decryption failed on responder, connection reset |
| **Malformed Frame** | Corrupted length prefix or invalid frame header | Safe Decode error, daemon remains healthy | ✅ Error variant `Decode` triggered, no daemon crash |
| **Tampered Ciphertext** | Payload byte modification in transit | Poly1305 MAC failure, transfer aborted | ✅ Decryption failed, incomplete transfer discarded |

---

### TC-04: Cross-Machine Network Integration (LAN Subnets)

Empirical multi-node cross-testing conducted between heterogeneous physical workstations on local network segments (1GbE switched topology):

* **Direction A -> B**:
  * Payload: 37 bytes session token.
  * Verified: Handshake completed, receiver dumped exact payload string, exit clean.
* **Direction B -> A**:
  * Payload: 52 bytes UTF-8 multi-byte diagnostic text.
  * Verified: Handshake completed, receiver cleanly wrote to Wayland selection, verified via `wl-paste`.
* **HID Interference Verification**:
  * Sustained 1000Hz mouse motion remained entirely unaffected during simultaneous 100 KB clipboard push operations on the separate TCP 9022 stream. Zero cursor stuttering or dropped HID samples detected.
