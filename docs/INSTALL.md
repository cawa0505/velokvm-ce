# VeloKVM Community Edition (velokvm-ce) — Installation & Deployment Guide

This guide walks through building, configuring, and running the VeloKVM Community Edition clipboard transport service with `lan-mouse` integration.

---

## 1. Prerequisites & System Requirements

* **Operating System**: Linux with an active Wayland Compositor session (e.g., `niri`, `sway`, `dwl`, `hyprland`).
* **System Utilities**:
  * `wl-clipboard` (provides `wl-copy` and `wl-paste` for OS selection integration).
  * `cargo` / `rustc` (Rust 2021 edition toolchain, 1.75+ recommended).
* **Network**:
  * Outbound/inbound access on TCP Port `9022` between paired workstations.
  * (Optional) UDP Port `9021` for 1000Hz HID input fast-path.

```bash
# Ubuntu / Debian
sudo apt-get install wl-clipboard

# Arch Linux
sudo pacman -S wl-clipboard

# Fedora
sudo dnf install wl-clipboard
```

---

## 2. Compilation & Workspace Setup

Clone the repository and compile the host service binary:

```bash
git clone https://github.com/cawa0505/velokvm-ce.git
cd velokvm-ce

# Build release binary with LTO optimization
cargo build --release -p velokvm-host

# Install to user bin (ensure ~/.cargo/bin is in PATH)
cargo install --path crates/velokvm-host
```

---

## 3. Key Exchange & Mutual Authorization (Noise_IK)

VeloKVM uses the Noise_IK handshake pattern (`Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`). Under this model:
* Every host generates a static Curve25519 keypair.
* The receiver (responder) operates under a strict **Fail-Closed** rule: any incoming connection without a whitelisted public key is immediately dropped without handshake response.

### Step 3.1: Generate Local Keypair

Run on each machine (e.g., Host A and Host B):

```bash
mkdir -p ~/.config/velokvm
velokvm-clipboard-service genkey ~/.config/velokvm/host.key

# Outputs:
#   ~/.config/velokvm/host.key      (Private key, keep secure)
#   ~/.config/velokvm/host.key.pub  (Public key hex string)
```

Display your public key:
```bash
cat ~/.config/velokvm/host.key.pub
# Example: f4bd8d46710d63ec0d761b730fa3c60eb3ad703eaaa0f703c6ae32370340430b
```

### Step 3.2: Configure Peer Whitelist

On **Host A**, add Host B's public key to `~/.config/velokvm/allow.txt`:
```bash
echo "<HOST_B_PUBLIC_KEY_HEX>" >> ~/.config/velokvm/allow.txt
```

On **Host B**, add Host A's public key to its own `allow.txt`:
```bash
echo "<HOST_A_PUBLIC_KEY_HEX>" >> ~/.config/velokvm/allow.txt
```

---

## 4. Running the Service

### Manual Execution

Start the daemon on Host A:
```bash
velokvm-clipboard-service serve \
  --key ~/.config/velokvm/host.key \
  --listen 0.0.0.0:9022 \
  --allow ~/.config/velokvm/allow.txt
```

### Systemd User Service (Recommended)

To run automatically in your desktop session, install as a systemd user unit:

```ini
# ~/.config/systemd/user/velokvm-clipboard-service.service
[Unit]
Description=VeloKVM Clipboard Synchronization Service
After=wayland-session.target
PartOf=graphical-session.target

[Service]
Type=simple
ExecStart=%h/.cargo/bin/velokvm-clipboard-service serve \
  --key %h/.config/velokvm/host.key \
  --allow %h/.config/velokvm/allow.txt \
  --listen 0.0.0.0:9022
Restart=always
RestartSec=3

[Install]
WantedBy=graphical-session.target
```

Enable and start the service:
```bash
systemctl --user daemon-reload
systemctl --user enable --now velokvm-clipboard-service.service
systemctl --user status velokvm-clipboard-service.service
```

---

## 5. Sending & Testing Clipboard Transfers

### Manual Push (Text or File)

From Host B to Host A:
```bash
# Push small string directly into remote Wayland clipboard:
velokvm-clipboard-service push \
  --peer 192.168.1.10:9022 \
  --key ~/.config/velokvm/host.key \
  --peer-key <HOST_A_PUBLIC_KEY_HEX> \
  --text "Hello from Host B via encrypted Noise_IK"

# Push a code file or large text snippet:
velokvm-clipboard-service push \
  --peer 192.168.1.10:9022 \
  --key ~/.config/velokvm/host.key \
  --peer-key <HOST_A_PUBLIC_KEY_HEX> \
  --file ./main.rs
```

### Verification on Target Machine

On Host A, paste immediately using standard Wayland utilities:
```bash
wl-paste
```
The exact content sent from Host B will be printed, having been transparently written to the Wayland selection by the background daemon.
