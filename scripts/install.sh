#!/usr/bin/env bash
set -euo pipefail

# Umbra Installation Script
# Installs release binary to /usr/bin/umbra, installs managed Tor config fragment to
# /etc/tor/torrc.d/umbra.conf, and installs systemd boot service unit template.
# Supports DESTDIR and PREFIX for packagers and isolated testing.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

DESTDIR="${DESTDIR:-}"
PREFIX="${PREFIX:-/usr}"
BIN_DIR="${DESTDIR}${PREFIX}/bin"
LOCAL_BIN_DIR="${DESTDIR}/usr/local/bin"
SYSCONFDIR="${DESTDIR}/etc"
TORRC_DIR="${SYSCONFDIR}/tor/torrc.d"
TOR_FRAGMENT="${TORRC_DIR}/umbra.conf"
SYSTEMD_DIR="${SYSCONFDIR}/systemd/system"

if [ -z "$DESTDIR" ] && [ "$(id -u)" -ne 0 ]; then
    echo "[!] Error: Installation requires root privileges. Please run with sudo:"
    echo "    sudo bash scripts/install.sh"
    exit 1
fi

echo "[*] Installing Umbra Privacy Boundary..."

# 1. Locate or compile the release binary
RELEASE_BIN="$REPO_ROOT/target/release/umbra"
if [ ! -f "$RELEASE_BIN" ]; then
    # If debug binary exists in test/development environments and release is absent, use it if DESTDIR is set
    if [ -n "$DESTDIR" ] && [ -f "$REPO_ROOT/target/debug/umbra" ]; then
        RELEASE_BIN="$REPO_ROOT/target/debug/umbra"
    else
        echo "[*] Release binary not found at $RELEASE_BIN. Attempting build with cargo..."
        CARGO_BIN="$(command -v cargo || true)"
        if [ -z "$CARGO_BIN" ] && [ -n "${SUDO_USER:-}" ]; then
            USER_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
            if [ -x "$USER_HOME/.cargo/bin/cargo" ]; then
                CARGO_BIN="$USER_HOME/.cargo/bin/cargo"
            fi
        fi

        if [ -z "$CARGO_BIN" ]; then
            echo "[!] Error: 'cargo' binary not found. Please compile the release binary first:"
            echo "    cargo build --release"
            exit 1
        fi

        echo "[*] Compiling release binary with $CARGO_BIN..."
        if [ -n "${SUDO_USER:-}" ]; then
            sudo -u "$SUDO_USER" "$CARGO_BIN" build --release --manifest-path "$REPO_ROOT/Cargo.toml"
        else
            "$CARGO_BIN" build --release --manifest-path "$REPO_ROOT/Cargo.toml"
        fi
    fi
fi

if [ ! -f "$RELEASE_BIN" ]; then
    echo "[!] Error: Failed to find compiled binary at $RELEASE_BIN"
    exit 1
fi

# 2. Install binary to $BIN_DIR/umbra and symlink $LOCAL_BIN_DIR/umbra
echo "[*] Installing binary to $BIN_DIR/umbra..."
mkdir -p "$BIN_DIR"
install -m 0755 "$RELEASE_BIN" "$BIN_DIR/umbra"

if [ "$BIN_DIR" != "$LOCAL_BIN_DIR" ] && [ "$(realpath "$BIN_DIR" 2>/dev/null || echo "$BIN_DIR")" != "$(realpath "$LOCAL_BIN_DIR" 2>/dev/null || echo "$LOCAL_BIN_DIR")" ]; then
    mkdir -p "$LOCAL_BIN_DIR"
    ln -sf "$PREFIX/bin/umbra" "$LOCAL_BIN_DIR/umbra"
    echo "[✓] Symlinked: $LOCAL_BIN_DIR/umbra -> $PREFIX/bin/umbra"
fi
echo "[✓] Binary installed: $BIN_DIR/umbra"

# 3. Install Tor configuration fragment with verified ownership and symlink refusal
mkdir -p "$TORRC_DIR"
chmod 0755 "$TORRC_DIR"

if [ -L "$TOR_FRAGMENT" ]; then
    echo "[!] Error: Existing file at $TOR_FRAGMENT is a symbolic link."
    echo "    Refusing to overwrite symlink to prevent configuration tampering or privilege abuse."
    exit 1
fi

if [ -f "$TOR_FRAGMENT" ]; then
    if ! grep -q "# umbra-managed" "$TOR_FRAGMENT"; then
        echo "[!] Error: Existing file at $TOR_FRAGMENT is not managed by Umbra (missing '# umbra-managed' marker)."
        echo "    Refusing to overwrite unmanaged file to prevent configuration corruption."
        exit 1
    fi
    echo "[*] Updating existing Umbra-managed fragment at $TOR_FRAGMENT..."
fi

TMP_FRAGMENT="${TOR_FRAGMENT}.tmp.$$"
cat > "$TMP_FRAGMENT" <<'EOF'
# umbra-managed: Umbra Tor Configuration Fragment
# Generated automatically by Umbra privacy boundary. Do not edit directly.
TransPort 127.0.0.1:9040
DNSPort 127.0.0.1:5353
ControlPort 127.0.0.1:9051
CookieAuthentication 1
EOF

chmod 0644 "$TMP_FRAGMENT"
mv -f "$TMP_FRAGMENT" "$TOR_FRAGMENT"
echo "[✓] Tor configuration fragment installed at $TOR_FRAGMENT"

if [ -z "$DESTDIR" ] && [ -f /etc/tor/torrc ]; then
    if ! grep -q -E "%include /etc/tor/torrc\.d" /etc/tor/torrc; then
        echo "[i] Reminder: Please verify that '/etc/tor/torrc' contains:"
        echo "    %include /etc/tor/torrc.d/*.conf"
        echo "    Then reload Tor: sudo systemctl restart tor"
    fi
fi

# 4. Install systemd boot service unit template if systemd is present
SERVICE_SRC="$REPO_ROOT/systemd/umbra-boot.service"
if [ -f "$SERVICE_SRC" ]; then
    mkdir -p "$SYSTEMD_DIR"
    install -m 0644 "$SERVICE_SRC" "$SYSTEMD_DIR/umbra-boot.service"
    echo "[✓] Systemd unit installed: $SYSTEMD_DIR/umbra-boot.service"
    if [ -z "$DESTDIR" ] && command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload 2>/dev/null || true
    fi
    if [ -z "$DESTDIR" ]; then
        echo "[i] Optional: Enable boot-time fail-closed enforcement with:"
        echo "    sudo systemctl enable umbra-boot.service"
    fi
fi

echo ""
echo "[✓] Umbra installation completed successfully."
echo "    Start routing:  sudo umbra start"
echo "    Check status:   sudo umbra status"
echo "    Stop routing:   sudo umbra stop"
