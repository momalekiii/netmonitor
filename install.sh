#!/usr/bin/env bash
# Interactive installer for NetMonitor
# Usage: curl -LsS https://raw.githubusercontent.com/YOUR_USERNAME/netmonitor/main/install.sh | bash

set -euo pipefail

REPO="YOUR_USERNAME/netmonitor"
INSTALL_DIR="${NETMONITOR_INSTALL_DIR:-$HOME/.local/share/netmonitor}"
BIN_DIR="${NETMONITOR_BIN_DIR:-$HOME/.local/bin}"

echo "=== NetMonitor Interactive Installer ==="
echo "Install directory: $INSTALL_DIR"
echo "Bin directory:     $BIN_DIR"
echo ""

# Detect OS
OS="$(uname -s)"
case "$OS" in
  Linux)     PLATFORM="linux" ;;
  Darwin)    PLATFORM="macos" ;;
  *)         echo "Unsupported OS: $OS"; exit 1 ;;
esac

# Python check
if ! command -v python3 &>/dev/null; then
  echo "python3 is required but not installed."
  exit 1
fi

# Create directories
mkdir -p "$INSTALL_DIR" "$BIN_DIR"

# Clone or download
if command -v git &>/dev/null; then
  if [ -d "$INSTALL_DIR/.git" ]; then
    echo "Updating existing clone..."
    git -C "$INSTALL_DIR" pull --ff-only
  else
    echo "Cloning repository..."
    git clone --depth 1 "https://github.com/$REPO.git" "$INSTALL_DIR"
  fi
else
  echo "git not found. Please install git and re-run."
  exit 1
fi

cd "$INSTALL_DIR"

# Create venv
if [ ! -d "$INSTALL_DIR/.venv" ]; then
  echo "Creating virtual environment..."
  python3 -m venv "$INSTALL_DIR/.venv"
fi

# Install dependencies
"$INSTALL_DIR/.venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/.venv/bin/pip" install -e .

# Run interactive installer (asks about features before installing)
echo ""
"$INSTALL_DIR/.venv/bin/python" -m netmonitor.installer

# Create wrapper script
cat > "$BIN_DIR/netmonitor" <<EOF
#!/usr/bin/env bash
exec "$INSTALL_DIR/.venv/bin/netmonitor" "\$@"
EOF
chmod +x "$BIN_DIR/netmonitor"

# Add to PATH hint
if ! echo "$PATH" | grep -q "$BIN_DIR"; then
  echo ""
  echo "=== IMPORTANT ==="
  echo "Add $BIN_DIR to your PATH, e.g.:"
  echo "  echo 'export PATH=\"$BIN_DIR:\$PATH\"' >> ~/.bashrc"
  echo "  source ~/.bashrc"
fi

echo ""
echo "=== Installation complete ==="
echo "Run: netmonitor"
echo "Run as daemon: netmonitor daemon start"
echo "Interactive:   netmonitor"
