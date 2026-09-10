#!/bin/bash
# Update panel code without touching data
set -e
if [[ $EUID -ne 0 ]]; then echo "Run as root"; exit 1; fi
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="/opt/dns-panel"
cp -r "$SRC_DIR/app" "$SRC_DIR/requirements.txt" "$INSTALL_DIR/"
"$INSTALL_DIR/venv/bin/pip" install -q -r "$INSTALL_DIR/requirements.txt"
systemctl restart dns-smart dns-sni dns-panel
echo "✔ Updated and restarted."
