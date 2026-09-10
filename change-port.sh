#!/bin/bash
# Change web panel port
set -e
if [[ $EUID -ne 0 ]]; then echo "Run as root: sudo bash change-port.sh"; exit 1; fi
INSTALL_DIR="/opt/dns-panel"
if [ ! -f "$INSTALL_DIR/config.env" ]; then echo "Panel not installed at $INSTALL_DIR"; exit 1; fi
OLD_PORT=$(grep PANEL_PORT "$INSTALL_DIR/config.env" | cut -d= -f2)
read -p "New panel port [$OLD_PORT]: " NEW_PORT
NEW_PORT=${NEW_PORT:-$OLD_PORT}
sed -i "s/^PANEL_PORT=.*/PANEL_PORT=$NEW_PORT/" "$INSTALL_DIR/config.env"
set -a; source "$INSTALL_DIR/config.env"; set +a
cd "$INSTALL_DIR"
"$INSTALL_DIR/venv/bin/python" -c "from app.database import set_setting; set_setting('panel_port','$NEW_PORT')" 2>/dev/null || true
ufw allow "$NEW_PORT"/tcp > /dev/null 2>&1 || true
systemctl restart dns-panel
sleep 2
systemctl is-active --quiet dns-panel && echo "✔ Panel port changed to $NEW_PORT" || echo "✘ Failed. journalctl -u dns-panel -e"
echo "New URL: http://$(curl -s -4 --max-time 5 https://api.ipify.org):$NEW_PORT"
