#!/bin/bash
# =====================================================
#  DNS Shop Panel - Auto Installer for Ubuntu
#  SmartDNS + Web Panel (IP-based accounts with expiry)
#  Tested on Ubuntu 20.04 / 22.04 / 24.04
# =====================================================
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
INSTALL_DIR="/opt/dns-panel"

info()  { echo -e "${BLUE}[INFO]${NC} $1"; }
ok()    { echo -e "${GREEN}[OK]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
err()   { echo -e "${RED}[ERR]${NC} $1"; }

echo "====================================================="
echo "     🌐 DNS Shop Panel - Installer"
echo "     SmartDNS + Web Panel (Ubuntu)"
echo "====================================================="
echo ""

# ---------- checks ----------
if [[ $EUID -ne 0 ]]; then err "Please run as root: sudo bash install.sh"; exit 1; fi
if ! grep -qi ubuntu /etc/os-release 2>/dev/null; then warn "This script is designed for Ubuntu. Continuing anyway..."; fi

# ---------- questions ----------
read -p "🔌 Web panel port [8080]: " PANEL_PORT
PANEL_PORT=${PANEL_PORT:-8080}
if ! [[ "$PANEL_PORT" =~ ^[0-9]+$ ]] || [ "$PANEL_PORT" -lt 1 ] || [ "$PANEL_PORT" -gt 65535 ]; then
  err "Invalid port: $PANEL_PORT"; exit 1
fi

read -p "👤 Admin username [admin]: " ADMIN_USER
ADMIN_USER=${ADMIN_USER:-admin}

read -s -p "🔑 Admin password (empty = random): " ADMIN_PASS
echo ""
if [[ -z "$ADMIN_PASS" ]]; then
  ADMIN_PASS=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 12)
  warn "Random password generated: $ADMIN_PASS  (save it!)"
fi

read -p "🌐 Upstream DNS 1 [8.8.8.8]: " UPSTREAM1
UPSTREAM1=${UPSTREAM1:-8.8.8.8}
read -p "🌐 Upstream DNS 2 [1.1.1.1]: " UPSTREAM2
UPSTREAM2=${UPSTREAM2:-1.1.1.1}

echo ""
echo "🔓 If this server runs OTHER services (tunnel, game server, ...), enter their"
echo "   ports space-separated so the firewall keeps them open (e.g. 9003 8080 7777)."
read -p "   Extra ports to allow [none]: " EXTRA_PORTS

DNS_PORT=53
echo ""
info "Panel port : $PANEL_PORT"
info "Admin user : $ADMIN_USER"
info "Upstreams  : $UPSTREAM1, $UPSTREAM2"
echo ""
read -p "Continue installation? [Y/n]: " CONFIRM
CONFIRM=${CONFIRM:-Y}
[[ "$CONFIRM" =~ ^[Yy]$ ]] || { info "Cancelled."; exit 0; }

# ---------- system packages ----------
info "Updating system and installing dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip ufw curl dnsutils > /dev/null
ok "System packages installed."

# ---------- free port 53 (systemd-resolved) ----------
info "Checking port 53..."
if ss -lun 2>/dev/null | grep -q ":53 " || systemctl is-active --quiet systemd-resolved 2>/dev/null; then
  warn "Something is listening on port 53 (usually systemd-resolved). Fixing..."
  mkdir -p /etc/systemd/resolved.conf.d
  cat > /etc/systemd/resolved.conf.d/dns-panel.conf <<EOF
[Resolve]
DNSStubListener=no
EOF
  systemctl restart systemd-resolved 2>/dev/null || true
  # Replace stub resolv.conf with static one so server itself keeps working
  if [ -L /etc/resolv.conf ]; then
    rm -f /etc/resolv.conf
    echo -e "nameserver $UPSTREAM1\nnameserver $UPSTREAM2" > /etc/resolv.conf
  fi
  sleep 2
fi
if ss -lun 2>/dev/null | grep -q ":53 "; then
  err "Port 53 is still busy. Please stop the conflicting service manually (e.g. named, dnsmasq, pihole) and re-run."
  ss -lunp | grep ":53 " || true
  exit 1
fi
ok "Port 53 is free."

# ---------- copy files ----------
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
info "Installing to $INSTALL_DIR ..."
mkdir -p "$INSTALL_DIR"
cp -r "$SRC_DIR/app" "$SRC_DIR/requirements.txt" "$INSTALL_DIR/"
mkdir -p "$INSTALL_DIR/data"

# ---------- python venv ----------
info "Creating Python environment..."
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install -q --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install -q -r "$INSTALL_DIR/requirements.txt"
ok "Python dependencies installed."

# ---------- config ----------
SECRET=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32)
cat > "$INSTALL_DIR/config.env" <<EOF
PANEL_PORT=$PANEL_PORT
DNS_PORT=$DNS_PORT
PANEL_SECRET=$SECRET
ADMIN_USER=$ADMIN_USER
ADMIN_PASS=$ADMIN_PASS
DNS_PANEL_DB=$INSTALL_DIR/data/panel.db
EOF
chmod 600 "$INSTALL_DIR/config.env"

# ---------- detect public IP ----------
info "Detecting public IP..."
PUBLIC_IP=$(curl -s -4 --max-time 10 https://api.ipify.org || hostname -I | awk '{print $1}')
PUBLIC_IP=$(echo "$PUBLIC_IP" | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || hostname -I | awk '{print $1}')
info "Public IP: $PUBLIC_IP"

# ---------- init database ----------
info "Initializing database..."
set -a; source "$INSTALL_DIR/config.env"; set +a
cd "$INSTALL_DIR"
"$INSTALL_DIR/venv/bin/python" -c "
from app.database import init_db, create_admin, set_settings, seed_proxy_domains, proxy_count
init_db()
import os
create_admin(os.environ['ADMIN_USER'], os.environ['ADMIN_PASS'])
set_settings({'upstream1': '$UPSTREAM1', 'upstream2': '$UPSTREAM2', 'panel_port': '$PANEL_PORT', 'server_ip': '$PUBLIC_IP'})
seed_proxy_domains()
print('DB ready, proxy domains:', proxy_count())
" 2>&1 | tail -2
ok "Database ready."

# ---------- systemd services ----------
info "Creating systemd services..."
cat > /etc/systemd/system/dns-smart.service <<EOF
[Unit]
Description=DNS Shop Panel - SmartDNS Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$INSTALL_DIR/config.env
ExecStart=$INSTALL_DIR/venv/bin/python -m app.dns_server
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/dns-panel.service <<EOF
[Unit]
Description=DNS Shop Panel - Web Panel
After=network.target dns-smart.service

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$INSTALL_DIR/config.env
ExecStart=$INSTALL_DIR/venv/bin/python -c "from waitress import serve; from app.main import create_app; import os; serve(create_app(), host='0.0.0.0', port=int(os.environ.get('PANEL_PORT','8080')), threads=8)"
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/dns-sni.service <<EOF
[Unit]
Description=DNS Shop Panel - SNI Anti-Sanction Proxy (Shekan-like)
After=network.target dns-smart.service

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$INSTALL_DIR/config.env
ExecStart=$INSTALL_DIR/venv/bin/python -m app.sni_proxy
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable dns-smart dns-panel dns-sni > /dev/null 2>&1
systemctl restart dns-smart
sleep 2
systemctl restart dns-sni
sleep 1
systemctl restart dns-panel
sleep 2

# ---------- firewall ----------
info "Configuring firewall..."
ufw allow 53/udp > /dev/null 2>&1 || true
ufw allow 53/tcp > /dev/null 2>&1 || true
ufw allow 80/tcp > /dev/null 2>&1 || true
ufw allow 443/tcp > /dev/null 2>&1 || true
ufw allow "$PANEL_PORT"/tcp > /dev/null 2>&1 || true
for P in $EXTRA_PORTS; do
  P_CLEAN=$(echo "$P" | tr -cd '0-9')
  if [ -n "$P_CLEAN" ] && [ "$P_CLEAN" -ge 1 ] && [ "$P_CLEAN" -le 65535 ] 2>/dev/null; then
    ufw allow "$P_CLEAN" > /dev/null 2>&1 || true
    info "Extra port allowed: $P_CLEAN (tcp+udp)"
  else
    warn "Skipping invalid port: $P"
  fi
done
ufw allow OpenSSH > /dev/null 2>&1 || true
yes | ufw enable > /dev/null 2>&1 || true
ok "Firewall: 53/udp, 53/tcp, 80/tcp, 443/tcp, $PANEL_PORT/tcp allowed."

# ---------- verify ----------
echo ""
info "Verifying services..."
systemctl is-active --quiet dns-smart && ok "SmartDNS is running ✔" || { err "SmartDNS failed to start! Check: journalctl -u dns-smart -e"; }
systemctl is-active --quiet dns-sni && ok "SNI anti-sanction proxy is running ✔" || { err "SNI proxy failed to start! Check: journalctl -u dns-sni -e (ports 80/443 must be free)"; }
systemctl is-active --quiet dns-panel && ok "Web panel is running ✔" || { err "Panel failed to start! Check: journalctl -u dns-panel -e"; }

sleep 1
SERVER_IP=$(curl -s -4 --max-time 5 https://api.ipify.org || hostname -I | awk '{print $1}')

echo ""
echo "====================================================="
echo -e "  ${GREEN}🎉 Installation completed!${NC}"
echo "====================================================="
echo ""
echo "  🌐 Web Panel : http://$SERVER_IP:$PANEL_PORT"
echo "  👤 Username  : $ADMIN_USER"
echo "  🔑 Password  : $ADMIN_PASS"
echo ""
echo "  📡 DNS Server: $SERVER_IP  (port 53)"
echo "     Give this IP to customers as their DNS."
echo "  🔀 Anti-sanction proxy: $SERVER_IP (ports 80/443, like Shecan/Shelter)"
echo "     Sanctioned domains resolve to this IP and relay through it."
echo ""
echo "  🧪 Test from customer device (after adding their IP in panel):"
echo "     nslookup google.com $SERVER_IP        (should return real IPs)"
echo "     nslookup binance.com $SERVER_IP       (should return $SERVER_IP = proxied)"
echo ""
echo "  📋 Useful commands:"
echo "     systemctl status dns-smart dns-sni dns-panel"
echo "     journalctl -u dns-smart -f        (DNS live log)"
echo "     journalctl -u dns-sni -f          (proxy live log)"
echo "     journalctl -u dns-panel -f        (panel live log)"
echo "     bash $INSTALL_DIR/../dns-panel-change-port.sh  (if provided)"
echo ""
echo "  ⚠️  Next steps:"
echo "     1. Login to panel and create users with their PUBLIC IP"
echo "     2. Customer sets server IP as DNS on their device"
echo "     3. Manage sanctioned domains in panel: 🔀 دامنه‌های پروکسی"
echo "     4. Change password regularly / keep server updated"
echo ""
