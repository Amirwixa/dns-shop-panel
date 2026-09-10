#!/bin/bash
# =====================================================
#  DNS Shop Panel - WARP installer (optional)
#  Installs Cloudflare WARP via WireGuard WITHOUT hijacking
#  server traffic: only connections explicitly bound to the
#  WARP IP (i.e. our SNI proxy when warp_enabled=1) use it.
#  SSH / panel / DNS / tunnels keep working directly.
#  Run as root: sudo bash install-warp.sh
# =====================================================
set -e
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
err()  { echo -e "${RED}[ERR]${NC} $1"; exit 1; }

[[ $EUID -ne 0 ]] && err "Run as root: sudo bash install-warp.sh"
WG_DIR="/etc/wireguard"
WG_CONF="$WG_DIR/warp.conf"

echo "====================================================="
echo "     ☁️  WARP installer for DNS Shop Panel"
echo "====================================================="

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq wireguard iproute2 curl > /dev/null
ok "wireguard installed"

# ---------- wgcf binary ----------
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  WGCF_ASSET="wgcf_Linux_x86_64" ;;
  aarch64) WGCF_ASSET="wgcf_Linux_arm64" ;;
  *) err "Unsupported architecture: $ARCH" ;;
esac
if ! command -v wgcf >/dev/null 2>&1; then
  curl -fsSL "https://github.com/ViRb3/wgcf/releases/latest/download/$WGCF_ASSET" -o /usr/local/bin/wgcf \
    || err "wgcf download failed (check internet/GitHub access)"
  chmod +x /usr/local/bin/wgcf
fi
ok "wgcf ready ($(wgcf --version 2>/dev/null | head -1))"

mkdir -p "$WG_DIR"
cd "$WG_DIR"

# ---------- register (once) ----------
if [ ! -f "$WG_DIR/wgcf-account.toml" ]; then
  wgcf register --accept-tos || err "WARP registration failed"
  ok "WARP account registered"
else
  ok "WARP account exists, reusing"
fi

# ---------- generate profile (once, keep existing) ----------
if [ ! -f "$WG_CONF" ]; then
  wgcf generate -p "$WG_DIR/wgcf-account.toml" > /dev/null || err "wgcf generate failed"
  mv -f "$WG_DIR/wgcf-profile.conf" "$WG_CONF"
  ok "WireGuard profile generated"
else
  ok "Using existing $WG_CONF"
fi

# ---------- patch: Table=off + policy routing (WARP-only for bound sockets) ----------
WARP_IP=$(grep -oP '^Address\s*=\s*\K[0-9.]+' "$WG_CONF" | head -1)
[ -z "$WARP_IP" ] && err "Could not parse WARP IP from $WG_CONF"

# ensure Table = off under [Interface]
if grep -qE '^Table\s*=' "$WG_CONF"; then
  sed -i -E 's/^Table\s*=.*/Table = off/' "$WG_CONF"
else
  sed -i '/^\[Interface\]/a Table = off' "$WG_CONF"
fi
# idempotent PostUp/PreDown
sed -i '/^PostUp = ip rule add from /d; /^PreDown = ip rule del from /d' "$WG_CONF" 2>/dev/null || true
sed -i '/^Table = off/a PostUp = ip rule add from '"$WARP_IP"' table 100; ip route add default dev warp table 100\nPreDown = ip rule del from '"$WARP_IP"' table 100; ip route del default dev warp table 100' "$WG_CONF"
ok "Policy routing configured (WARP IP: $WARP_IP)"

# ---------- bring up ----------
systemctl enable --now wg-quick@warp 2>&1 | tail -1 || true
sleep 3
if ip link show warp >/dev/null 2>&1; then
  ok "warp interface is UP"
else
  err "warp interface failed. Check: journalctl -u wg-quick@warp -e"
fi

# ---------- verify exit IP via WARP ----------
EXIT_IP=$(curl -s --max-time 10 --interface "$WARP_IP" https://api.ipify.org || echo "")
DIRECT_IP=$(curl -s --max-time 10 https://api.ipify.org || echo "?")
echo ""
echo "  Direct exit IP : $DIRECT_IP"
echo "  WARP exit IP   : ${EXIT_IP:-FAILED}"
[ -z "$EXIT_IP" ] && err "Traffic via WARP failed. Check: wg show; ip rule; ip route show table 100"
ok "WARP works ✔"

echo ""
echo "====================================================="
echo -e "  ${GREEN}🎉 WARP installed!${NC}  Next step:"
echo "  Panel → ⚙️ تنظیمات DNS → بخش ☁️ وارپ → «فعال» + ذخیره"
echo "  (SNI proxy outbound will then exit via $EXIT_IP)"
echo "  Disable anytime: systemctl stop wg-quick@warp"
echo "====================================================="
