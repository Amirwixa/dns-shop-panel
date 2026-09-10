#!/bin/bash
# =====================================================
#  DNS Shop Panel - Doctor (health check & diagnostics)
#  Read-only: changes NOTHING, only reports.
#  Run as root: sudo bash doctor.sh
# =====================================================
INSTALL_DIR="/opt/dns-panel"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}✔${NC} $1"; }
warn() { echo -e "  ${YELLOW}⚠${NC} $1"; }
bad()  { echo -e "  ${RED}✘${NC} $1"; }
sec() { echo -e "\n${BLUE}━━━ $1 ━━━${NC}"; }

echo "====================================================="
echo "     🩺 DNS Shop Panel - Doctor"
echo "     $(date '+%Y-%m-%d %H:%M:%S')"
echo "====================================================="

# ---------- 0. installation ----------
sec "0) Installation"
if [ -d "$INSTALL_DIR" ]; then ok "Installed at $INSTALL_DIR"; else bad "NOT installed at $INSTALL_DIR"; fi
[ -f "$INSTALL_DIR/config.env" ] && ok "config.env exists" || bad "config.env MISSING"
[ -f "$INSTALL_DIR/data/panel.db" ] && ok "database exists ($(du -h "$INSTALL_DIR/data/panel.db" 2>/dev/null | cut -f1))" || bad "database MISSING"
PANEL_PORT=$(grep -E '^PANEL_PORT=' "$INSTALL_DIR/config.env" 2>/dev/null | cut -d= -f2)
PANEL_PORT=${PANEL_PORT:-8080}
echo "  Panel port (config): $PANEL_PORT"
VENV_PY="$INSTALL_DIR/venv/bin/python"

# ---------- 1. services ----------
sec "1) Services (systemd)"
for svc in dns-smart dns-sni dns-panel; do
  if systemctl is-active --quiet "$svc" 2>/dev/null; then
    ok "$svc is RUNNING"
  else
    bad "$svc is NOT running  →  journalctl -u $svc -n 30 --no-pager"
  fi
done

# ---------- 2. ports ----------
sec "2) Listening ports (who owns what?)"
echo "  --- TCP ---"
(ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || echo "  (no ss/netstat available)") | head -30
echo "  --- UDP/53 ---"
(ss -ulnp 2>/dev/null | grep -E ':53\b' || echo "  nothing on UDP/53!") | head -10

# conflict analysis on key ports
for P in 53 80 443 "$PANEL_PORT"; do
  HOLDER=$(ss -tlnp 2>/dev/null | grep -E ":$P\b" | grep -oP '"\K[^"]+' | sort -u | tr '\n' ',' | sed 's/,$//')
  if [ -z "$HOLDER" ]; then
    [ "$P" = "53" ] && true || bad "TCP/$P: NOTHING listening!"
  else
    case "$HOLDER" in
      *python*) ok "TCP/$P ← python (ours) ✔" ;;
      *) bad "TCP/$P ← [$HOLDER] (NOT ours — CONFLICT!)";;
    esac
  fi
done
UHOLDER=$(ss -ulnp 2>/dev/null | grep -E ':53\b' | grep -oP '"\K[^"]+' | sort -u | tr '\n' ',' | sed 's/,$//')
if [ -z "$UHOLDER" ]; then bad "UDP/53: NOTHING listening!"; else
  case "$UHOLDER" in *python*) ok "UDP/53 ← python (ours) ✔";; *) bad "UDP/53 ← [$UHOLDER] (CONFLICT!)";;
  esac
fi

# ---------- 3. recent errors ----------
sec "3) Recent service errors"
for svc in dns-smart dns-sni dns-panel; do
  echo "  --- $svc ---"
  journalctl -u "$svc" -n 40 --no-pager 2>/dev/null | grep -iE 'error|fail|refused|denied|traceback|exception|address already|permission' | tail -5 || echo "  (no journal or no errors)"
done

# ---------- 4. settings via venv python ----------
sec "4) Panel settings (DB)"
if [ -x "$VENV_PY" ]; then
  SETTINGS=$($VENV_PY -c "
import sys; sys.path.insert(0, '$INSTALL_DIR')
import os; os.environ['DNS_PANEL_DB']='$INSTALL_DIR/data/panel.db'
from app.database import get_all_settings
s = get_all_settings()
for k in ['dns_mode','server_ip','sni_enabled','upstream1','upstream2','refuse_unlisted','link_cooldown_sec']:
    print(f'{k}={s.get(k)}')
" 2>&1)
  echo "$SETTINGS" | sed 's/^/  /'
  MODE=$(echo "$SETTINGS" | grep '^dns_mode=' | cut -d= -f2)
  SRVIP=$(echo "$SETTINGS" | grep '^server_ip=' | cut -d= -f2)
  SNIEN=$(echo "$SETTINGS" | grep '^sni_enabled=' | cut -d= -f2)
else
  warn "venv python missing!"; MODE=""; SRVIP=""; SNIEN=""
fi

# ---------- 5. server_ip sanity ----------
sec "5) Server IP check"
PUB=$(curl -s -4 --max-time 8 https://api.ipify.org 2>/dev/null || echo "")
echo "  Actual public IP : ${PUB:-unknown}"
echo "  Panel server_ip  : ${SRVIP:-(empty)}"
LOCAL_IPS=$(ip -4 addr show 2>/dev/null | grep -oP 'inet \K[\d.]+' | tr '\n' ' ')
echo "  Local IPv4s      : ${LOCAL_IPS:-(unknown)}"
if [ -z "$SRVIP" ]; then
  bad "server_ip is EMPTY → proxied domains fall back to upstream (no sanction bypass)"
elif echo " $LOCAL_IPS " | grep -q " $SRVIP "; then
  ok "server_ip ($SRVIP) is LOCAL on this box ✔ (multi-IP server — fine, customers must use a reachable IP as DNS)"
elif [ -n "$PUB" ] && [ "$SRVIP" != "$PUB" ]; then
  bad "MISMATCH! Panel server_ip ($SRVIP) is neither local nor public ($PUB) → proxied sites WILL BREAK"
else
  ok "server_ip matches public IP ✔"
fi
case "$SRVIP" in 10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*|127.*)
  bad "server_ip looks PRIVATE ($SRVIP) → proxied sites WILL BREAK (fix in panel → تنظیمات DNS)";; esac

# ---------- 6. DNS self-tests ----------
sec "6) DNS self-tests (from this server)"
if command -v dig >/dev/null 2>&1; then
  for D in google.com binance.com; do
    OUT=$(dig @127.0.0.1 -p 53 "$D" +time=3 +tries=1 2>&1)
    STATUS=$(echo "$OUT" | grep -o 'status: [A-Z]*' | head -1 | cut -d' ' -f2)
    ANS=$(echo "$OUT" | awk '/^[^;].*\sIN\s+A\s/ {print $NF}' | head -2 | tr '\n' ' ')
    [ -z "$STATUS" ] && STATUS="TIMEOUT(no response)"
    echo "  $D → status=$STATUS $ANS"
  done
  echo "  (NOTE: status=REFUSED for 127.0.0.1 is NORMAL if localhost isn't a registered user — it still proves DNS is alive)"
else
  warn "dig not found, trying venv python..."
  [ -x "$VENV_PY" ] && $VENV_PY -c "
import sys; sys.path.insert(0,'$INSTALL_DIR')
import socket
from dnslib import DNSRecord
for d in ['google.com','binance.com']:
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(3)
        s.sendto(DNSRecord.question(d).pack(),('127.0.0.1',53))
        r=DNSRecord.parse(s.recvfrom(4096)[0]); s.close()
        print(f'  {d} -> rcode={r.header.rcode} answers={[str(x.rdata) for x in r.rr][:2]}')
    except Exception as e:
        print(f'  {d} -> TIMEOUT ({e})')
" 2>&1 || warn "DNS self-test skipped"
fi

# ---------- 7. SNI ports reachable? ----------
sec "7) SNI proxy ports (80/443) reachable locally?"
for P in 80 443; do
  if timeout 3 bash -c "echo > /dev/tcp/127.0.0.1/$P" 2>/dev/null; then
    ok "TCP/$P accepts connections ✔"
  else
    bad "TCP/$P NOT reachable → proxied/full-mode sites WILL BREAK"
  fi
done

# ---------- 8. panel reachable? ----------
sec "8) Web panel reachable locally?"
CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:$PANEL_PORT/login" 2>/dev/null); CODE=${CODE:-000}
if [ "$CODE" = "200" ]; then ok "Panel http://127.0.0.1:$PANEL_PORT/login → 200 ✔"
else bad "Panel → HTTP $CODE (want 200)"; fi

# ---------- 9. users summary ----------
sec "9) Users summary"
if [ -x "$VENV_PY" ]; then
  $VENV_PY -c "
import sys; sys.path.insert(0, '$INSTALL_DIR')
import os; os.environ['DNS_PANEL_DB']='$INSTALL_DIR/data/panel.db'
from app.database import dashboard_stats
d = dashboard_stats()
u = d['users']
print(f\"  total={u['total']} active={u['active']} expired={u['expired']} expiring(3d)={u['expiring']} disabled={u['disabled']}\")
print(f\"  queries today={d['queries']['today']} blocked/refused today={d['queries']['blocked_today']}\")
" 2>&1 | sed 's/^/  /' || warn "stats failed"
fi

# ---------- 10. firewall ----------
sec "10) Firewall (UFW)"
if command -v ufw >/dev/null 2>&1; then
  ufw status 2>/dev/null | head -25 | sed 's/^/  /'
else
  echo "  ufw not installed"
fi

# ---------- 11. resources ----------
sec "11) Resources"
free -m 2>/dev/null | head -2 | sed 's/^/  /' || true
df -h / 2>/dev/null | tail -1 | sed 's/^/  Disk: /' || true
uptime 2>/dev/null | sed 's/^/  /' || true

# ---------- verdict ----------
echo ""
echo "====================================================="
echo "  🩺 QUICK VERDICT"
echo "====================================================="
if [ "$MODE" = "full" ]; then
  echo -e "  Mode: ${YELLOW}FULL (all traffic via server)${NC}"
  echo "  → Requires: dns-sni RUNNING + TCP 80/443 owned by us + correct server_ip."
  echo "  → If anything above is red, users can't open ANY site."
  echo "  → Emergency rollback to smart mode (no panel needed):"
  echo "      $VENV_PY -c \"import sys;sys.path.insert(0,'$INSTALL_DIR');import os;os.environ['DNS_PANEL_DB']='$INSTALL_DIR/data/panel.db';from app.database import set_setting;set_setting('dns_mode','smart')\""
  echo "      systemctl restart dns-smart   # (or wait 30s for auto-reload)"
else
  echo -e "  Mode: ${GREEN}SMART${NC} (only proxy-list domains via server)"
  echo "  → Normal sites work even if SNI proxy is down; listed/sanctioned ones need it."
fi
echo ""
echo "  If users get REFUSED a lot: their IP changed → they must open their 🔗 link."
echo "  Paste this FULL output to your AI assistant for pinpoint diagnosis."
echo "====================================================="
