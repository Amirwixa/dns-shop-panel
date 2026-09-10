#!/bin/bash
# DNS Shop Panel - Uninstaller
set -e
if [[ $EUID -ne 0 ]]; then echo "Run as root: sudo bash uninstall.sh"; exit 1; fi
echo "Stopping services..."
systemctl stop dns-smart dns-sni dns-panel 2>/dev/null || true
systemctl disable dns-smart dns-sni dns-panel 2>/dev/null || true
rm -f /etc/systemd/system/dns-smart.service /etc/systemd/system/dns-sni.service /etc/systemd/system/dns-panel.service
systemctl daemon-reload
read -p "Delete data (/opt/dns-panel including users & logs)? [y/N]: " C
if [[ "$C" =~ ^[Yy]$ ]]; then rm -rf /opt/dns-panel; echo "Data deleted."; else echo "Data kept at /opt/dns-panel"; fi
rm -f /etc/systemd/resolved.conf.d/dns-panel.conf
systemctl restart systemd-resolved 2>/dev/null || true
echo "Uninstalled."
