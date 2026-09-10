#!/bin/bash
# =====================================================
#  DNS Shop Panel - One-line remote installer (bootstrap)
#  Usage on a fresh Ubuntu server (as root):
#    bash <(curl -fsSL https://raw.githubusercontent.com/USER/REPO/main/install-remote.sh)
#  - Fresh server  → downloads project + runs install.sh
#  - Existing install (/opt/dns-panel) → runs update.sh (users & data preserved)
# =====================================================
set -e

# ↓↓↓ EDIT THIS after creating your GitHub repo (or pass GITHUB_REPO env) ↓↓↓
REPO="${GITHUB_REPO:-Amirwixa/dns-shop-panel}"
BRANCH="${GITHUB_BRANCH:-main}"
DEST="${INSTALL_SRC:-/root/dns-shop-panel}"
TARBALL_URL="${REPO_TARBALL_URL:-https://github.com/$REPO/archive/refs/heads/$BRANCH.tar.gz}"

if [[ $EUID -ne 0 ]]; then echo "Please run as root: sudo bash <(curl -fsSL ...)"; exit 1; fi
if [[ "$REPO" == "YOUR_USER/dns-shop-panel" && -z "${REPO_TARBALL_URL:-}" ]]; then
  echo "ERROR: edit install-remote.sh and set your GitHub REPO (USER/REPO) first."
  echo "See PUSH_TO_GITHUB.md for instructions."
  exit 1
fi

command -v curl >/dev/null 2>&1 || { apt-get update -qq && apt-get install -y -qq curl; }

TMP=$(mktemp -d)
echo "⬇ Downloading $REPO ($BRANCH) ..."
if ! curl -fsSL "$TARBALL_URL" -o "$TMP/repo.tar.gz"; then
  echo "ERROR: download failed. Check repo name/branch (repo must be PUBLIC)."
  rm -rf "$TMP"
  exit 1
fi
rm -rf "$DEST"
mkdir -p "$DEST"
tar -xzf "$TMP/repo.tar.gz" -C "$TMP"
EXTRACTED=$(find "$TMP" -mindepth 1 -maxdepth 1 -type d | head -1)
if [ -z "$EXTRACTED" ] || [ ! -f "$EXTRACTED/install.sh" ]; then
  echo "ERROR: unexpected archive layout."
  rm -rf "$TMP"
  exit 1
fi
cp -r "$EXTRACTED"/. "$DEST"/
rm -rf "$TMP"
chmod +x "$DEST"/*.sh
echo "✔ Source ready at $DEST"

if [ "${SKIP_INSTALL:-0}" = "1" ]; then
  echo "(SKIP_INSTALL=1 → stopping before install/update)"
  exit 0
fi

if [ -d /opt/dns-panel ]; then
  echo "🔄 Existing installation detected → update.sh (data preserved)"
  bash "$DEST/update.sh"
else
  echo "🆕 Fresh install → install.sh"
  bash "$DEST/install.sh"
fi
