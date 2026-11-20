#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

RAW_ARCH="${1:-$(uname -m)}"
case "$RAW_ARCH" in
  x86_64|x64) ARCH="x64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) ARCH="$RAW_ARCH" ;;
esac

echo "==> Building Marlowe for Linux (linux-${ARCH})..."
npm run build
node scripts/package.mjs --platform=linux --arch="${ARCH}"
echo "==> Done: release/Marlowe-linux-${ARCH}/Marlowe"
