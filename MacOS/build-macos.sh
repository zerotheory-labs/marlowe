#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

ARCH="${1:-$(uname -m)}"
if [[ "$ARCH" == "x86_64" ]]; then
  ARCH="x64"
fi

echo "==> Building Marlowe for macOS (darwin-${ARCH})..."
npm run build
node scripts/package.mjs --platform=darwin --arch="${ARCH}"
echo "==> Done: release/Marlowe-darwin-${ARCH}/Marlowe.app"
