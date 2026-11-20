#!/usr/bin/env bash
# Marlowe — Optional Linux Security CLI Installer
# Installs the 8 cross-platform security CLIs detected by Toolchain Doctor.
# Review before running:
#   ./LinuxOS/install-clis.sh
set -euo pipefail

if command -v brew >/dev/null 2>&1; then
  echo "==> Homebrew on Linux detected — installing security CLIs..."
  brew install semgrep gitleaks trivy osv-scanner nmap nuclei wireshark radare2
elif command -v apt-get >/dev/null 2>&1; then
  echo "==> Installing base CLIs via apt + Python pipx..."
  sudo apt-get update
  sudo apt-get install -y nmap tshark radare2 pipx
  pipx install semgrep
  echo "Note: Install latest gitleaks, trivy, osv-scanner, and nuclei from their official release packages or Homebrew on Linux."
elif command -v pacman >/dev/null 2>&1; then
  echo "==> Installing CLIs via pacman..."
  sudo pacman -S --needed gitleaks trivy nmap wireshark-cli radare2 python-pipx
  pipx install semgrep
else
  echo "Install semgrep, gitleaks, trivy, osv-scanner, nmap, nuclei, tshark, and radare2 using your distribution package manager."
fi
