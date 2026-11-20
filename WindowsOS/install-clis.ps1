# Marlowe — Optional Windows Security CLI Installer (winget + pip)
# Review before running:
#   powershell -ExecutionPolicy Bypass -File .\WindowsOS\install-clis.ps1

$ErrorActionPreference = "Continue"

Write-Host "==> Installing Marlowe external security CLIs via winget / pip..."

winget install --id Gitleaks.Gitleaks -e --accept-source-agreements --accept-package-agreements
winget install --id AquaSecurity.Trivy -e --accept-source-agreements --accept-package-agreements
winget install --id Google.OSVScanner -e --accept-source-agreements --accept-package-agreements
winget install --id Insecure.Nmap -e --accept-source-agreements --accept-package-agreements
winget install --id ProjectDiscovery.Nuclei -e --accept-source-agreements --accept-package-agreements
winget install --id WiresharkFoundation.Wireshark -e --accept-source-agreements --accept-package-agreements
winget install --id RadareOrg.Radare2 -e --accept-source-agreements --accept-package-agreements

if (Get-Command pip -ErrorAction SilentlyContinue) {
  pip install --upgrade semgrep
} else {
  Write-Host "Note: Install Python/pip to add 'semgrep' (pip install semgrep)."
}

Write-Host "==> Done. Restart your terminal and open Toolchain Doctor in Marlowe."
