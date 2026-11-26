# Marlowe for Linux (`EXPERIMENTAL`)

![Status: EXPERIMENTAL](https://img.shields.io/badge/status-EXPERIMENTAL_(not_yet_host--validated)-e5c07b?style=flat-square&labelColor=181714)
![Targets](https://img.shields.io/badge/targets-Ubuntu_%7C_Debian_%7C_Fedora_%7C_Arch_(x64_%7C_arm64)-6ea8fe?style=flat-square&labelColor=181714)

> [!WARNING]
> **EXPERIMENTAL BUILD — NOT YET HOST-VALIDATED:** `Marlowe v0.6.0` has been exercised end-to-end on **macOS**. On Linux, POSIX PTY process-group isolation, `O_NOFOLLOW` workspace confinement, ELF binary triage, optional `shirudo` (10th CLI in Security Convergence for eBPF upatch + TPM 2.0 attestation), and `zsh` prompt hooks use the same Unix primitives, but desktop keyring behavior (`libsecret` / KWallet for Electron `safeStorage`) and distro-specific Chromium sandbox profiles have not yet been host-validated across Linux distributions. Prebuilt `Marlowe-Linux-x64-v0.6.0.tar.gz` archives are published on [GitHub Releases](https://github.com/zerotheory-labs/marlowe/releases/tag/v0.6.0). Please report any platform issues on GitHub.

Marlowe shares a single cross-platform Electron + Node.js codebase at the repository root (`../electron` and `../src`). This directory contains Linux setup documentation, a security-CLI reference installer, and the Linux desktop packager helper.

---

## 1. Prerequisites

1. **Node.js `22.12+`** and `npm`
2. **C/C++ build toolchain & keyring libraries** (to compile `node-pty` and support encrypted API key storage via Secret Service):

   **Ubuntu / Debian:**
   ```sh
   sudo apt-get update
   sudo apt-get install -y build-essential python3 pkg-config libsecret-1-dev libnss3 libatk-bridge2.0-0 libgtk-3-0 libgbm1 libasound2t64
   ```

   **Fedora:**
   ```sh
   sudo dnf groupinstall -y "Development Tools"
   sudo dnf install -y python3 libsecret-devel nss atk at-spi2-atk gtk3 mesa-libgbm alsa-lib
   ```

   **Arch Linux:**
   ```sh
   sudo pacman -S --needed base-devel python libsecret nss gtk3 alsa-lib
   ```

> **Keyring requirement:** Marlowe refuses to persist plaintext API keys if OS-backed `safeStorage` is unavailable. Ensure `gnome-keyring` or `kwallet` is active in your desktop session (local loopback models such as Ollama require no API key).

---

## 2. Install Security CLIs on Linux (Optional)

Built-in analyzers (**Codebase DNA**, `scan_secrets`, `audit_code_patterns`, `audit_dependencies`, `triage_artifact` with ELF magic/header inspection, and `ScopeGate` HTTP/TLS/DNS/TCP) run with zero external dependencies.

To install the 8 cross-platform security CLIs used by **Toolchain Doctor** (`semgrep`, `gitleaks`, `trivy`, `osv-scanner`, `nmap`, `nuclei`, `tshark`, `radare2`; note `otool` is macOS Mach-O specific), see `./LinuxOS/install-clis.sh` (uses Linuxbrew or distro packages).

---

## 3. Run from Source

From the repository root:

```sh
npm install
npm start
```

*(If your distribution restricts unprivileged user namespaces for Electron's Chromium sandbox, configure an AppArmor profile for Electron rather than disabling sandboxing.)*

---

## 4. Build Linux Bundle

From the repository root:

```sh
./LinuxOS/build-linux.sh
```

Output directory: `release/Marlowe-linux-x64/Marlowe` (or `linux-arm64`).

---

## 5. Linux Paths & Shell Notes

- **Local state & encrypted keys:** `~/.config/Marlowe/`
- **Shell integration:** If your login shell is `zsh`, Marlowe activates full prompt/directory/exit-status tracking via temporary shims under `~/.config/Marlowe/shell/zsh/` without touching `~/.zshrc`. In `bash` or `fish`, terminal tabs run normally and context attachment uses selected text or bounded buffer snapshots.
