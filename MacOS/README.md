# Marlowe for macOS

**Status:** Exercised & Validated (`macOS 14+`, Apple Silicon `arm64` & Intel `x64`)

Marlowe shares a single cross-platform Electron + Node.js codebase at the repository root (`../electron` and `../src`). This directory contains macOS-specific setup, the 9-CLI Homebrew manifest (`Brewfile`), and the `.app` bundle builder.

---

## 1. Prerequisites

1. **Xcode Command Line Tools** (compiles `node-pty` and provides `otool` for Mach-O binary triage):
   ```sh
   xcode-select --install
   ```
2. **Node.js `22.12+`** and `npm`:
   ```sh
   brew install node
   ```

---

## 2. Install the 9 Security CLIs (Optional, Recommended)

Marlowe's built-in analyzers (`scan_secrets`, `audit_code_patterns`, `audit_dependencies`, `triage_artifact`, `ScopeGate` HTTP/TLS/DNS/TCP, **Codebase DNA**) work with **zero external dependencies**.

To light up **9/9 Ready** in **Toolchain Doctor** and unlock full **9-CLI Security Convergence** + **Attack Reachability** corroboration, install the Homebrew bundle in this folder:

```sh
brew bundle --file=MacOS/Brewfile
```

| CLI | Purpose in Marlowe | Source on macOS |
| --- | --- | --- |
| `semgrep` | Multi-language AST / taint SAST | Homebrew (`semgrep`) |
| `gitleaks` | Git & directory secret detection | Homebrew (`gitleaks`) |
| `trivy` | Containers, IaC, lockfiles & vulnerability scan | Homebrew (`trivy`) |
| `osv-scanner` | Live OSV.dev supply-chain advisories | Homebrew (`osv-scanner`) |
| `nmap` | Scope-locked service & port discovery | Homebrew (`nmap`) |
| `nuclei` | Scope-locked template vulnerability verification | Homebrew (`nuclei`) |
| `tshark` | PCAP / network packet forensic inspection | Homebrew (`wireshark`) |
| `radare2` | Binary disassembly, strings & header triage | Homebrew (`radare2`) |
| `otool` | macOS Mach-O load commands & linked dylibs | Xcode Command Line Tools |

---

## 3. Run from Source

From the repository root:

```sh
npm install
npm start
```

---

## 4. Build `Marlowe.app`

Run from the repository root (or invoke `./MacOS/build-macos.sh`):

```sh
./MacOS/build-macos.sh
```

This outputs an unsigned desktop bundle at:
- Apple Silicon: `release/Marlowe-darwin-arm64/Marlowe.app`
- Intel Mac: `release/Marlowe-darwin-x64/Marlowe.app`

> **Unsigned build note:** Local builds are not notarized with an Apple Developer ID. If Gatekeeper blocks moving a copied build across machines, clear quarantine attributes first (`xattr -cr /path/to/Marlowe.app`) only on builds you compiled or verified yourself.

---

## 5. macOS Paths & Shell Notes

- **Local state & encrypted keys:** `~/Library/Application Support/Marlowe/` (`settings.json` encrypted via macOS Keychain / Electron `safeStorage`, `findings/`, `agent-runs/`, `agent-backups/`).
- **zsh shell integration:** Marlowe generates session-only startup shims in `~/Library/Application Support/Marlowe/shell/zsh/` to track working directory, Git branch, and command exit codes without ever modifying `~/.zshrc` or `~/.zprofile`.
