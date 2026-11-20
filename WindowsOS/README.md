# Marlowe for Windows

**Status:** Experimental / Not Yet Host-Validated (`Windows 11 x64 / arm64`)

Marlowe shares a single cross-platform Electron + Node.js codebase at the repository root (`../electron` and `../src`). This directory contains Windows setup documentation, an optional security-CLI installer script, and the `win32` desktop packager helper.

> **Platform honesty note:** The `v0.4.0` release has been exercised end-to-end on macOS. Windows PTY sessions (`PowerShell` / `cmd.exe` via ConPTY), DPAPI key encryption (`safeStorage`), and core Node.js analyzers are cross-platform, while zsh-specific prompt hooks, `otool` (macOS Mach-O only), and Windows shell process-tree cancellation have not yet been validated on a Windows host.

---

## 1. Prerequisites

1. **Node.js `22.12+` LTS** (`winget install OpenJS.NodeJS.LTS`)
2. **Python 3 + Visual Studio 2022 Build Tools** with the **Desktop development with C++** workload (required by `electron-rebuild` to compile `node-pty` against Electron's Windows ABI):
   ```powershell
   winget install Python.Python.3.12
   winget install Microsoft.VisualStudio.2022.BuildTools --override "--passive --wait --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
   ```

---

## 2. Install Security CLIs on Windows (Optional)

Marlowe's built-in security analyzers (**Codebase DNA**, `scan_secrets`, `audit_code_patterns`, `audit_dependencies`, `triage_artifact` including PE header detection, and `ScopeGate` HTTP/TLS/DNS/TCP) run natively in Node.js with zero external binaries.

To install the external CLI engines detected by **Toolchain Doctor** (`8/8` applicable on Windows; `otool` is macOS Mach-O specific), review and run `WindowsOS\install-clis.ps1` or install individually via `winget` / `pip`:

```powershell
powershell -ExecutionPolicy Bypass -File .\WindowsOS\install-clis.ps1
```

---

## 3. Run from Source

From PowerShell at the repository root:

```powershell
npm install
npm start
```

---

## 4. Build `Marlowe.exe`

From PowerShell at the repository root:

```powershell
.\WindowsOS\build-windows.ps1
```

Output directory: `release\Marlowe-win32-x64\Marlowe.exe` (unsigned portable folder).

---

## 5. Windows Paths & Differences from macOS

- **Local state & encrypted keys:** `%APPDATA%\Marlowe\` (API keys encrypted via Windows DPAPI through Electron `safeStorage`).
- **Shell integration:** Terminal tabs launch `powershell.exe` (or `%COMSPEC%`). Context sharing falls back cleanly to selected terminal text or bounded buffer preview.
- **Keyboard shortcuts:** Use `Ctrl+,` (Settings), `Ctrl+T` (New terminal), `Ctrl+J` (Toggle Marlowe drawer), and `Ctrl+Shift+L` (Focus composer).
