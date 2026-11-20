# Marlowe.

**Security for AI. A little more careful.**

Marlowe (`v0.4.0`, by **[Zero Theory Labs](https://github.com/zero-theory-labs)**) is a native desktop terminal and cybersecurity workbench: real interactive shells (`node-pty` + `xterm.js`) alongside a streaming security partner, **Codebase DNA**, **9-CLI Security Convergence**, **Attack Reachability** graphs, host-enforced **Approve once** gates, `ScopeGate` SSRF confinement, secret masking, and SARIF v2.1.0 / Markdown finding reports.

> **License:** Source-available under the **[PolyForm Noncommercial License 1.0.0](./LICENSE)**. Personal, academic, educational, non-profit, and non-commercial security research uses are free. Commercial use requires a separate license from Zero Theory Labs.

---

## Operating System Folders

Choose your platform folder for OS-specific prerequisites, 9-CLI security toolchain installers, and desktop bundle scripts:

| Folder | Platform | Validation Status | Quick Links |
| --- | --- | --- | --- |
| **[`MacOS/`](./MacOS)** | macOS 14+ (`arm64` & `x64`) | **Exercised & Validated** | [Setup Guide](./MacOS/README.md) · [`Brewfile` (9 CLIs)](./MacOS/Brewfile) · [`build-macos.sh`](./MacOS/build-macos.sh) |
| **[`WindowsOS/`](./WindowsOS)** | Windows 11 (`x64` & `arm64`) | **Experimental** *(not yet host-validated)* | [Setup Guide](./WindowsOS/README.md) · [`install-clis.ps1`](./WindowsOS/install-clis.ps1) · [`build-windows.ps1`](./WindowsOS/build-windows.ps1) |
| **[`LinuxOS/`](./LinuxOS)** | Linux (`x64` & `arm64`) | **Experimental** *(not yet host-validated)* | [Setup Guide](./LinuxOS/README.md) · [`install-clis.sh`](./LinuxOS/install-clis.sh) · [`build-linux.sh`](./LinuxOS/build-linux.sh) |

All three platforms build from the **single shared codebase** at this repository root (`electron/` and `src/`).

---

## Quickstart (From Source)

Requires **Node.js `22.12+`** and `npm` (plus C++ build tools for `node-pty` — Xcode CLT on macOS, `build-essential` + `libsecret-1-dev` on Linux, or Visual Studio Build Tools on Windows).

```sh
npm install
npm start
```

- `npm run dev` builds an unminified renderer and launches Electron (restart after source changes; no hot reload).
- `npm run package` (or `./MacOS/build-macos.sh`, `.\WindowsOS\build-windows.ps1`, `./LinuxOS/build-linux.sh`) creates an unsigned desktop bundle under `release/`.

---

## Connect a Model (Local Air-Gapped or Cloud)

Open **Settings** with the gear icon or **⌘,** (`Ctrl+,` on Windows/Linux) to open the **Model Command Center**:

- **Local Loopback Radar (Zero Data Egress):** Automatically probes `127.0.0.1` for **Ollama (`:11434`)**, **LM Studio (`:1234`)**, **Jan (`:1337`)**, and **vLLM (`:8000`)**, lists installed local models, displays a model security-fit badge (flagging small models prone to SAST false positives vs. recommended 14B–32B+ reasoning models), and offers 1-click `ollama pull` in your active shell.
- **Cloud Provider Presets (10 Built-In):** One-click endpoint + curated security model presets for **Anthropic Claude**, **OpenAI**, **Google Gemini**, **xAI Grok**, **DeepSeek**, **Mistral**, **Groq**, **Together AI**, **Fireworks AI**, and **OpenRouter**, plus any custom OpenAI-compatible `/chat/completions` SSE server.
- **Connection Verification & Keychain Storage:** **Test connection** measures live round-trip streaming latency before saving. API keys are encrypted via OS-backed Electron `safeStorage` (macOS Keychain / Windows DPAPI / Linux Secret Service) and never exposed to the renderer. Switching the endpoint clears the stored key unless a new key is supplied, and HTTP redirects are rejected so credentials are never forwarded to another host.

---

## Three Live Security Visualizations (`v0.4`)

1. **Codebase DNA (`DNA` Drawer Tab):** Plots workspace files across **Shannon byte entropy (`0.00–8.00 bits/byte`)** × directory lanes × **9-CLI security posture** (`Clean`, `Binary / PCAP`, `Medium / Low`, `Critical / High`). Multi-finding files display `×N` badges; clicking any node opens its entropy profile, CLI coverage tags, active CWEs, and 1-click **Audit File →**, **Mark Mitigated ✓**, or **False Positive** actions.
2. **9-CLI Security Convergence (Main Stage Tab):** Interactive 3-column bipartite graph beside the `Marlowe` terminal tab mapping installed local security engines (`Semgrep`, `Gitleaks`, `Trivy`, `OSV-Scanner`, `Nmap`, `Nuclei`, `TShark`, `Radare2`, `otool`) → live workspace & scope assets → corroborated CWE / artifact posture.
3. **Attack Reachability (Main Stage Tab):** Interactive taint-reachability topology mapping untrusted entrypoints (HTTP/API inputs, CLI args, CI triggers, dependencies, artifacts) → vulnerable code/config sinks → blast radius (RCE, data egress, supply-chain compromise, or contained/mitigated).

---

## Cybersecurity Workbench (`v0.4`)

Marlowe operates as a multi-domain AppSec, authorized recon, and DFIR triage workbench while keeping the renderer sandboxed (`connect-src 'none'`):

- **Four Agent Playbooks:** **Engineering** (`12` rounds / `32` actions) plus three deep-investigation security playbooks — **AppSec Audit**, **Authorized Recon**, and **DFIR Triage** (`24` rounds / `64` actions each) — governed by strict source-to-sink taint verification before recording findings.
- **Host-Enforced Authorized Scope (`ScopeGate`) & SSRF Guard:** Configure authorized hostnames, wildcard subdomains (`*.example.com`), URLs, or IPv4 CIDRs in **Scope**. Network inspection and scanner tools (`inspect_http_security`, `inspect_tls`, `dns_recon`, `probe_ports`, and `nmap`/`nuclei` via `run_security_scanner`) reject out-of-scope targets and block DNS resolution to loopback, RFC1918, link-local, or cloud-metadata (`169.254.169.254`) addresses unless explicitly authorized.
- **Built-In Zero-Dependency Security Analyzers:**
  - **AppSec & Secrets:** `scan_secrets` (signature + Shannon entropy scanner that masks raw credential values before returning results to the model, ignoring `$VAR` / `<token>` placeholders) and `audit_code_patterns` (CWE-mapped injection, XSS, deserialization, crypto, CORS, and container checks).
  - **Supply Chain & OSV:** `audit_dependencies` inventories `package-lock.json`, `package.json`, `pnpm-lock.yaml`, `requirements.txt`, `pyproject.toml`, `go.mod`, and `Cargo.lock`, generates a CycloneDX 1.5 SBOM summary, and (when enabled in Scope) queries `api.osv.dev` with package names and versions only.
  - **Scope-Locked Web, TLS, DNS & Port Inspection:** `inspect_http_security`, `inspect_tls`, `dns_recon`, and `probe_ports` (bounded up to 32 TCP ports; requires **Approve once**).
  - **DFIR, Binary & Log Triage:** `triage_artifact` (`O_NOFOLLOW` inspection up to 10 MB for SHA-256/SHA-1/MD5, byte entropy, ELF/Mach-O/PE/PDF/PCAP headers, and notable strings), `extract_iocs`, and `analyze_logs`.
- **Toolchain Doctor & Typed Scanner Wrappers:** Detects `semgrep`, `trivy`, `gitleaks`, `osv-scanner`, `nmap`, `nuclei`, `tshark`, `radare2`, and `otool` from verified login `PATH` directories outside the workspace, executing preset profiles via `spawn(binary, argv, { shell: false })` after **Approve once**, filtering noisy informational rules, and masking secrets.
- **Auto-Reconciling Findings Ledger & SARIF Export:** `record_finding` deduplicates per-file findings and persists them locally per workspace. Editing or fixing a file and clicking **Rescan** automatically reconciles cleared findings to `mitigated` and turns **Codebase DNA** nodes green (`#3ddc97`). Supports 1-click **Dismiss Rule (×N)** suppression and exports **Markdown**, **SARIF v2.1.0**, or **JSON**.

---

## Agent Execution & Approval Policy

1. Select **Agent** above the composer and choose a specific project folder (the home directory and disk root are refused).
2. Describe the task or audit. Marlowe streams real tool activity cards; model prose narrating fake approvals or activity is rejected by host guards.
3. Review action cards: **Approve once** authorizes that single action (`{ runId, approvalId }`); **Deny** skips it; **Stop** cancels the model request, pending approvals, and the active command process group on macOS/Linux.

| Action | Host Enforcement |
| --- | --- |
| List, find, search, and read workspace text files | Automatic; `.env*`, `.git`, SSH/cloud keys, symlinks (`O_NOFOLLOW`), hard links, and binary files are refused |
| Built-in local passive analyzers (`scan_secrets`, `audit_code_patterns`, `triage_artifact`, `analyze_logs`, `extract_iocs`) | Automatic within the selected workspace; detected secrets are masked |
| Create a new file | Automatic when its parent directory exists inside the workspace |
| Focused exact-match file edits | Automatic unless they delete text, blank content, replace the entire file, or replace >100 lines |
| Overwrite or delete an existing file | Review bounded line diff (plus full before/after file toggle) and click **Approve once** |
| Exact `pwd`, `ls`, `ls -l`, `ls -a`, `ls -la` | Automatic via fixed system binaries on macOS/Linux |
| Active TCP port probes, external CLI scanners, and arbitrary shell commands (`run_command`) | Review exact argv/command, working directory, scope target, and timeout, then click **Approve once** |

> **Important boundary:** Approved shell commands run as your OS user in a minimal `/bin/sh` environment and **are not OS-sandboxed** — they may access files outside the workspace or the network. File-tool path checks are not a sandbox for shell commands you approve. Always inspect the command shown on the approval card.

### Environment, Backups, Logs & Limits

- **Clean `PATH`-only environment:** Agent commands inherit only verified login-shell `PATH` directories outside the workspace (so Homebrew/nvm/pyenv/mise tools resolve normally, while workspace files cannot shadow approved command names) — never API keys, aliases, or arbitrary environment variables.
- **Snapshots & Safe Undo:** File mutations save snapshots under `agent-backups/`. **Undo file change** restores a file only if it still matches the agent's exact output, protecting newer manual edits.
- **Audit Logs & Reliability Checks:** Every run writes a local JSONL audit log under `agent-runs/`. Open **Agent reliability** in the top bar to inspect tool/guard telemetry or run deterministic offline safeguard checks (**Run checks**) in a disposable temp folder.
- **Terminal Context Consent:** Terminal output is **off by default**. Checking **Attach terminal output** captures a one-shot snapshot (capped at `16,000` chars) that you can inspect, edit, or scrub with **Redact secrets** via **Preview** before sending. Right-clicking a terminal offers **Explain selection**, **Explain last command**, or **Help fix this error**.
- **Connected `Marlowe` Terminal Tab:** The `Marlowe` tab beside your shell tabs mirrors live conversation and tool results using an escape-stripped line editor so model output can never inject terminal control sequences or execute shell input.

---

## Validation & Tests

```sh
npm test          # 55 unit tests: ScopeGate, SSRF guard, analyzers, findings reconciliation, provider, agent gates
npm run test:e2e  # Playwright Electron desktop suites against a local deterministic SSE model server
```

Tests never call paid external APIs and run against isolated temporary `userData` directories.

---

## Project Layout

- [`MacOS/`](./MacOS), [`WindowsOS/`](./WindowsOS), [`LinuxOS/`](./LinuxOS) — OS-specific setup guides, 9-CLI manifests, and packaging scripts.
- `electron/main.cjs`, `electron/preload.cjs` — Electron lifecycle, sender-verified IPC, PTY sessions, `safeStorage` keys, local persistence.
- `electron/provider.cjs` — Loopback runtime radar, 10 cloud provider presets, Anthropic/Gemini/OpenAI SSE streaming transport.
- `electron/agent.cjs`, `electron/agent-tools.cjs` — Playbook loop, `ApprovalGate`, workspace file confinement, backups/Undo, and command runner.
- `electron/cyber-scope.cjs` — `ScopeGate`, DNS-rebinding/SSRF guard, and credential redactor.
- `electron/cyber-analyzers.cjs` — Built-in AppSec, SBOM/OSV, HTTP/TLS/DNS/TCP, DFIR, **Codebase DNA**, and **Convergence / Reachability** graph builders.
- `electron/cyber-toolchain.cjs` — Toolchain Doctor and `shell: false` preset wrappers + noise filters for the 9 security CLIs.
- `electron/findings.cjs` — Workspace Findings Ledger, deduplication, auto-reconciliation, and Markdown / SARIF v2.1.0 / JSON exporters.
- `src/` — Sandboxed UI (`app.js`, `cyber.js`, `stage-graphs.js`, `benjamin-terminal.mjs`, `reliability.js`, `styles.css`, `index.html`).
- `test/` — Node unit tests (`*.test.cjs`) and Playwright Electron E2E tests (`*.e2e.cjs`).

---

## Security & Licensing

- **Vulnerability disclosure & trust boundaries:** See **[`SECURITY.md`](./SECURITY.md)**.
- **Source-available license:** **[PolyForm Noncommercial License 1.0.0](./LICENSE)** — Copyright (c) Zero Theory Labs.
- **Bundled fonts & open-source notices:** See **[`THIRD_PARTY_NOTICES.md`](./THIRD_PARTY_NOTICES.md)**.
