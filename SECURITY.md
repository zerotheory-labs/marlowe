# Security Policy

## Supported Versions

| Version | Supported | Platform Status |
| --- | --- | --- |
| `0.4.x` | Yes | macOS (exercised); Windows & Linux (experimental / not yet host-validated) |
| `< 0.4.0` | No | Superseded |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for suspected security vulnerabilities in Marlowe (such as renderer sandbox escapes, IPC validation bypasses, `ScopeGate` / SSRF guard bypasses, `ApprovalGate` bypasses, symlink/traversal escapes in workspace file tools, or terminal control-sequence injection).

Instead, report vulnerabilities privately through **GitHub Private Vulnerability Reporting** on this repository:

- `https://github.com/zerotheory-labs/marlowe/security/advisories/new`

Include:
1. Affected version, operating system, and commit hash.
2. Minimal reproduction steps or proof-of-concept workspace/payload.
3. Expected security boundary vs. observed behavior.

## Enforced Security Boundaries vs. Intentional Design

When auditing Marlowe, distinguish enforced host boundaries from capabilities that intentionally execute with user authority:

### Enforced Host Boundaries (Bugs Here Are Security Issues)
- **Renderer isolation:** `contextIsolation: true`, `sandbox: true`, `nodeIntegration: false`, and CSP `connect-src 'none'`. Every IPC handler in `electron/main.cjs` validates sender frame origin and bounds input types.
- **One-shot `ApprovalGate`:** Destructive file mutations, arbitrary shell commands, port probes, and external security scanners require an explicit user click bound to `{ runId, approvalId }`. Model prose claiming approval is rejected.
- **`ScopeGate` & SSRF / DNS-rebinding guard (`electron/cyber-scope.cjs`):** Active HTTP, TLS, DNS, port-probe, and network scanner tools reject out-of-scope hosts and refuse targets resolving to loopback, RFC1918, link-local, or cloud-metadata (`169.254.169.254`) addresses unless explicitly authorized in `scope.json`.
- **Workspace file confinement (`electron/agent-tools.cjs`):** Workspace file tools reject paths outside the selected workspace, symlinks (`O_NOFOLLOW`), hard links, binary files (except bounded read-only `triage_artifact`), and sensitive credential paths (`.env*`, `.git`, SSH/cloud keys).
- **Credential storage & secret masking:** Provider API keys are encrypted via OS-backed Electron `safeStorage` and cleared when changing API base URL unless re-entered. `scan_secrets` and `redactSecrets` mask raw secret values before serializing tool output to the model.
- **External CLI execution (`electron/cyber-toolchain.cjs`):** Security CLIs resolve only from verified login `PATH` directories outside the workspace and execute via `spawn(binary, argv, { shell: false })`.

### Non-Boundaries by Design (Documented Operator Responsibility)
- **Interactive terminal tabs (`zsh` / `bash` / `PowerShell`)** are real shells running with your OS user permissions.
- **User-approved `run_command` actions** execute in `/bin/sh -c` as your user and are **not OS-sandboxed**. File-tool path restrictions do not confine shell commands that you explicitly approve. Review the command, working directory, and timeout on the approval card before clicking **Approve once**.
- **Configured LLM endpoints** receive conversation messages, explicitly attached terminal snapshots, and Agent tool outputs. Use a local loopback model (`Ollama`, `LM Studio`, `vLLM`, `Jan`) when auditing sensitive or air-gapped codebases.
