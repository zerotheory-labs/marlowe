# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Marlowe (formerly `benjamin`) is Zero Theory Labs' Electron desktop AI terminal and cybersecurity workbench: real interactive shells (node-pty + xterm.js) beside a streaming conversation with any OpenAI-compatible `/chat/completions` endpoint. It has a tool-less **Chat** mode and an **Agent** mode (with `general`, `appsec`, `recon`, `dfir`, and `upatch` / **Draft Shield** playbooks) that audits code/artifacts, inspects scope-locked targets, audits/verifies Shirudo eBPF upatches and TPM 2.0 quotes, edits files, records structured findings, and runs commands behind host-enforced approval and scope gates. README.md is the user-facing spec of that behavior (limits, approval policy, data retention) — keep it in sync when behavior changes.

## Commands

Requires Node.js 22.12+. `npm install` runs a `postinstall` that rebuilds `node-pty` against Electron's ABI.

```sh
npm start            # minified renderer build, then launch Electron
npm run dev          # unminified build, then launch (no hot reload — restart after changes)
npm run build        # esbuild src/app.js -> dist/ (also copies index.html)
npm test             # node --test test/*.test.cjs (unit tests, no Electron needed)
npm run test:e2e     # build, then Playwright drives the real Electron app
npm run record:videos # build, then capture automated dark/light promo demos via scripts/record-videos.cjs
npm run package      # build + @electron/packager -> release/ (unsigned unless APPLE_SIGN_IDENTITY set)
```

- When running `npm test` from sandboxed/background subshells where `shell.test.cjs` opens PTYs, wrap in a detached session: `python3 -c "import subprocess, sys; sys.exit(subprocess.call(['npm', 'test'], start_new_session=True))"`.
- `scripts/package.mjs` checks optional `APPLE_SIGN_IDENTITY`, `APPLE_ID`, `APPLE_APP_SPECIFIC_PASSWORD`, and `APPLE_TEAM_ID` on macOS for hardened runtime signing + notarization; `.github/workflows/package-platforms.yml` automates native 3-OS release packaging (`macOS-arm64`, `Windows-x64`, `Linux-x64`) + `SHA256SUMS` on `v*` tags.

Single tests:

```sh
node --test test/agent.test.cjs
node --test --test-name-pattern="approval is bound" test/agent.test.cjs
npm run build && npx playwright test test/agent.e2e.cjs      # e2e loads dist/, so build first
```

- There is no linter, formatter, or type checker configured.
- E2E tests launch Electron with `BENJAMIN_TEST_DATA` pointing at a temp dir (overrides `userData`) and a local fake SSE model server; they never call a paid API. Set `BENJAMIN_EXECUTABLE` to run them against a packaged binary instead of `electron .`.
- Several `shell.test.cjs` tests spawn a real zsh and are skipped off macOS.
- From a VS Code-hosted terminal or agent, `ELECTRON_RUN_AS_NODE=1` is inherited and Electron fails to launch with `bad option: --remote-debugging-port=0`. Run e2e as `env -u ELECTRON_RUN_AS_NODE npx playwright test`.
- `node scripts/live-agent-smoke.cjs [delete|restore <backupId>]` runs the production agent engine against a real local Ollama endpoint (`http://127.0.0.1:11434/v1` must be the saved connection) on `examples/agent-playground`, with approvals typed on stdin (`approve` / `deny` / `stop`). Logs go to the ignored `.live-agent/`.

## Architecture

Two processes with a deliberately narrow boundary:

- **Main process (`electron/*.cjs`, CommonJS).** `main.cjs` is the only module (besides `preload.cjs`) that imports `electron`. It owns all state — PTY sessions, settings, the decrypted API key, conversation history, the selected workspace `folder`, and the single `activeRequest` — and registers every IPC channel through a `handle()` wrapper that rejects any sender other than the main frame of the bundled `dist/index.html`. Every handler validates and bounds its inputs.
- **Renderer (`src/`, ESM bundled by esbuild into `dist/`).** Sandboxed, context-isolated, CSP `connect-src 'none'` — it has no Node or network access and talks only through `window.benjamin`, defined in `preload.cjs`. `app.js` is one flat DOM-wiring module (no framework); `index.html` is static markup referenced by element IDs.

Adding a capability means touching three places: a `handle('ns:verb', …)` in `main.cjs`, the matching `invoke`/`listen` entry in `preload.cjs`, and the caller in `src/app.js`.

The other `electron/*.cjs` modules are Electron-free and take their dependencies as arguments (`fetchImpl`, `signal`, `audit`, `approve`, `backupDir`, …). That is what lets `npm test`, the in-app reliability checks, and the live smoke script all drive the same production code under plain Node. Keep them that way.

### Request flow

`chat:start` is the single entry point for both modes; only one request (or reliability check) runs at a time, each with an `AbortController` that `chat:stop`, timeouts, window reload, and quit all abort.

- **Chat:** `provider.cjs` `streamCompletion` parses SSE and streams tokens to the renderer over `chat:token`. A tool call arriving in Chat mode is an error.
- **Agent:** `agent.cjs` `runAgent` loops (12 model rounds, 32 actions). Each tool call goes `prepareTool` → optional approval → `executeTool` in `agent-tools.cjs`. `prepareTool` builds a plan with the before/after contents, a bounded line diff (`diff.cjs`, sent once with the `planned` event and the approval request, rendered by `diffView` in `src/app.js` with `textContent` only), and sets `plan.reason` when user approval is required; `executeTool` re-validates the path and refuses if the file no longer matches `plan.before`. Mutations write a backup snapshot first, which `restoreBackup` (Undo) only applies if the file still equals the agent's result.

### Invariants worth knowing before editing agent code

- **Model prose is never trusted as activity.** In Agent mode, streamed text is buffered (`onToken() {}`) and only the final answer is shown. `claimsPendingApproval` rejects final responses that narrate approvals or an "Agent activity" log, pushes a corrective system message, and gives up after three attempts. Progress shown to the user comes only from real tool events (`agent:event`).
- **Approvals and Authorized Scope are host-enforced.** `ApprovalGate` tokens are bound to run + action, one-shot, and expire on abort. `ScopeGate` (`electron/cyber-scope.cjs`) validates every network/web/TLS/DNS/port or network-scanner target against `scope.json` and checks resolved DNS addresses to block loopback/RFC1918/link-local/metadata SSRF and DNS rebinding unless that private IP/CIDR is explicitly in scope. `scan_secrets` and `redactSecrets` mask raw credential values before model serialization. External 10-CLI scanners (`electron/cyber-toolchain.cjs`, including `shirudo`) resolve only from verified directories outside the workspace, execute via `spawn` with `shell: false` and preset argument arrays, and always require approval. The auto-run shell command list (`AUTO_COMMANDS`) remains an exact-match allowlist executed via fixed binaries.
- **Shirudo static & TPM 2.0 guarantees (`electron/shirudo.cjs`).** Enforces the 10-rule Shirudo suite (`SHIRUDO-BPF-001..004`, `SHIRUDO-BEE-001..003`, `SHIRUDO-TPM-001..003`) across `.bpf.c`, `Beefile`, scripts/CI YAML, and offline evidence JSONs alongside `inspectShirudoStatus --check`. `isShirudoDraftPath` requires explicit **Approve once** before even creating/editing `Beefile` or `.bpf.c`/`.upatch.c` files, and `.shirudo` / `shirudo-keys` are blocked in `PROTECTED`. Cross-file reachability in `electron/cyber-analyzers.cjs` traces 1-hop/2-hop route→service→helper import graphs for taint classification, `electron/artex-defense.cjs` surfaces pre-deploy `ARTEX-EDGE-001..003` exposures (`auditCodePatterns`) and behavioral `ARTEX-BEHAV-001` machine-speed attack loops (`analyzeLogs`), and `electron/findings.cjs` preserves `ruleId` in SARIF v2.1.0 exports.
- **File tools are confined** to the workspace: no absolute paths, symlinks, hard links, binaries, files over 200 KB, or `PROTECTED` names (`.git`, `.env*`, `.shirudo`, `shirudo-keys`, keys, …). `find_files` and `search_text` walk the tree under the same refusals, match globs without regular expressions, and search literal text only, so a model-supplied pattern cannot stall the main process. Read and search results are sized to `RESULT_BUDGET` so they page or report truncation instead of hitting the 32 KB slice in `agent.cjs`. Approved shell commands are *not* sandboxed; they run via `/bin/sh -c` with a minimal environment, a time limit (30 s by default, up to 600 s via `timeout_seconds`, shown on the approval card), and process-group kill. Output keeps its head and tail instead of stopping the command; `toolContent` in `agent.cjs` shortens any oversized result structurally so status fields and the output tail always reach the model.
- **Only `PATH` comes from the user's shell.** `toolchain.cjs` `loginPath` runs the login shell (zsh/bash/fish, `-i -l -c`, own session, 5 s limit) in the workspace when it is chosen in `app:folder`, reads `PATH` between random markers, and keeps existing absolute directories outside the workspace so an auto-created file cannot shadow an approved command name. `main.cjs` passes the result as `commandPath` to `runAgent`; `''` means `DEFAULT_PATH`, which is what tests, reliability checks, and the auto-run `pwd`/`ls` use. Do not widen this to other variables.
- **Two histories exist.** The renderer's display history (`conversation.json`, user/assistant text only, sanitized by `cleanMessages`) is not what the agent model sees. Each agent run saves its real tool-call transcript to `agent-runs/<id>.context.json`; `history.cjs` `agentHistory` rebuilds model context from those records via the message's `agentRunId`, quotes anything without a record as inert "legacy" data, and truncates without splitting a tool call from its result.
- **Audit log → dashboard.** Every agent event is appended to `agent-runs/<id>.jsonl`. `reliability.cjs` summarizes those logs for the dashboard; `reliability-checks.cjs` runs `runAgent` with scripted `fetchImpl` replies in a temp workspace. New event `status` values need handling in `summarizeRun`.

### Terminals

- `shell.cjs` never edits user dotfiles. For zsh it generates shim startup files in `userData/shell/zsh`, points `ZDOTDIR` at them, sources the user's real files, then loads `shell/colors.zsh` and `shell/integration.zsh`. Those two files are copied out at runtime because the shell cannot read from `app.asar`.
- `integration.zsh` emits `OSC 777;Benjamin;<token>;S|P;…` markers (hex-encoded cwd/command/exit status) from `preexec`/`precmd`. `terminal-context.cjs` `TerminalContext` strips them from the PTY stream before it reaches xterm and tracks per-tab cwd, running state, and last/failed command output. Non-zsh shells get no tracking; features fall back to selected text.
- Terminal context reaches the model only as an explicit, user-reviewed snapshot attached to one send (16,000-char cap). Nothing is shared automatically.
- The **Benjamin** tab is not a PTY: `src/benjamin-terminal.mjs` implements a line editor on an xterm instance and mirrors the conversation. `terminalText` strips escape sequences so model/tool output can never act as terminal control codes or shell input. It is `.mjs` so the CommonJS unit test can `import()` it directly.

### Persistence

Everything lives in Electron's `userData` directory: `settings.json` (API key encrypted with `safeStorage`, never sent to the renderer; cleared when the base URL changes), `conversation.json`, `agent-runs/`, `agent-backups/`, `reliability-checks.json`, and `shell/zsh/`. JSON writes go through `writeJson` (temp file + rename, mode 0600).

## Conventions

- Code is written in a dense style: long single-line functions and object literals, few comments. Existing comments explain safety reasoning — preserve them.
- User-facing error strings are actionable and shown directly in toasts; the renderer strips Electron's `Error invoking remote method` prefix.
- Tool errors and results returned to the model name the fix (the relative path to use instead of an absolute one, the `hint` to retry with a larger `timeout_seconds`). A live trial with a small local model looped on a vague refusal until the step limit; keep refusals specific, without relaxing what is refused.
- The version string is duplicated in `package.json`, `electron/shell.cjs` (`TERM_PROGRAM_VERSION`), and `src/index.html`.
- Top-level `MacOS/`, `WindowsOS/`, and `LinuxOS/` folders hold OS-specific setup guides, 9-CLI Homebrew / 10-CLI Convergence manifests, and build wrappers pointing at the shared root source.
- `scripts/package.mjs` has an explicit `ignore` list (including `MacOS/`, `WindowsOS/`, `LinuxOS/`); new top-level directories that should not ship inside `app.asar` must be added there.
