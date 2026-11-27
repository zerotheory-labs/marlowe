const fs = require('node:fs/promises');
const { constants } = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const net = require('node:net');
const { spawn } = require('node:child_process');
const { randomUUID } = require('node:crypto');
const { DEFAULT_PATH } = require('./toolchain.cjs');
const { lineDiff } = require('./diff.cjs');
const { DEFAULT_SCOPE, checkTargetScopeSync } = require('./cyber-scope.cjs');
const {
  scanSecrets, auditCodePatterns, auditDependencies,
  inspectHttpSecurity, inspectTls, dnsRecon, parsePortList, probePorts,
  triageArtifact, extractIocs, analyzeLogs, reconcileWorkspaceFindings
} = require('./cyber-analyzers.cjs');
const { prepareScannerSpec, executeScannerRun } = require('./cyber-toolchain.cjs');
const { normalizeFinding, scanRevision } = require('./findings.cjs');
const { isShirudoDraftPath, inspectShirudoTarget, verifyShirudoAttestation } = require('./shirudo.cjs');

const MAX_FILE = 200000;
// Read and search results stay well under the 32 KB model-visible cap, so the
// model pages or narrows a request instead of receiving a silently cut result.
const RESULT_BUDGET = 24000;
const PROTECTED = /^(\.git|\.ssh|\.aws|\.gnupg|\.codex|\.shirudo|shirudo-keys|\.npmrc|\.netrc|\.pypirc|\.env(?:\..*)?|.*\.(?:pem|key))$/i;
const SKIPPED = new Set([
  'node_modules', '.venv', 'venv', '__pycache__',
  '.uv-cache', '.cache', '.pytest_cache', '.mypy_cache', '.ruff_cache',
  '.tox', '.nox', '.next', '.nuxt', '.turbo', '.parcel-cache'
]);
const DIRECTORY_TOOLS = new Set(['list_files', 'find_files', 'search_text', 'scan_secrets', 'audit_code_patterns']);
const COMMAND_HEAD = 6000, COMMAND_TAIL = 22000;
const schema = (name, description, properties, required) => ({ type: 'function', function: { name, description, parameters: { type: 'object', properties, required, additionalProperties: false } } });
const str = description => ({ type: 'string', description });
const int = description => ({ type: 'integer', description });
const num = description => ({ type: 'number', description });
const bool = description => ({ type: 'boolean', description });

const CORE_TOOLS = [
  schema('list_files', 'List one directory inside the chosen workspace. Symlinks and sensitive files cannot be opened.', { path: str('Relative directory path, or .') }, ['path']),
  schema('find_files', 'Find files by name anywhere under a workspace directory. Patterns support *, ?, ** and {a,b}; a pattern without / matches file names at any depth. Symlinks, sensitive files and dependency folders such as node_modules are skipped.', { pattern: str('Glob relative to path, such as *.test.cjs or src/**/*.js'), path: str('Relative directory to search, or .') }, ['pattern', 'path']),
  schema('search_text', 'Search file contents under a workspace directory for literal text (case-insensitive, not a regular expression). Returns matching lines with their paths and line numbers. Symlinks, sensitive files, binary files and dependency folders such as node_modules are skipped.', { query: str('Text to find on a single line'), path: str('Relative directory to search, or .'), glob: str('Optional: only search files matching this glob, such as *.js') }, ['query', 'path']),
  schema('read_file', 'Read a UTF-8 text file (up to 200 KB) inside the workspace. Long files are returned in pages: the result reports startLine, endLine and totalLines; pass start_line to read further.', { path: str('Workspace-relative path'), start_line: int('Optional: first line to return, counting from 1'), line_count: int('Optional: maximum number of lines to return') }, ['path']),
  schema('write_file', 'Create a UTF-8 file. Replacing an existing file requires user approval. Parent directory must exist.', { path: str('Workspace-relative path'), content: str('Complete file content') }, ['path', 'content']),
  schema('edit_file', 'Replace one exact occurrence in a file. Read it first. Removing text or large edits require approval. Backups are saved.', { path: str('Workspace-relative path'), old_text: str('Exact nonempty text occurring once'), new_text: str('Replacement text') }, ['path', 'old_text', 'new_text']),
  schema('delete_file', 'Delete one regular file after user approval. Directories cannot be deleted with this tool. A backup is saved.', { path: str('Workspace-relative path') }, ['path']),
  schema('run_command', 'Run a shell command in the chosen workspace. It is stopped after 30 seconds unless timeout_seconds allows longer (up to 600) for tests, builds or installs. Long output keeps its beginning and end. Only exact pwd/ls forms run automatically; other commands require approval. Commands are not OS-sandboxed.', { command: str('Exact shell command'), cwd: str('Workspace-relative working directory, or .'), timeout_seconds: int('Optional: time limit in seconds, from 1 to 600; the default is 30') }, ['command', 'cwd'])
];

const FINDING_PROPERTIES = {
  title: str('Concise finding title'),
  severity: str('Severity: critical, high, medium, low, or info'),
  category: str('Category: appsec, secrets, supply-chain, network, web, dfir, or config'),
  location: str('Workspace path:line or in-scope host/URL'),
  evidence: str('Verified tool evidence (code snippet, header, hash, or log sample)'),
  remediation: str('Concrete fix or mitigation steps'),
  cwe: str('Optional CWE ID, such as CWE-89'),
  mitre: str('Optional MITRE ATT&CK ID, such as T1190'),
  cvss: num('Optional CVSS score from 0.0 to 10.0')
};
const FINDING_REQUIRED = ['title', 'severity', 'category', 'location', 'evidence', 'remediation'];

const CYBER_TOOLS = [
  schema('scan_secrets', 'Scan workspace source and config files for hardcoded API keys, tokens, private keys, and high-entropy secrets. Secret values are automatically masked in results.', { path: str('Relative workspace directory to scan, or .') }, ['path']),
  schema('audit_code_patterns', 'Static security audit across workspace code and IaC configs for injection sinks, XSS, unsafe deserialization, weak crypto, disabled TLS verification, CORS, and container misconfigurations (mapped to CWE). Omit category to scan all rule categories in a single pass.', { path: str('Relative workspace directory to audit, or .'), category: str('Optional single-category filter (omit to audit all categories at once): injection, xss, deserialization, crypto, config, or iac') }, ['path']),
  schema('audit_dependencies', 'Inventory pinned packages across package-lock.json, package.json, pnpm-lock.yaml, requirements.txt, pyproject.toml, go.mod, and Cargo.lock, generate a CycloneDX SBOM summary, and optionally query OSV.dev for known CVE/GHSA vulnerabilities.', { path: str('Relative workspace directory or manifest file, or .'), query_osv: bool('Optional: query OSV.dev advisory database when allowed by scope settings (default true)') }, ['path']),
  schema('inspect_http_security', 'Inspect HTTP security headers (CSP, HSTS, X-Frame-Options, nosniff, CORS, server banners) and Set-Cookie flags on an Authorized Scope URL using a non-redirecting GET or HEAD request.', { url: str('Full http:// or https:// URL inside Authorized Scope'), method: str('Optional: GET or HEAD (default GET)') }, ['url']),
  schema('inspect_tls', 'Inspect TLS protocol version, cipher suite, certificate chain trust, SANs, and expiration on an Authorized Scope host or host:port.', { target: str('Hostname or host:port inside Authorized Scope, such as example.com:443') }, ['target']),
  schema('dns_recon', 'Query A, AAAA, CNAME, MX, NS, TXT, and DMARC records for an Authorized Scope domain and evaluate SPF/DMARC spoofing defenses.', { domain: str('Domain name inside Authorized Scope, such as example.com') }, ['domain']),
  schema('probe_ports', 'Run a bounded TCP port and service-banner check (up to 32 ports) against an Authorized Scope host or IP. Requires user approval.', { target: str('Hostname or IP address inside Authorized Scope'), ports: str('Optional comma-separated ports or small ranges (max 32 ports), e.g. "22,80,443,8000-8005"'), timeout_ms: int('Optional per-port timeout in milliseconds, from 300 to 5000 (default 2000)') }, ['target']),
  schema('triage_artifact', 'Forensic static triage of a workspace file or binary (up to 10 MB): computes SHA-256/SHA-1/MD5 hashes, byte Shannon entropy (packing/encryption indicator), ELF/Mach-O/PE/PDF/PCAP header metadata, and notable printable strings.', { path: str('Workspace-relative file path') }, ['path']),
  schema('extract_iocs', 'Extract and classify Indicators of Compromise (public/private IPs, domains, URLs, SHA-256/SHA-1/MD5 hashes, CVEs, and MITRE ATT&CK technique IDs) from a workspace file or log.', { path: str('Workspace-relative file path') }, ['path']),
  schema('analyze_logs', 'Analyze JSONL, HTTP access, or syslog/auth log files (up to 10 MB) for brute-force spikes, traversal/SQLi/XSS/JNDI/SSRF probes, scanner signatures, and top source IPs.', { path: str('Workspace-relative log file path'), filter: str('Optional case-insensitive substring filter') }, ['path']),
  schema('audit_shirudo_upatch', 'Audit Shirudo Beefiles, Plain BPF C (.bpf.c/.upatch.c) runtime upatches, and .bee/.upatch bundles for embedded keys, insecure registries, path traversal, unsafe BPF helpers, fmod_ret bounds, and selector/rodata invariants.', { path: str('Workspace-relative path to a Beefile, .bpf.c file, .bee package, or directory (e.g. ".")') }, ['path']),
  schema('verify_shirudo_attestation', 'Inspect a Shirudo TPM 2.0 attestation evidence JSON file in the workspace and verify it offline via policy checks and trusted shirudo CLI when installed.', { evidence_path: str('Workspace-relative path to the Shirudo TPM 2.0 attestation evidence JSON file'), nonce: str('Optional expected hex nonce (8-128 hex chars)'), ak_name: str('Optional expected attestation key (AK) name'), expected_pcr11: str('Optional expected PCR 11 measured boot digest (64 hex chars)'), expected_config_root: str('Optional expected active Shirudo config root hash') }, ['evidence_path']),
  schema('run_security_scanner', 'Execute an installed external security CLI (semgrep, trivy, gitleaks, osv-scanner, nmap, nuclei, or shirudo) using safe preset arguments without shell interpolation. Always requires user approval.', { scanner: str('Scanner ID: semgrep, trivy, gitleaks, osv-scanner, nmap, nuclei, or shirudo'), target: str('Workspace-relative path for local scanners, Authorized Scope host/URL for nmap/nuclei, or "." / upatch path for shirudo'), profile: str('Optional preset profile (e.g. auto, owasp-top-ten, secrets, fs-vuln, fs-misconfig, fs-all, dir-no-git, workspace, top-100-ports, service-version, misconfiguration, exposures, cves-safe, status, upatch-list, upatch-info)'), timeout_seconds: int('Optional time limit in seconds, from 10 to 600 (default 120)') }, ['scanner', 'target']),
  schema('record_finding', 'Record a single verified security vulnerability, misconfiguration, or incident finding into the workspace Findings Ledger (for UI review and SARIF/Markdown export). Only record findings where untrusted input or real secret/CVE exposure is verified.', FINDING_PROPERTIES, FINDING_REQUIRED),
  schema('record_findings', 'Record multiple verified security findings into the workspace Findings Ledger in a single step (up to 50 findings per call). Never record unverified sink candidates or static UI constants.', { findings: { type: 'array', description: 'Non-empty array of verified findings (1 to 50 items)', items: { type: 'object', properties: FINDING_PROPERTIES, required: FINDING_REQUIRED, additionalProperties: false } } }, ['findings']),
  schema('update_finding_status', 'Update an existing finding status in the workspace Findings Ledger (for example marking it mitigated after applying a code fix, or false-positive when inspection shows only static constants with no untrusted input).', { finding_id: str('UUID of the existing finding in the ledger'), status: str('New status: open, verified, mitigated, or false-positive') }, ['finding_id', 'status'])
];

const TOOLS = [...CORE_TOOLS, ...CYBER_TOOLS];

const APPSEC_CYBER_NAMES = new Set(['scan_secrets', 'audit_code_patterns', 'audit_dependencies', 'audit_shirudo_upatch', 'verify_shirudo_attestation', 'run_security_scanner', 'record_finding', 'record_findings', 'update_finding_status']);
const RECON_CYBER_NAMES = new Set(['inspect_http_security', 'inspect_tls', 'dns_recon', 'probe_ports', 'run_security_scanner', 'scan_secrets', 'record_finding', 'record_findings', 'update_finding_status']);
const DFIR_CYBER_NAMES = new Set(['triage_artifact', 'extract_iocs', 'analyze_logs', 'audit_shirudo_upatch', 'verify_shirudo_attestation', 'scan_secrets', 'audit_code_patterns', 'run_security_scanner', 'record_finding', 'record_findings', 'update_finding_status']);
const UPATCH_CYBER_NAMES = new Set(['audit_shirudo_upatch', 'verify_shirudo_attestation', 'scan_secrets', 'audit_code_patterns', 'audit_dependencies', 'triage_artifact', 'run_security_scanner', 'record_finding', 'record_findings', 'update_finding_status']);

const NETWORK_RECON_NAMES = new Set(['inspect_http_security', 'inspect_tls', 'dns_recon', 'probe_ports']);

function toolsForPlaybook(playbook = 'general', scope = null) {
  let selected = TOOLS;
  if (playbook === 'appsec') selected = [...CORE_TOOLS, ...CYBER_TOOLS.filter(t => APPSEC_CYBER_NAMES.has(t.function.name))];
  else if (playbook === 'recon') selected = [...CORE_TOOLS.filter(t => ['list_files', 'find_files', 'search_text', 'read_file', 'write_file'].includes(t.function.name)), ...CYBER_TOOLS.filter(t => RECON_CYBER_NAMES.has(t.function.name))];
  else if (playbook === 'dfir') selected = [...CORE_TOOLS, ...CYBER_TOOLS.filter(t => DFIR_CYBER_NAMES.has(t.function.name))];
  else if (playbook === 'upatch') selected = [...CORE_TOOLS, ...CYBER_TOOLS.filter(t => UPATCH_CYBER_NAMES.has(t.function.name))];
  if (scope && (!Array.isArray(scope.targets) || scope.targets.length === 0)) {
    return selected.filter(t => !NETWORK_RECON_NAMES.has(t.function.name));
  }
  return selected;
}

function validateObject(definition, args) {
  if (!definition || !args || Array.isArray(args) || typeof args !== 'object') throw new Error('Unknown tool or invalid arguments.');
  const clean = {};
  for (const [key, value] of Object.entries(args)) {
    if (!Object.hasOwn(definition.properties, key)) throw new Error('Invalid tool arguments.');
    // Some models send null or an empty string for an optional argument they omit.
    if (!definition.required.includes(key) && (value === null || value === '')) continue;
    const prop = definition.properties[key];
    const expectedType = prop.type;
    if (expectedType === 'integer') {
      const number = typeof value === 'string' && /^\d{1,9}$/.test(value) ? Number(value) : value;
      if (!Number.isSafeInteger(number) || number < 1 || number > 1e9) throw new Error(`${key} must be a positive whole number.`);
      clean[key] = number;
    } else if (expectedType === 'number') {
      const number = typeof value === 'string' && value.trim() ? Number(value) : value;
      if (typeof number !== 'number' || !Number.isFinite(number)) throw new Error(`${key} must be a valid number.`);
      clean[key] = number;
    } else if (expectedType === 'boolean') {
      if (typeof value === 'boolean') clean[key] = value;
      else if (value === 'true' || value === 'false') clean[key] = value === 'true';
      else throw new Error(`${key} must be true or false.`);
    } else if (expectedType === 'array') {
      if (!Array.isArray(value) || value.length < 1 || value.length > 50) throw new Error(`${key} must be an array of 1 to 50 items.`);
      clean[key] = value.map(item => validateObject(prop.items, item));
    } else {
      if (typeof value !== 'string') throw new Error('Invalid tool arguments.');
      if (value.length > MAX_FILE || value.includes('\0')) throw new Error('Tool argument is too large or contains a null byte.');
      clean[key] = value;
    }
  }
  if (definition.required.some(k => !Object.hasOwn(clean, k))) throw new Error('Invalid tool arguments.');
  return clean;
}

function checkArgs(name, args) {
  const definition = TOOLS.find(t => t.function.name === name)?.function.parameters;
  return validateObject(definition, args);
}
function contained(root, target) { const relative = path.relative(root, target); return relative === '' || (!relative.startsWith('..' + path.sep) && relative !== '..' && !path.isAbsolute(relative)); }
async function resolvePath(root, relative, { directory = false, missing = false, any = false } = {}) {
  if (typeof relative !== 'string' || !relative || relative.length > 4096 || relative.includes('\0')) throw new Error('Use a workspace-relative path such as "." or "src/app.js".');
  // Still refused, but a model that sends the workspace's absolute path is told the exact form to use.
  if (path.isAbsolute(relative)) throw new Error(contained(root, path.resolve(relative)) ? `Paths are relative to the workspace. Use ${JSON.stringify(path.relative(root, path.resolve(relative)) || '.')} instead of the absolute path.` : 'Absolute paths are not accepted. Use a workspace-relative path such as "." or "src/app.js".');
  const target = path.resolve(root, relative);
  if (!contained(root, target)) throw new Error('Path is outside the selected workspace.');
  if (target === root && !directory && !any) throw new Error('Choose a file, not the workspace root.');
  const segments = path.relative(root, target).split(path.sep).filter(Boolean);
  if (segments.some(part => PROTECTED.test(part))) throw new Error('Sensitive configuration and credential paths are not available to agent file tools.');
  let current = root;
  for (let i = 0; i < segments.length; i++) {
    current = path.join(current, segments[i]);
    let stat;
    try { stat = await fs.lstat(current); } catch (error) {
      if (error.code === 'ENOENT' && missing && i === segments.length - 1) return target;
      if (error.code === 'ENOENT') {
        throw new Error(`Path "${relative}" does not exist in the selected workspace. Do not retry this path; use find_files or list_files to locate existing files.`);
      }
      throw error;
    }
    if (stat.isSymbolicLink()) throw new Error('Symlinks are not followed by agent file tools.');
    if (i < segments.length - 1 && !stat.isDirectory()) throw new Error('Parent path is not a directory.');
    if (i === segments.length - 1 && !any && (directory ? !stat.isDirectory() : !stat.isFile())) throw new Error(directory ? 'Expected a directory.' : 'Expected a regular file.');
    if (i === segments.length - 1 && any && !stat.isDirectory() && !stat.isFile()) throw new Error('Expected a regular file or directory.');
    if (i === segments.length - 1 && stat.isFile() && stat.nlink > 1) throw new Error('Hard-linked files are not supported.');
  }
  return target;
}
async function readText(file, missing = false, onReadRevision) {
  let handle;
  try {
    handle = await fs.open(file, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
    const stat = await handle.stat({ bigint: true });
    if (!stat.isFile() || stat.nlink > 1n || stat.size > MAX_FILE) throw new Error('Use a regular text file of at most 200 KB, without hard links.');
    const data = await handle.readFile();
    if (data.includes(0)) throw new Error('Binary files are not supported.');
    const text = new TextDecoder('utf-8', { fatal: true }).decode(data);
    if (onReadRevision) {
      const revision = scanRevision(stat);
      if (scanRevision(await handle.stat({ bigint: true })) === revision) onReadRevision(revision);
    }
    return text;
  } catch (error) { if (missing && error.code === 'ENOENT') return null; throw error; }
  finally { await handle?.close(); }
}
function selectLines(text, start = 1, count = Infinity) {
  // Lines keep their terminators so a whole-file read returns the exact contents.
  const lines = text.match(/[^\n]*\n|[^\n]+$/g) || [];
  if (start > Math.max(1, lines.length)) throw new Error(`start_line is past the end of this ${lines.length}-line file.`);
  let content = '', used = 0, end = start - 1, note = '';
  while (end < lines.length && end - start + 1 < count) {
    const cost = JSON.stringify(lines[end]).length;
    if (used + cost > RESULT_BUDGET) break;
    content += lines[end++]; used += cost;
  }
  if (end < start && lines.length) {
    content = lines[start - 1].slice(0, RESULT_BUDGET);
    while (JSON.stringify(content).length > RESULT_BUDGET) content = content.slice(0, Math.floor(content.length * 0.8));
    end = start; note = `Line ${start} is too long to return in full; only its first ${content.length} characters are shown.`;
  } else if (end < lines.length && end - start + 1 < count) note = `Showing lines ${start}-${end} of ${lines.length}. Call read_file with start_line ${end + 1} to continue.`;
  return { content, startLine: start, endLine: end, totalLines: lines.length, ...(note ? { truncated: true, note } : {}) };
}
const relativePath = (from, to) => path.relative(from, to).split(path.sep).join('/');
// Globs are matched segment by segment without regular expressions, so a
// model-supplied pattern cannot stall the main process.
function segmentMatches(pattern, text) {
  let p = 0, t = 0, star = -1, mark = 0;
  while (t < text.length) {
    if (p < pattern.length && (pattern[p] === '?' || pattern[p] === text[t])) { p++; t++; }
    else if (p < pattern.length && pattern[p] === '*') { star = p++; mark = t; }
    else if (star !== -1) { p = star + 1; t = ++mark; }
    else return false;
  }
  while (pattern[p] === '*') p++;
  return p === pattern.length;
}
function expandBraces(pattern) {
  const group = /\{([^{}]*)\}/.exec(pattern);
  if (!group) return [pattern];
  const results = [];
  for (const option of group[1].split(',')) {
    results.push(...expandBraces(pattern.slice(0, group.index) + option + pattern.slice(group.index + group[0].length)));
    if (results.length > 32) throw new Error('Glob pattern has too many {a,b} alternatives.');
  }
  return results;
}
function globMatcher(pattern) {
  if (!pattern.trim() || pattern.length > 200) throw new Error('Glob pattern is empty or too long.');
  const alternatives = expandBraces(pattern.toLowerCase()).map(option => {
    const parts = option.split('/').filter(part => part && part !== '.');
    return option.includes('/') ? parts : ['**', ...parts];
  });
  return relative => {
    const names = relative.toLowerCase().split('/');
    return alternatives.some(parts => {
      let reachable = new Set([0]);
      for (const part of parts) {
        const next = new Set();
        for (const index of reachable) {
          if (part === '**') for (let i = index; i <= names.length; i++) next.add(i);
          else if (index < names.length && segmentMatches(part, names[index])) next.add(index + 1);
        }
        reachable = next;
      }
      return reachable.has(names.length);
    });
  };
}
// Search tools visit only what read_file could open: no symlinks, no protected
// names. Entry, time and size limits keep a huge workspace from stalling a run.
async function* walk(start, signal, state) {
  const pending = [start]; let visited = 0;
  while (pending.length) {
    signal.throwIfAborted();
    const directory = pending.pop();
    let entries;
    try { entries = await fs.readdir(directory, { withFileTypes: true }); } catch { continue; }
    entries.sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
    const folders = [];
    for (const entry of entries) {
      if (++visited > 20000 || Date.now() > state.deadline) { state.truncated = true; return; }
      if (entry.isSymbolicLink() || PROTECTED.test(entry.name)) continue;
      if (entry.isDirectory()) { if (!SKIPPED.has(entry.name)) folders.push(path.join(directory, entry.name)); }
      else if (entry.isFile()) yield path.join(directory, entry.name);
    }
    pending.push(...folders.reverse());
  }
}
async function findFiles(root, start, args, signal) {
  const wanted = globMatcher(args.pattern), state = { truncated: false, deadline: Date.now() + 10000 }, files = [];
  let size = 0;
  for await (const found of walk(start, signal, state)) {
    if (!wanted(relativePath(start, found))) continue;
    const name = relativePath(root, found);
    if (files.length >= 500 || (size += JSON.stringify(name).length + 1) > RESULT_BUDGET) { state.truncated = true; break; }
    files.push(name);
  }
  const summary = (files.length ? `Found ${files.length} file${files.length === 1 ? '' : 's'}.` : 'No files matched.') + (state.truncated ? ' The search stopped at a limit; narrow the pattern or path for complete results.' : '');
  return { path: args.path, pattern: args.pattern, files, truncated: state.truncated, summary };
}
async function searchText(root, start, args, signal) {
  const needle = args.query.toLowerCase(), wanted = args.glob ? globMatcher(args.glob) : null;
  const state = { truncated: false, deadline: Date.now() + 10000 }, matches = [], files = new Set();
  let size = 0, scanned = 0, characters = 0;
  search: for await (const found of walk(start, signal, state)) {
    if (wanted && !wanted(relativePath(start, found))) continue;
    signal.throwIfAborted();
    if (++scanned > 5000 || characters > 50_000_000) { state.truncated = true; break; }
    let text;
    // Files read_file would refuse (too large, binary, hard-linked) are skipped.
    try { text = await readText(found); } catch { continue; }
    characters += text.length;
    if (!text.toLowerCase().includes(needle)) continue;
    const lines = text.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].replace(/\r$/, ''), at = line.toLowerCase().indexOf(needle);
      if (at === -1) continue;
      const from = Math.max(0, Math.min(at - 80, line.length - 240));
      const match = { path: relativePath(root, found), line: i + 1, text: line.length > 240 ? line.slice(from, from + 240) : line.trim() };
      if (matches.length >= 200 || (size += JSON.stringify(match).length + 1) > RESULT_BUDGET) { state.truncated = true; break search; }
      matches.push(match); files.add(match.path);
    }
  }
  const summary = (matches.length ? `Found ${matches.length} matching line${matches.length === 1 ? '' : 's'} in ${files.size} file${files.size === 1 ? '' : 's'}.` : 'No matches.') + (state.truncated ? ' The search stopped at a limit; narrow the query, path or glob for complete results.' : '');
  return { path: args.path, query: args.query, matches, truncated: state.truncated, summary };
}
// Deliberately finite, not a blacklist. Anything else is reviewed in full.
const AUTO_COMMANDS = new Map([
  ['pwd', ['/bin/pwd', []]], ['ls', ['/bin/ls', []]],
  ['ls -l', ['/bin/ls', ['-l']]], ['ls -a', ['/bin/ls', ['-a']]], ['ls -la', ['/bin/ls', ['-la']]]
]);
function commandPolicy(command) { return process.platform !== 'win32' && AUTO_COMMANDS.has(command) ? 'automatic' : 'approval'; }
const duration = seconds => seconds >= 60 && seconds % 60 === 0 ? `${seconds / 60} minute${seconds === 60 ? '' : 's'}` : `${seconds} second${seconds === 1 ? '' : 's'}`;
function runCommand(command, cwd, signal, onOutput = () => {}, seconds = 30, commandPath = '') {
  signal.throwIfAborted();
  const auto = commandPolicy(command) === 'automatic';
  const [executable, args] = auto ? AUTO_COMMANDS.get(command) : process.platform === 'win32' ? ['cmd.exe', ['/d', '/s', '/c', command]] : ['/bin/sh', ['-c', command]];
  return new Promise((resolve, reject) => {
    let head = '', tail = '', omitted = 0, live = '', skipped = false, stopped = '', hint = '', timer, killRetry, throttle;
    const child = spawn(executable, args, {
      cwd, detached: process.platform !== 'win32', stdio: ['ignore', 'pipe', 'pipe'],
      env: { PATH: process.platform === 'win32' ? process.env.PATH : auto ? DEFAULT_PATH : commandPath || DEFAULT_PATH, HOME: os.homedir(), TMPDIR: os.tmpdir(), LANG: 'en_US.UTF-8', NO_COLOR: '1', ...(process.platform === 'win32' ? { SystemRoot: process.env.SystemRoot } : {}) }
    });
    function kill() {
      if (!child.pid) return;
      try { if (process.platform === 'win32') child.kill('SIGKILL'); else process.kill(-child.pid, 'SIGKILL'); } catch {}
    }
    function stop(reason) {
      stopped = reason; kill();
      // A child can be in the middle of fork when its shell is signalled.
      // Retry until inherited pipes close so those children are stopped too.
      if (!killRetry) killRetry = setInterval(kill, 25);
    }
    function abort() { stop('Stopped by user'); }
    function emit() {
      if (!live) return;
      const text = (skipped ? '\n[… live output skipped …]\n' : '') + live; live = ''; skipped = false; onOutput(text);
    }
    function consume(chunk) {
      // Keep the start and the end; a failure is usually reported last. A
      // noisy command is never stopped for its output, only by its time limit.
      const text = chunk.toString(), start = text.slice(0, COMMAND_HEAD - head.length);
      head += start; tail += text.slice(start.length);
      if (tail.length > COMMAND_TAIL) { omitted += tail.length - COMMAND_TAIL; tail = tail.slice(-COMMAND_TAIL); }
      // Live output is batched so a flood cannot swamp the interface.
      live += text;
      if (live.length > 16000) { live = live.slice(-16000); skipped = true; }
      if (!throttle) { emit(); throttle = setTimeout(() => { throttle = null; emit(); }, 100); }
    }
    child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
    child.stdout.on('data', consume); child.stderr.on('data', consume);
    signal.addEventListener('abort', abort, { once: true });
    // The hint is for the model: without it a small model reports the timeout instead of asking for longer.
    timer = setTimeout(() => { if (seconds < 600) hint = 'If this command needs longer, run it again with a larger timeout_seconds (up to 600).'; stop(`Command timed out after ${duration(seconds)}`); }, seconds * 1000);
    const cleanup = () => { clearTimeout(timer); clearTimeout(throttle); clearInterval(killRetry); signal.removeEventListener('abort', abort); emit(); };
    child.once('exit', () => { if (!stopped) kill(); });
    child.once('error', error => { cleanup(); reject(error); });
    child.once('close', (code, exitSignal) => { kill(); cleanup(); resolve({ exitCode: code, signal: exitSignal, output: omitted ? `${head}\n[… ${omitted} characters of output omitted …]\n${tail}` : head + tail, ...(omitted ? { truncated: true } : {}), ...(stopped ? { stopped } : {}), ...(hint ? { hint } : {}) }); });
    if (signal.aborted) abort();
  });
}

async function prepareTool(root, name, args, options = {}) {
  args = checkArgs(name, args);
  const scope = options.scope || DEFAULT_SCOPE;
  if (name === 'run_command') {
    if (!args.command.trim() || args.command.length > 8000) throw new Error('Command is empty or too long.');
    const cwd = await resolvePath(root, args.cwd, { directory: true }), seconds = args.timeout_seconds ?? 30;
    if (seconds > 600) throw new Error('timeout_seconds can be at most 600 (ten minutes).');
    const reason = commandPolicy(args.command) === 'approval' ? 'This shell command is not in the verified read-only set. It may modify or delete files, run project scripts, or access the network and paths outside this workspace.' : '';
    return { name, args, cwd, seconds, reason, title: args.command, preview: `$ ${args.command}\n\nWorking directory: ${cwd}\nTime limit: ${duration(seconds)}` };
  }
  if (name === 'inspect_http_security') {
    const method = (args.method || 'GET').toUpperCase();
    if (!['GET', 'HEAD'].includes(method)) throw new Error('method must be GET or HEAD.');
    const { endpoint } = checkTargetScopeSync(args.url, scope, { requireUrl: true });
    return { name, args: { ...args, method }, title: `${method} ${endpoint.url}`, reason: '', preview: `HTTP security header & cookie inspection\nTarget: ${endpoint.url}` };
  }
  if (name === 'inspect_tls') {
    const { endpoint } = checkTargetScopeSync(args.target, scope, { defaultPort: 443 });
    return { name, args, title: `${endpoint.host}:${endpoint.port}`, reason: '', preview: `TLS handshake & certificate inspection\nTarget: ${endpoint.host}:${endpoint.port}` };
  }
  if (name === 'dns_recon') {
    const { endpoint } = checkTargetScopeSync(args.domain, scope);
    if (net.isIP(endpoint.host)) throw new Error('dns_recon requires a domain name rather than an IP address.');
    return { name, args, title: endpoint.host, reason: '', preview: `DNS records & SPF/DMARC posture lookup\nDomain: ${endpoint.host}` };
  }
  if (name === 'probe_ports') {
    const portList = parsePortList(args.ports);
    const { endpoint } = checkTargetScopeSync(args.target, scope);
    const timeoutMs = args.timeout_ms ?? 2000;
    if (timeoutMs < 300 || timeoutMs > 5000) throw new Error('timeout_ms must be between 300 and 5000.');
    return {
      name, args, title: `${endpoint.host} (${portList.length} ports)`,
      reason: 'Active TCP port and service-banner probe against an authorized target.',
      preview: `Target: ${endpoint.host}\nPorts (${portList.length}): ${portList.join(', ')}\nPer-port timeout: ${timeoutMs} ms`
    };
  }
  if (name === 'run_security_scanner') {
    const seconds = args.timeout_seconds ?? 120;
    if (seconds < 10 || seconds > 600) throw new Error('timeout_seconds must be between 10 and 600.');
    let scannerArgs = args;
    const prelim = prepareScannerSpec(args, { scope });
    if (!prelim.isNetwork) {
      const targetPath = await resolvePath(root, args.target, { any: true });
      const cleanRel = relativePath(root, targetPath) || '.';
      scannerArgs = { ...args, target: cleanRel };
    }
    const scannerPlan = prepareScannerSpec(scannerArgs, { scope });
    return {
      name, args: scannerArgs, seconds, scannerPlan,
      title: `${scannerPlan.spec.id} (${scannerPlan.profile}) → ${scannerPlan.targetValue}`,
      reason: `External security CLI (${scannerPlan.spec.label}) runs via fixed argument array without OS sandboxing.`,
      preview: `Binary: ${scannerPlan.spec.binary}\nArguments: ${JSON.stringify(scannerPlan.argv)}\nWorking directory: ${root}\nTime limit: ${duration(seconds)}`
    };
  }
  if (name === 'record_finding') {
    const normalized = normalizeFinding(args);
    return {
      name, args, normalized,
      title: `[${normalized.severity.toUpperCase()}] ${normalized.title}`,
      reason: '',
      preview: `Severity: ${normalized.severity.toUpperCase()}${normalized.cwe ? ' · ' + normalized.cwe : ''}${normalized.mitre ? ' · ' + normalized.mitre : ''}\nLocation: ${normalized.location}\n\nEvidence:\n${normalized.evidence}\n\nRemediation:\n${normalized.remediation}`
    };
  }
  if (name === 'record_findings') {
    const items = args.findings.map(item => normalizeFinding(item));
    return {
      name, args, items,
      title: `${items.length} verified finding${items.length === 1 ? '' : 's'}`,
      reason: '',
      preview: items.map(f => `[${f.severity.toUpperCase()}${f.cwe ? ' · ' + f.cwe : ''}] ${f.title} — ${f.location}`).join('\n')
    };
  }
  if (name === 'update_finding_status') {
    const status = args.status.trim().toLowerCase();
    if (!['open', 'verified', 'mitigated', 'false-positive'].includes(status)) {
      throw new Error('status must be open, verified, mitigated, or false-positive.');
    }
    if (!/^[a-f0-9-]{36}$/i.test(args.finding_id.trim())) {
      throw new Error('finding_id must be a valid finding UUID.');
    }
    return {
      name,
      args: { finding_id: args.finding_id.trim(), status },
      title: `${args.finding_id.slice(0, 8)}… → ${status}`,
      reason: '',
      preview: `Finding ID: ${args.finding_id}\nNew status: ${status}`
    };
  }
  if (name === 'audit_dependencies') {
    const file = await resolvePath(root, args.path, { any: true });
    const stat = await fs.lstat(file);
    return { name, args, file, isDirectory: stat.isDirectory(), title: args.path, reason: '' };
  }
  if (name === 'audit_shirudo_upatch') {
    const upathTarget = await resolvePath(root, args.path, { any: true });
    return { name, args, file: upathTarget, title: args.path, reason: '' };
  }
  if (name === 'verify_shirudo_attestation') {
    const cleanNonce = args.nonce ? String(args.nonce).trim() : '';
    const cleanAk = args.ak_name ? String(args.ak_name).trim() : '';
    const cleanPcr11 = args.expected_pcr11 ? String(args.expected_pcr11).trim() : '';
    const cleanConfigRoot = args.expected_config_root ? String(args.expected_config_root).trim() : '';
    if (cleanNonce && !/^[0-9a-fA-F]{8,128}$/.test(cleanNonce)) throw new Error('Invalid nonce: expected 8-128 hex characters.');
    if (cleanAk && !/^[0-9a-zA-Z:._-]{4,128}$/.test(cleanAk)) throw new Error('Invalid ak_name: expected 4-128 alphanumeric, :, ., _, or - characters.');
    const evFile = await resolvePath(root, args.evidence_path);
    return { name, args: { ...args, nonce: cleanNonce, ak_name: cleanAk, expected_pcr11: cleanPcr11, expected_config_root: cleanConfigRoot }, file: evFile, title: args.evidence_path, reason: '' };
  }
  const file = await resolvePath(root, args.path, { directory: DIRECTORY_TOOLS.has(name), missing: name === 'write_file' });
  if (name === 'scan_secrets') return { name, args, file, title: `secrets in ${args.path}`, reason: '' };
  if (name === 'audit_code_patterns') {
    if (args.category && !['injection', 'xss', 'deserialization', 'crypto', 'config', 'iac'].includes(args.category.trim().toLowerCase())) {
      throw new Error('category must be injection, xss, deserialization, crypto, config, or iac.');
    }
    return { name, args, file, title: `${args.category || 'all rules'} in ${args.path}`, reason: '' };
  }
  if (name === 'triage_artifact' || name === 'extract_iocs' || name === 'analyze_logs') {
    return { name, args, file, title: args.path, reason: '' };
  }
  if (name === 'find_files') { globMatcher(args.pattern); return { name, args, file, title: `${args.pattern} in ${args.path}`, reason: '' }; }
  if (name === 'search_text') {
    if (!args.query.trim() || args.query.length > 500 || /[\r\n]/.test(args.query)) throw new Error('Search for a short piece of text on a single line.');
    if (args.glob) globMatcher(args.glob);
    return { name, args, file, title: `${JSON.stringify(args.query)} in ${args.path}${args.glob ? ` (${args.glob})` : ''}`, reason: '' };
  }
  if (name === 'list_files' || name === 'read_file') return { name, args, file, title: args.path, reason: '' };
  const before = await readText(file, name === 'write_file');
  let after, reason = '';
  if (name === 'write_file') { after = args.content; if (before !== null && before !== after) reason = 'Replace the full contents of an existing file.'; }
  if (name === 'delete_file') { after = null; reason = 'Delete this file from the workspace.'; }
  if (name === 'edit_file') {
    if (!args.old_text || !before.includes(args.old_text)) throw new Error('Exact old_text was not found. Read the file again.');
    if (before.indexOf(args.old_text) !== before.lastIndexOf(args.old_text)) throw new Error('old_text matches more than once. Use a unique surrounding section.');
    after = before.replace(args.old_text, () => args.new_text);
    if (args.new_text.length < args.old_text.length || !args.new_text.trim() || args.old_text.split('\n').length > 100 || (args.old_text === before && !args.new_text.includes(args.old_text))) reason = 'This edit removes text or replaces a large section.';
  }
  if (!reason && (name === 'write_file' || name === 'edit_file') && isShirudoDraftPath(args.path)) {
    reason = 'Creating or modifying a Shirudo Beefile or kernel/runtime upatch requires explicit operator review before building or signing.';
  }
  if (after !== null && Buffer.byteLength(after) > MAX_FILE) throw new Error('Edited file exceeds 200 KB.');
  return { name, args, file, before, after, reason, title: args.path, diff: lineDiff(before, after), preview: `--- Before: ${args.path}\n${before ?? '(new file)'}\n\n+++ After: ${args.path}\n${after ?? '(deleted)'}` };
}

async function runTextScan(root, plan, { signal, scope = DEFAULT_SCOPE, fetchImpl, findingsStore }) {
  const revisions = new Map();
  const completed = new Map();
  const readForScan = file => readText(file, false, version => revisions.set(relativePath(root, file), version));
  const access = { relativePath, walk, readText };
  if (findingsStore?.recordScans) {
    access.readText = readForScan;
    access.onFileScanned = rel => {
      if (revisions.has(rel)) completed.set(rel, revisions.get(rel));
    };
  }
  let result;
  if (plan.name === 'audit_dependencies') {
    const file = await resolvePath(root, plan.args.path, { any: true });
    result = await auditDependencies(root, file, {
      ...access, isDirectory: (await fs.lstat(file)).isDirectory(), queryOsv: plan.args.query_osv !== false, scope, fetchImpl
    }, signal);
  } else {
    const dir = await resolvePath(root, plan.args.path, { directory: true });
    result = plan.name === 'scan_secrets'
      ? await scanSecrets(root, dir, access, signal)
      : await auditCodePatterns(root, dir, { ...access, category: plan.args.category }, signal);
  }
  if (completed.size) await findingsStore.recordScans(root, plan.name, completed);
  return result;
}

// External scanners and artifact tools name their inspected files in the result.
// A directory target alone is never evidence that every descendant was scanned.
async function recordReportedFiles(root, target, scanner, paths, startedAt, store) {
  if (!store?.recordScans || !paths.length) return;
  const revisions = new Map();
  for (const reported of new Set(paths)) {
    if (typeof reported !== 'string' || !reported) continue;
    let full = path.resolve(root, reported);
    // Trivy filesystem reports name targets relative to the directory it inspected.
    if (scanner === 'trivy' && !path.isAbsolute(reported) && !contained(target, full)) full = path.resolve(target, reported);
    if (!contained(target, full)) continue;
    const rel = relativePath(root, full);
    try {
      const safe = await resolvePath(root, rel);
      const stat = await fs.lstat(safe, { bigint: true });
      if (stat.isFile() && stat.nlink === 1n && stat.ctimeNs < startedAt && stat.mtimeNs < startedAt) {
        revisions.set(rel, scanRevision(stat));
      }
    } catch { /* Deleted, restricted or replaced while the scanner was running. */ }
  }
  if (revisions.size) await store.recordScans(root, scanner, revisions);
}

async function executeTool(root, plan, context = {}) {
  const startedAt = BigInt(Date.now()) * 1_000_000n;
  const { signal, backupDir, onOutput, commandPath, scope = DEFAULT_SCOPE, findingsStore, onFinding, playbook, runId, fetchImpl, dnsLookup, dnsResolver, tlsConnect, netConnect, spawnImpl, execFileImpl } = context;
  signal.throwIfAborted();
  if (plan.name === 'run_command') {
    await resolvePath(root, plan.args.cwd, { directory: true });
    return runCommand(plan.args.command, plan.cwd, signal, onOutput, plan.seconds, commandPath);
  }
  if (plan.name === 'inspect_http_security') {
    return inspectHttpSecurity(plan.args.url, { method: plan.args.method, scope, fetchImpl, dnsLookup }, signal);
  }
  if (plan.name === 'inspect_tls') {
    return inspectTls(plan.args.target, { scope, dnsLookup, tlsConnect }, signal);
  }
  if (plan.name === 'dns_recon') {
    return dnsRecon(plan.args.domain, { scope, dnsLookup, dnsResolver }, signal);
  }
  if (plan.name === 'probe_ports') {
    return probePorts(plan.args.target, { ports: plan.args.ports, timeoutMs: plan.args.timeout_ms, scope, dnsLookup, netConnect }, signal);
  }
  if (plan.name === 'run_security_scanner') {
    const target = plan.scannerPlan.isNetwork ? null : await resolvePath(root, plan.args.target, { any: true });
    return executeScannerRun(plan, { root, scope, commandPath, signal, onOutput, dnsLookup, spawnImpl,
      onScannedFiles: target && findingsStore
        ? paths => recordReportedFiles(root, target, plan.scannerPlan.spec.id, paths, startedAt, findingsStore)
        : undefined });
  }
  if (plan.name === 'record_finding') {
    if (!findingsStore) return { recorded: true, finding: plan.normalized, summary: `Recorded ${plan.normalized.severity.toUpperCase()} finding: ${plan.normalized.title}.` };
    const saved = await findingsStore.record(root, plan.args, { playbook, runId });
    await onFinding?.(saved.finding);
    return {
      recorded: true,
      deduplicated: saved.deduplicated,
      findingId: saved.finding.id,
      severity: saved.finding.severity,
      totalWorkspaceFindings: saved.total,
      summary: `${saved.deduplicated ? 'Updated' : 'Recorded'} [${saved.finding.severity.toUpperCase()}] finding "${saved.finding.title}" at ${saved.finding.location} (${saved.total} total in ledger).`
    };
  }
  if (plan.name === 'record_findings') {
    if (!findingsStore) {
      return {
        recorded: true,
        recordedCount: plan.items.length,
        findings: plan.items.map(f => ({ severity: f.severity, title: f.title, location: f.location, cwe: f.cwe })),
        summary: `Recorded ${plan.items.length} verified finding${plan.items.length === 1 ? '' : 's'}.`
      };
    }
    let created = 0, updated = 0, total = 0;
    const recordedItems = [];
    for (const rawItem of plan.args.findings) {
      const saved = await findingsStore.record(root, rawItem, { playbook, runId });
      if (saved.deduplicated) updated++; else created++;
      total = saved.total;
      recordedItems.push({ findingId: saved.finding.id, severity: saved.finding.severity, title: saved.finding.title, location: saved.finding.location, cwe: saved.finding.cwe });
    }
    await onFinding?.(recordedItems.at(-1));
    return {
      recorded: true,
      recordedCount: recordedItems.length,
      created,
      updated,
      totalWorkspaceFindings: total,
      findings: recordedItems,
      summary: `Recorded ${recordedItems.length} finding${recordedItems.length === 1 ? '' : 's'} (${created} new, ${updated} updated; ${total} total in ledger).`
    };
  }
  if (plan.name === 'update_finding_status') {
    if (!findingsStore) return { updated: true, findingId: plan.args.finding_id, status: plan.args.status, summary: `Marked finding ${plan.args.finding_id} as ${plan.args.status}.` };
    const updatedList = await findingsStore.update(root, plan.args.finding_id, { status: plan.args.status });
    await onFinding?.(updatedList.find(f => f.id === plan.args.finding_id) || null);
    return {
      updated: true,
      findingId: plan.args.finding_id,
      status: plan.args.status,
      summary: `Updated finding ${plan.args.finding_id.slice(0, 8)}… status to "${plan.args.status}".`
    };
  }
  if (plan.name === 'audit_shirudo_upatch') {
    const result = await inspectShirudoTarget(root, plan.args.path, signal);
    await recordReportedFiles(root, path.resolve(root, plan.args.path), plan.name, result.inspectedFiles.map(f => f.path), startedAt, findingsStore);
    return result;
  }
  if (plan.name === 'verify_shirudo_attestation') {
    return verifyShirudoAttestation({
      root,
      evidencePath: plan.args.evidence_path,
      nonce: plan.args.nonce || '',
      akName: plan.args.ak_name || '',
      expectedPcr11: plan.args.expected_pcr11 || '',
      expectedConfigRoot: plan.args.expected_config_root || '',
      commandPath,
      ...(execFileImpl ? { execFileImpl } : {})
    });
  }
  if (['scan_secrets', 'audit_code_patterns', 'audit_dependencies'].includes(plan.name)) return runTextScan(root, plan, context);
  const file = await resolvePath(root, plan.args.path, { directory: DIRECTORY_TOOLS.has(plan.name), missing: plan.name === 'write_file' });
  if (['triage_artifact', 'extract_iocs', 'analyze_logs'].includes(plan.name)) {
    const rel = relativePath(root, file);
    const inspect = { triage_artifact: triageArtifact, extract_iocs: extractIocs, analyze_logs: analyzeLogs }[plan.name];
    const result = plan.name === 'analyze_logs' ? await inspect(file, rel, { filter: plan.args.filter }, signal) : await inspect(file, rel, signal);
    await recordReportedFiles(root, file, plan.name, [rel], startedAt, findingsStore);
    return result;
  }
  if (plan.name === 'read_file') return { path: plan.args.path, ...selectLines(await readText(file), plan.args.start_line, plan.args.line_count) };
  if (plan.name === 'find_files') return findFiles(root, file, plan.args, signal);
  if (plan.name === 'search_text') return searchText(root, file, plan.args, signal);
  if (plan.name === 'list_files') {
    const entries = await fs.readdir(file, { withFileTypes: true });
    return { path: plan.args.path, entries: entries.slice(0, 500).map(e => ({ name: e.name, type: e.isSymbolicLink() ? 'symlink' : e.isDirectory() ? 'directory' : 'file', restricted: PROTECTED.test(e.name) })), truncated: entries.length > 500 };
  }
  if (await readText(file, true) !== plan.before) throw new Error('File changed after it was reviewed. Read it again and request a new change.');
  const backupId = randomUUID();
  await fs.mkdir(backupDir, { recursive: true, mode: 0o700 });
  const snapshot = { root, path: plan.args.path, before: plan.before, after: plan.after, mode: plan.before === null ? 0o644 : (await fs.stat(file)).mode & 0o777 };
  await fs.writeFile(path.join(backupDir, `${backupId}.json`), JSON.stringify(snapshot), { mode: 0o600, flag: 'wx' });
  signal.throwIfAborted();
  // Recheck after asynchronous backup I/O, before changing anything.
  await resolvePath(root, plan.args.path, { missing: plan.name === 'write_file' });
  if (await readText(file, true) !== plan.before) throw new Error('File changed before execution. No change was applied.');
  signal.throwIfAborted();
  if (plan.after === null) await fs.unlink(file);
  else if (plan.before === null) await fs.writeFile(file, plan.after, { flag: 'wx', mode: 0o644 });
  else {
    // Replace atomically, preserving permissions. Never truncate in place.
    const stat = await fs.stat(file);
    const temp = path.join(path.dirname(file), `.benjamin-${randomUUID()}.tmp`);
    try { await fs.writeFile(temp, plan.after, { flag: 'wx', mode: stat.mode & 0o777 }); signal.throwIfAborted(); await fs.rename(temp, file); }
    finally { await fs.unlink(temp).catch(() => {}); }
  }
  let autoMitigated = 0;
  if (findingsStore) {
    const rec = await reconcileWorkspaceFindings(root, findingsStore).catch(() => ({ mitigatedCount: 0 }));
    autoMitigated = rec.mitigatedCount || 0;
    if (autoMitigated > 0) await onFinding?.(null);
  }
  return {
    path: plan.args.path,
    operation: plan.name,
    backupId,
    ...(autoMitigated > 0 ? { autoMitigatedFindings: autoMitigated } : {}),
    summary: plan.after === null ? 'Deleted file; backup saved.' : plan.before === null ? 'Created file.' : `Updated file; original backed up.${autoMitigated > 0 ? ` Auto-marked ${autoMitigated} remediated finding(s) as mitigated.` : ''}`
  };
}

async function restoreBackup(backupDir, id) {
  if (!/^[a-f0-9-]{36}$/.test(id)) throw new Error('Invalid backup ID.');
  const saved = JSON.parse(await fs.readFile(path.join(backupDir, `${id}.json`), 'utf8'));
  const file = await resolvePath(saved.root, saved.path, { missing: true });
  if (await readText(file, true) !== saved.after) throw new Error('The file has changed since this action. Restore was refused to protect newer edits.');
  if (saved.before === null) await fs.unlink(file);
  else if (saved.after === null) await fs.writeFile(file, saved.before, { flag: 'wx', mode: saved.mode ?? 0o644 });
  else {
    const stat = await fs.stat(file), temp = path.join(path.dirname(file), `.benjamin-${randomUUID()}.tmp`);
    try { await fs.writeFile(temp, saved.before, { flag: 'wx', mode: stat.mode & 0o777 }); await fs.rename(temp, file); }
    finally { await fs.unlink(temp).catch(() => {}); }
  }
  return { path: saved.path, restored: true };
}

module.exports = { TOOLS, CORE_TOOLS, CYBER_TOOLS, toolsForPlaybook, resolvePath, prepareTool, executeTool, restoreBackup, commandPolicy, runCommand };
