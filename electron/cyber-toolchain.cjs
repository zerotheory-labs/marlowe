const fs = require('node:fs/promises');
const { constants } = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { execFile, spawn } = require('node:child_process');
const { promisify } = require('node:util');
const { DEFAULT_PATH } = require('./toolchain.cjs');
const { checkTargetScopeSync, assertTargetInScope, redactSecrets } = require('./cyber-scope.cjs');

const execFileAsync = promisify(execFile);

const TOOL_CATALOG = [
  { id: 'semgrep', binary: 'semgrep', label: 'Semgrep', category: 'SAST / Code Audit', versionArgs: ['--version'], installHint: 'brew install semgrep', runnable: true, profiles: ['auto', 'owasp-top-ten', 'secrets'] },
  { id: 'trivy', binary: 'trivy', label: 'Trivy', category: 'Vuln / IaC / Config', versionArgs: ['--version'], installHint: 'brew install trivy', runnable: true, profiles: ['fs-vuln', 'fs-misconfig', 'fs-all'] },
  { id: 'gitleaks', binary: 'gitleaks', label: 'Gitleaks', category: 'Secret Detection', versionArgs: ['version'], installHint: 'brew install gitleaks', runnable: true, profiles: ['dir-no-git'] },
  { id: 'osv-scanner', binary: 'osv-scanner', label: 'OSV-Scanner', category: 'Supply Chain CVEs', versionArgs: ['--version'], installHint: 'brew install osv-scanner', runnable: true, profiles: ['workspace'] },
  { id: 'nmap', binary: 'nmap', label: 'Nmap', category: 'Scope-Gated Network', versionArgs: ['--version'], installHint: 'brew install nmap', runnable: true, network: true, profiles: ['top-100-ports', 'service-version'] },
  { id: 'nuclei', binary: 'nuclei', label: 'Nuclei', category: 'Scope-Gated Web/Template', versionArgs: ['-version'], installHint: 'brew install nuclei', runnable: true, network: true, profiles: ['misconfiguration', 'exposures', 'cves-safe'] },
  { id: 'tshark', binary: 'tshark', label: 'TShark (Wireshark CLI)', category: 'Packet / PCAP Forensics', versionArgs: ['--version'], installHint: 'brew install wireshark', runnable: false, profiles: [] },
  { id: 'radare2', binary: 'radare2', label: 'Radare2', category: 'Binary Reverse Engineering', versionArgs: ['-v'], installHint: 'brew install radare2', runnable: false, profiles: [] },
  { id: 'otool', binary: 'otool', label: 'otool (macOS Mach-O)', category: 'Binary Inspection', versionArgs: ['--version'], installHint: 'xcode-select --install', runnable: false, profiles: [] }
];

async function safeSearchDirs(commandPath = '', root = '') {
  const raw = (commandPath || DEFAULT_PATH).split(':').filter(Boolean);
  const dirs = [];
  const realRoot = root ? await fs.realpath(root).catch(() => root) : '';
  for (const dir of raw.slice(0, 200)) {
    if (!path.isAbsolute(dir) || dirs.includes(dir)) continue;
    try {
      const real = await fs.realpath(dir);
      if (realRoot && (real === realRoot || real.startsWith(realRoot + path.sep))) continue;
      if ((await fs.stat(real)).isDirectory()) dirs.push(real);
    } catch { /* Ignore missing PATH entries. */ }
  }
  return dirs;
}

async function resolveToolBinary(binaryName, commandPath = '', root = '') {
  const dirs = await safeSearchDirs(commandPath, root);
  for (const dir of dirs) {
    const candidate = path.join(dir, binaryName);
    try {
      await fs.access(candidate, constants.X_OK);
      const stat = await fs.stat(candidate);
      if (stat.isFile()) return candidate;
    } catch { /* Continue searching PATH. */ }
  }
  return null;
}

async function detectSecurityTools(commandPath = '', { root = '', execFileImpl = execFileAsync } = {}) {
  const dirs = await safeSearchDirs(commandPath, root);
  const tools = await Promise.all(TOOL_CATALOG.map(async spec => {
    let binaryPath = null;
    for (const dir of dirs) {
      const candidate = path.join(dir, spec.binary);
      try {
        await fs.access(candidate, constants.X_OK);
        if ((await fs.stat(candidate)).isFile()) { binaryPath = candidate; break; }
      } catch {}
    }
    if (!binaryPath) {
      return { id: spec.id, label: spec.label, category: spec.category, available: false, runnable: spec.runnable, profiles: spec.profiles, binaryPath: '', version: '', installHint: spec.installHint };
    }
    let version = 'installed';
    try {
      const { stdout = '', stderr = '' } = await execFileImpl(binaryPath, spec.versionArgs, {
        timeout: 2500,
        env: { PATH: dirs.join(':') || DEFAULT_PATH, HOME: os.homedir(), LANG: 'en_US.UTF-8', NO_COLOR: '1' }
      });
      const firstLine = (stdout || stderr).split(/\r?\n/).map(s => s.trim()).find(Boolean);
      if (firstLine) version = firstLine.slice(0, 90);
    } catch (err) {
      const out = `${err?.stdout || ''}\n${err?.stderr || ''}`.split(/\r?\n/).map(s => s.trim()).find(Boolean);
      if (out) version = out.slice(0, 90);
    }
    return { id: spec.id, label: spec.label, category: spec.category, available: true, runnable: spec.runnable, profiles: spec.profiles, binaryPath, version, installHint: spec.installHint };
  }));
  return {
    tools,
    availableCount: tools.filter(t => t.available).length,
    totalCount: tools.length
  };
}

function buildScannerArgs(spec, profile, safeTarget) {
  if (safeTarget.startsWith('-')) throw new Error('Scanner target must not begin with "-".');
  switch (spec.id) {
    case 'semgrep': {
      const cfg = profile === 'owasp-top-ten' ? 'p/owasp-top-ten' : profile === 'secrets' ? 'p/secrets' : 'auto';
      return ['scan', '--config', cfg, '--json', '--quiet', '--metrics=off', '--', safeTarget];
    }
    case 'trivy': {
      const scanners = profile === 'fs-misconfig' ? 'misconfig' : profile === 'fs-all' ? 'vuln,misconfig,secret' : 'vuln';
      return ['fs', '--scanners', scanners, '--format', 'json', '--quiet', '--', safeTarget];
    }
    case 'gitleaks':
      return ['dir', safeTarget, '--report-format', 'json', '--report-path', '-', '--redact', '--no-banner'];
    case 'osv-scanner':
      return ['scan', '--format', 'json', '-r', safeTarget];
    case 'nmap':
      return profile === 'service-version'
        ? ['-sT', '-sV', '--top-ports', '50', '-Pn', '--open', '--', safeTarget]
        : ['-sT', '--top-ports', '100', '-Pn', '--open', '--', safeTarget];
    case 'nuclei': {
      const tags = profile === 'exposures' ? 'exposure,panel' : profile === 'cves-safe' ? 'cve' : 'misconfig,headers,ssl';
      return ['-u', safeTarget, '-tags', tags, '-es', 'dos,fuzz,intrusive', '-jsonl', '-silent', '-nc'];
    }
    default:
      throw new Error(`Unsupported scanner "${spec.id}".`);
  }
}

function parseScannerStructuredOutput(scannerId, rawOutput) {
  const findings = [];
  try {
    if (scannerId === 'semgrep') {
      const data = JSON.parse(rawOutput);
      const grouped = new Map();
      for (const r of data.results || []) {
        const ruleId = String(r.check_id || '');
        const sevRaw = String(r.extra?.severity || 'WARNING').toUpperCase();
        const conf = String(r.extra?.metadata?.confidence || '').toUpperCase();
        const impact = String(r.extra?.metadata?.impact || '').toUpperCase();
        // Drop noisy best-practice / style / unpinned-action lints and low-confidence info noise
        if (sevRaw === 'INFO') continue;
        if (conf === 'LOW' && (impact === 'LOW' || !impact)) continue;
        if (/(?:not-pinned-to-commit-sha|mutable-tag|missing-user|writable-filesystem-service|use-hardcoded-)/i.test(ruleId)) continue;
        const gKey = `${ruleId}|${r.path}`;
        const line = r.start?.line || 1;
        if (!grouped.has(gKey)) {
          grouped.set(gKey, {
            rule: ruleId,
            severity: sevRaw === 'ERROR' ? (impact === 'LOW' ? 'low' : 'high') : 'medium',
            cwe: Array.isArray(r.extra?.metadata?.cwe) ? String(r.extra.metadata.cwe[0] || '').split(':')[0] : '',
            location: `${r.path}:${line}`,
            lines: [line],
            message: redactSecrets(String(r.extra?.message || '').slice(0, 220)).text
          });
        } else {
          grouped.get(gKey).lines.push(line);
        }
      }
      for (const item of [...grouped.values()].slice(0, 35)) {
        if (item.lines.length > 1) {
          item.message = `${item.message} (occurs on ${item.lines.length} lines: ${item.lines.slice(0, 6).join(', ')}${item.lines.length > 6 ? '…' : ''})`;
        }
        delete item.lines;
        findings.push(item);
      }
    } else if (scannerId === 'trivy') {
      const data = JSON.parse(rawOutput);
      for (const res of data.Results || []) {
        for (const v of (res.Vulnerabilities || []).slice(0, 30)) {
          findings.push({ id: v.VulnerabilityID, package: `${v.PkgName}@${v.InstalledVersion}`, fixed: v.FixedVersion || '', severity: (v.Severity || 'MEDIUM').toLowerCase(), target: res.Target, title: String(v.Title || '').slice(0, 180) });
        }
        for (const m of (res.Misconfigurations || []).slice(0, 20)) {
          findings.push({ id: m.ID, severity: (m.Severity || 'MEDIUM').toLowerCase(), target: res.Target, title: String(m.Title || '').slice(0, 180) });
        }
      }
    } else if (scannerId === 'gitleaks') {
      const data = JSON.parse(rawOutput);
      if (Array.isArray(data)) {
        for (const leak of data) {
          const fPath = String(leak.File || '');
          if (/(?:^|\/)(?:target|node_modules|\.venv|venv|dist|release)\//i.test(fPath)) continue;
          findings.push({ rule: leak.RuleID, location: `${fPath}:${leak.StartLine || 1}`, description: leak.Description || 'Secret detected' });
          if (findings.length >= 40) break;
        }
      }
    } else if (scannerId === 'osv-scanner') {
      const data = JSON.parse(rawOutput);
      for (const res of data.results || []) {
        for (const pkg of res.packages || []) {
          for (const v of (pkg.vulnerabilities || []).slice(0, 25)) {
            findings.push({ id: v.id, package: `${pkg.package?.name}@${pkg.package?.version}`, summary: String(v.summary || '').slice(0, 180) });
          }
        }
      }
    } else if (scannerId === 'nuclei') {
      for (const line of rawOutput.split(/\r?\n/).filter(Boolean).slice(0, 40)) {
        try {
          const item = JSON.parse(line);
          findings.push({ template: item['template-id'], severity: item.info?.severity || 'info', matched: item['matched-at'] || item.host, name: item.info?.name || '' });
        } catch {}
      }
    }
  } catch { /* Fallback to bounded text output when scanner prints plain text. */ }
  return findings;
}

function prepareScannerSpec(args, { scope }) {
  const spec = TOOL_CATALOG.find(t => t.id === args.scanner && t.runnable);
  if (!spec) {
    const allowed = TOOL_CATALOG.filter(t => t.runnable).map(t => t.id).join(', ');
    throw new Error(`Unsupported scanner "${args.scanner}". Supported runnable scanners: ${allowed}.`);
  }
  const profile = args.profile ? String(args.profile).trim() : spec.profiles[0];
  if (!spec.profiles.includes(profile)) {
    throw new Error(`Invalid profile "${profile}" for ${spec.id}. Supported profiles: ${spec.profiles.join(', ')}.`);
  }
  const rawTarget = String(args.target || '').trim();
  if (!rawTarget || rawTarget.startsWith('-')) throw new Error('Provide a valid target path or in-scope host/URL (cannot start with "-").');
  if (spec.network) {
    const { endpoint } = checkTargetScopeSync(rawTarget, scope, { requireUrl: spec.id === 'nuclei' });
    const targetValue = spec.id === 'nuclei' ? endpoint.url : endpoint.host;
    const argv = buildScannerArgs(spec, profile, targetValue);
    return { spec, profile, isNetwork: true, targetValue, argv };
  }
  const argv = buildScannerArgs(spec, profile, rawTarget);
  return { spec, profile, isNetwork: false, targetValue: rawTarget, argv };
}

async function executeScannerRun(plan, { root, scope, commandPath = '', signal, onOutput = () => {}, dnsLookup, spawnImpl = spawn }) {
  signal.throwIfAborted();
  const { spec, profile, isNetwork, targetValue, argv } = plan.scannerPlan;
  if (isNetwork) {
    await assertTargetInScope(targetValue, scope, { dnsLookup, requireUrl: spec.id === 'nuclei' });
  }
  const binaryPath = await resolveToolBinary(spec.binary, commandPath, root);
  if (!binaryPath) {
    throw new Error(`${spec.label} ("${spec.binary}") is not installed on the verified PATH. Install it (for example: ${spec.installHint}) or use Benjamin's built-in analyzers.`);
  }
  const safeDirs = await safeSearchDirs(commandPath, root);
  const seconds = plan.seconds || 120;
  return new Promise((resolve, reject) => {
    let raw = '', stopped = '';
    const child = spawnImpl(binaryPath, argv, {
      cwd: root,
      shell: false,
      detached: process.platform !== 'win32',
      stdio: ['ignore', 'pipe', 'pipe'],
      env: {
        PATH: safeDirs.join(':') || DEFAULT_PATH,
        HOME: os.homedir(),
        TMPDIR: os.tmpdir(),
        LANG: 'en_US.UTF-8',
        NO_COLOR: '1'
      }
    });
    const kill = () => {
      if (!child.pid) return;
      try { if (process.platform === 'win32') child.kill('SIGKILL'); else process.kill(-child.pid, 'SIGKILL'); } catch {}
    };
    const stop = reason => { stopped = reason; kill(); };
    const onAbort = () => stop('Stopped by user');
    const timer = setTimeout(() => stop(`Scanner timed out after ${seconds}s`), seconds * 1000);
    signal.addEventListener('abort', onAbort, { once: true });
    const consume = chunk => {
      const text = chunk.toString('utf8');
      if (raw.length < 512000) raw += text;
      onOutput(redactSecrets(text.slice(0, 4000)).text);
    };
    child.stdout?.on('data', consume);
    child.stderr?.on('data', consume);
    const cleanup = () => { clearTimeout(timer); signal.removeEventListener('abort', onAbort); };
    child.once('error', err => { cleanup(); reject(err); });
    child.once('close', (exitCode, exitSignal) => {
      kill();
      cleanup();
      const structuredFindings = parseScannerStructuredOutput(spec.id, raw);
      const redactedTail = redactSecrets(raw.slice(-14000)).text;
      resolve({
        scanner: spec.id,
        binaryPath,
        profile,
        target: targetValue,
        exitCode,
        signal: exitSignal,
        ...(stopped ? { stopped } : {}),
        structuredFindingsCount: structuredFindings.length,
        structuredFindings,
        output: redactedTail,
        summary: stopped
          ? `${spec.label} (${profile}) stopped: ${stopped}.`
          : `${spec.label} (${profile}) exited with code ${exitCode}; parsed ${structuredFindings.length} structured finding(s).`
      });
    });
    if (signal.aborted) onAbort();
  });
}

module.exports = {
  TOOL_CATALOG,
  safeSearchDirs,
  resolveToolBinary,
  detectSecurityTools,
  prepareScannerSpec,
  executeScannerRun
};
