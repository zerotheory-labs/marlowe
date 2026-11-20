const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const assert = require('node:assert/strict');
const { runAgent, ApprovalGate } = require('./agent.cjs');
const { restoreBackup } = require('./agent-tools.cjs');
const { assertTargetInScope } = require('./cyber-scope.cjs');
const { createFindingsStore, toSarifReport } = require('./findings.cjs');
function response(content, call) {
  const delta = call ? { tool_calls: [{ index: 0, id: 'check-call', type: 'function', function: { name: call.name, arguments: JSON.stringify(call.args) } }] } : { content };
  return new Response('data: ' + JSON.stringify({ choices: [{ delta, finish_reason: call ? 'tool_calls' : 'stop' }] }) + '\n\ndata: [DONE]\n');
}
async function runReliabilityChecks(version) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'benjamin-checks-'));
  const root = path.join(directory, 'workspace'), backupDir = path.join(directory, 'backups');
  await fs.mkdir(root);
  const checks = [];
  async function check(name, fn) {
    const start = Date.now();
    try { await fn(); checks.push({ name, passed: true, durationMs: Date.now() - start }); }
    catch (e) { checks.push({ name, passed: false, durationMs: Date.now() - start, error: e.message.slice(0, 1000) }); }
  }
  async function run(replies, approve, commandPath, extra = {}) {
    const events = [], tokens = [], gate = new ApprovalGate(), controller = new AbortController();
    let index = 0;
    const result = await runAgent({ id: 'reliability-check', root, backupDir, settings: { baseUrl: 'https://fixture.invalid/v1', model: 'deterministic fixture' }, messages: [{ role: 'user', content: 'Run isolated check' }], context: '', apiKey: '', signal: controller.signal, commandPath,
      onToken: token => tokens.push(token), onEvent() {}, audit: async event => events.push(event),
      approve: action => gate.wait(action, controller.signal, pending => { approve(pending, gate); }),
      fetchImpl: async () => { const reply = replies[index++]; if (!reply) throw new Error('Unexpected extra model request'); return response(reply.content, reply.call); },
      ...extra
    });
    return { events, tokens, result };
  }
  try {
    await check('Denial prevents deletion', async () => {
      await fs.writeFile(path.join(root, 'note.txt'), 'original');
      const r = await run([{ call: { name: 'delete_file', args: { path: 'note.txt' } } }, { content: 'Deletion was denied.' }], (p, gate) => gate.decide(p.runId, p.approvalId, false));
      assert.equal(await fs.readFile(path.join(root, 'note.txt'), 'utf8'), 'original');
      assert.ok(r.events.some(e => e.status === 'denied')); assert.ok(!r.events.some(e => e.status === 'running'));
    });
    await check('Approve once and Undo restore exact contents', async () => {
      await fs.writeFile(path.join(root, 'note.txt'), 'original');
      const r = await run([{ call: { name: 'delete_file', args: { path: 'note.txt' } } }, { content: 'Deleted the note.' }], (p, gate) => {
        gate.decide(p.runId, p.approvalId, true);
        assert.throws(() => gate.decide(p.runId, p.approvalId, true));
      });
      await assert.rejects(fs.access(path.join(root, 'note.txt')));
      await restoreBackup(backupDir, r.events.find(e => e.result?.backupId).result.backupId);
      assert.equal(await fs.readFile(path.join(root, 'note.txt'), 'utf8'), 'original');
    });
    await check('Unsupported approval claim recovers into a real tool call', async () => {
      const r = await run([{ content: 'I requested approval. Please approve.' }, { call: { name: 'read_file', args: { path: 'note.txt' } } }, { content: 'Read the note.' }], () => assert.fail('Unexpected approval'));
      assert.equal(r.events.filter(e => e.status === 'response-rejected').length, 1);
      assert.ok(r.events.some(e => e.name === 'read_file' && e.status === 'completed'));
      assert.deepEqual(r.tokens, ['Read the note.']);
    });
    await check('Stop expires a pending approval', async () => {
      const gate = new ApprovalGate(), controller = new AbortController(); let pending;
      const waiting = gate.wait({ runId: 'stopped' }, controller.signal, p => pending = p);
      controller.abort(); await assert.rejects(waiting);
      assert.equal(gate.pending.size, 0); assert.throws(() => gate.decide('stopped', pending.approvalId, true));
    });
    await check('Undo refuses to overwrite newer edits', async () => {
      const r = await run([{ call: { name: 'write_file', args: { path: 'new.txt', content: 'agent change' } } }, { content: 'Created the file.' }], () => assert.fail('Unexpected approval'));
      await fs.writeFile(path.join(root, 'new.txt'), 'human edit');
      await assert.rejects(restoreBackup(backupDir, r.events.find(e => e.result?.backupId).result.backupId), /changed/);
      assert.equal(await fs.readFile(path.join(root, 'new.txt'), 'utf8'), 'human edit');
    });
    await check('Search skips credentials, symlinks and files outside the workspace', async () => {
      await fs.writeFile(path.join(directory, 'outside.txt'), 'search-marker outside');
      await fs.symlink(directory, path.join(root, 'link')).catch(error => { if (error.code !== 'EPERM') throw error; });
      await fs.writeFile(path.join(root, '.env'), 'search-marker secret');
      await fs.writeFile(path.join(root, 'visible.txt'), 'search-marker visible');
      const r = await run([{ call: { name: 'search_text', args: { query: 'search-marker', path: '.' } } }, { content: 'Searched the workspace.' }], () => assert.fail('Unexpected approval'));
      assert.deepEqual(r.events.find(e => e.name === 'search_text' && e.status === 'completed').result.matches.map(m => m.path), ['visible.txt']);
    });
    await check('ScopeGate blocks out-of-scope and DNS-rebinding network targets', async () => {
      await assert.rejects(assertTargetInScope('https://evil.example.com', { targets: ['api.example.com'] }), /outside Authorized Scope/);
      await assert.rejects(assertTargetInScope('https://api.example.com', { targets: ['api.example.com'] }, { dnsLookup: async () => [{ address: '169.254.169.254' }] }), /SSRF \/ DNS-rebinding/);
      const r = await run([{ call: { name: 'inspect_http_security', args: { url: 'https://unlisted.example.com' } } }, { content: 'Blocked.' }], () => assert.fail('Out-of-scope call must never reach approval'), '', { playbook: 'recon', scope: { targets: ['allowed.example.com'], allowOsv: false, redactContext: true } });
      assert.ok(r.events.some(e => e.name === 'inspect_http_security' && e.status === 'error' && /outside Authorized Scope/.test(e.result?.error || '')));
    });
    await check('Secret scanner masks detected credentials before model serialization', async () => {
      const fakeToken = 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8';
      await fs.writeFile(path.join(root, 'leak-check.js'), `const token = "${fakeToken}";\n`);
      const r = await run([{ call: { name: 'scan_secrets', args: { path: '.' } } }, { content: 'Scanned.' }], () => assert.fail('Unexpected approval'), '', { playbook: 'appsec' });
      const completed = r.events.find(e => e.name === 'scan_secrets' && e.status === 'completed');
      assert.ok(completed.result.findingsCount >= 1);
      assert.ok(!JSON.stringify(completed.result).includes(fakeToken));
      await fs.unlink(path.join(root, 'leak-check.js'));
    });
    await check('Finding recorder persists structured CWE evidence and exports valid SARIF', async () => {
      const store = createFindingsStore(path.join(directory, 'findings'));
      const r = await run([{ call: { name: 'record_finding', args: { title: 'SQL Injection in login', severity: 'high', category: 'appsec', cwe: 'CWE-89', cvss: 8.8, location: 'src/auth.js:42', evidence: 'SELECT * FROM users WHERE id = ' + '${id}', remediation: 'Use parameterized statements.' } } }, { content: 'Recorded.' }], () => assert.fail('Unexpected approval'), '', { playbook: 'appsec', findingsStore: store });
      assert.ok(r.events.some(e => e.name === 'record_finding' && e.status === 'completed'));
      const list = await store.list(root);
      assert.equal(list.length, 1); assert.equal(list[0].cwe, 'CWE-89');
      const sarif = toSarifReport({ workspace: root, findings: list, appVersion: version });
      assert.equal(sarif.version, '2.1.0'); assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.region.startLine, 42);
    });
    if (process.platform !== 'win32') await check('Approved commands find tools on the provided PATH and inherit no other variables', async () => {
      const tools = path.join(directory, 'tools'); await fs.mkdir(tools);
      await fs.writeFile(path.join(tools, 'benjamin-check-tool'), '#!/bin/sh\necho check-tool-ran\n', { mode: 0o755 });
      const r = await run([{ call: { name: 'run_command', args: { command: 'benjamin-check-tool && env', cwd: '.' } } }, { content: 'Ran the tool.' }], (p, gate) => gate.decide(p.runId, p.approvalId, true), `${tools}:/usr/bin:/bin`);
      const { exitCode, output } = r.events.find(e => e.name === 'run_command' && e.status === 'completed').result;
      assert.equal(exitCode, 0); assert.ok(output.startsWith('check-tool-ran\n'));
      assert.deepEqual(output.trim().split('\n').slice(1).map(line => line.split('=')[0]).filter(name => !['PATH', 'HOME', 'TMPDIR', 'LANG', 'NO_COLOR', 'PWD', 'OLDPWD', 'SHLVL', '_'].includes(name)), []);
    });
    return { time: new Date().toISOString(), version, kind: 'Deterministic app checks · isolated temporary files · no model or network', checks };
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
}
module.exports = { runReliabilityChecks };
