const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { prepareTool, executeTool, restoreBackup, commandPolicy, runCommand } = require('../electron/agent-tools.cjs');
const { runAgent, ApprovalGate } = require('../electron/agent.cjs');
const { streamCompletion } = require('../electron/provider.cjs');
async function fixture(fn) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'benjamin-agent-'));
  const root = path.join(dir, 'workspace'), backupDir = path.join(dir, 'backups');
  await fs.mkdir(root);
  try { await fn({ dir, root, backupDir, signal: new AbortController().signal }); }
  finally { await fs.rm(dir, { recursive: true, force: true }); }
}
function sse(chunks) { return new Response(new ReadableStream({ start(c) { for (const x of chunks) c.enqueue(new TextEncoder().encode(x)); c.close(); } })); }
function toolResponse(name, args, id = 'call_1') { return sse([`data: ${JSON.stringify({ choices: [{ delta: { tool_calls: [{ index: 0, id, type: 'function', function: { name, arguments: JSON.stringify(args) } }] } }] })}\n\n`, 'data: {"choices":[{"delta":{},"finish_reason":"tool_calls"}]}\n\ndata: [DONE]\n']); }
const textResponse = () => sse(['data: {"choices":[{"delta":{"content":"Done."},"finish_reason":"stop"}]}\n\ndata: [DONE]\n']);
const settings = { baseUrl: 'https://example.invalid/v1', model: 'test' };

test('rejects path escapes, symlinks, hard links, credentials and binary files', () => fixture(async f => {
  await assert.rejects(prepareTool(f.root, 'list_files', { path: f.root }), /Use "\." instead of the absolute path/);
  await assert.rejects(prepareTool(f.root, 'run_command', { command: 'pwd', cwd: path.join(f.root, 'sub') }), /Use "sub" instead/);
  await assert.rejects(prepareTool(f.root, 'read_file', { path: path.join(f.dir, 'outside') }), /Absolute paths are not accepted/);
  await fs.writeFile(path.join(f.dir, 'outside'), 'secret');
  await fs.symlink(f.dir, path.join(f.root, 'link'));
  await fs.link(path.join(f.dir, 'outside'), path.join(f.root, 'hard'));
  await fs.writeFile(path.join(f.root, 'binary'), Buffer.from([1, 0, 2]));
  for (const target of ['../outside', path.join(f.dir, 'outside'), 'link/outside', 'hard', '.git/config', '.env', 'binary']) {
    await assert.rejects(async () => executeTool(f.root, await prepareTool(f.root, 'read_file', { path: target }), f));
  }
  await assert.rejects(prepareTool(f.root, 'write_file', { path: 'missing/child', content: 'x' }));
}));
test('file edits preserve backups, reject stale plans, and restore without clobbering new work', () => fixture(async f => {
  let plan = await prepareTool(f.root, 'write_file', { path: 'note.txt', content: 'hello' });
  assert.equal(plan.reason, '');
  await executeTool(f.root, plan, f);
  plan = await prepareTool(f.root, 'edit_file', { path: 'note.txt', old_text: 'hello', new_text: 'hello world' });
  assert.equal(plan.reason, '');
  const changed = await executeTool(f.root, plan, f);
  assert.equal(await fs.readFile(path.join(f.root, 'note.txt'), 'utf8'), 'hello world');
  await restoreBackup(f.backupDir, changed.backupId);
  assert.equal(await fs.readFile(path.join(f.root, 'note.txt'), 'utf8'), 'hello');
  plan = await prepareTool(f.root, 'write_file', { path: 'note.txt', content: 'replacement' });
  assert.ok(plan.reason);
  await fs.writeFile(path.join(f.root, 'note.txt'), 'human edit');
  await assert.rejects(executeTool(f.root, plan, f), /changed/);
  await assert.rejects(restoreBackup(f.backupDir, changed.backupId), /changed/);
  const shortening = await prepareTool(f.root, 'edit_file', { path: 'note.txt', old_text: 'human edit', new_text: 'hi' });
  assert.ok(shortening.reason);
  const deletion = await prepareTool(f.root, 'delete_file', { path: 'note.txt' });
  assert.ok(deletion.reason);
}));
test('search tools stay inside the workspace and skip protected, linked, binary and dependency files', () => fixture(async f => {
  for (const folder of ['src/deep', 'node_modules/pkg', '.git']) await fs.mkdir(path.join(f.root, folder), { recursive: true });
  await fs.writeFile(path.join(f.dir, 'outside.js'), 'needle outside');
  await fs.symlink(f.dir, path.join(f.root, 'link'));
  await fs.link(path.join(f.dir, 'outside.js'), path.join(f.root, 'hard.js'));
  for (const [name, content] of [['src/app.js', 'first\n  const Needle = 1;\n'], ['src/deep/util.test.js', 'needle again\r\n'], ['src/notes.md', 'no match'], ['node_modules/pkg/index.js', 'needle dependency'], ['.git/config', 'needle git'], ['.env', 'needle secret'], ['binary.js', Buffer.from('needle\0')]]) await fs.writeFile(path.join(f.root, name), content);
  const run = async (name, args) => executeTool(f.root, await prepareTool(f.root, name, args), f);
  assert.deepEqual((await run('find_files', { pattern: '*.js', path: '.' })).files, ['binary.js', 'hard.js', 'src/app.js', 'src/deep/util.test.js']);
  assert.deepEqual((await run('find_files', { pattern: 'src/*.{js,md}', path: '.' })).files, ['src/app.js', 'src/notes.md']);
  assert.deepEqual((await run('find_files', { pattern: '**/*.TEST.js', path: 'src' })).files, ['src/deep/util.test.js']);
  const search = await run('search_text', { query: 'NEEDLE', path: '.' });
  assert.deepEqual(search.matches, [{ path: 'src/app.js', line: 2, text: 'const Needle = 1;' }, { path: 'src/deep/util.test.js', line: 1, text: 'needle again' }]);
  assert.equal(search.truncated, false); assert.match(search.summary, /2 matching lines in 2 files/);
  assert.deepEqual((await run('search_text', { query: 'needle', path: '.', glob: '*.test.js' })).matches.map(m => m.path), ['src/deep/util.test.js']);
  assert.equal((await run('search_text', { query: 'absent', path: 'src', glob: '' })).summary, 'No matches.');
  for (const args of [{ query: 'needle', path: '..' }, { query: 'needle', path: 'link' }, { query: 'needle', path: '.git' }, { query: 'needle', path: 'src/app.js' }, { query: 'a\nb', path: '.' }, { query: ' ', path: '.' }]) await assert.rejects(prepareTool(f.root, 'search_text', args));
  await assert.rejects(prepareTool(f.root, 'find_files', { pattern: '{a,b}'.repeat(8), path: '.' }), /alternatives/);
  await fs.writeFile(path.join(f.root, 'a'.repeat(200)), 'x');
  assert.deepEqual((await run('find_files', { pattern: '*a'.repeat(90) + 'c', path: '.' })).files, []);
  await fs.writeFile(path.join(f.root, 'many.txt'), 'needle line\n'.repeat(5000));
  const many = await run('search_text', { query: 'needle', path: '.', glob: 'many.txt' });
  assert.equal(many.matches.length, 200); assert.equal(many.truncated, true); assert.match(many.summary, /limit/);
}));
test('read_file pages long files with exact contents and accepts line ranges', () => fixture(async f => {
  const lines = Array.from({ length: 3000 }, (_, i) => `line ${i + 1} "quoted"`);
  await fs.writeFile(path.join(f.root, 'long.txt'), lines.join('\n') + '\n');
  await fs.writeFile(path.join(f.root, 'short.txt'), 'one\ntwo');
  await fs.writeFile(path.join(f.root, 'empty.txt'), '');
  const read = async args => executeTool(f.root, await prepareTool(f.root, 'read_file', args), f);
  assert.deepEqual(await read({ path: 'short.txt' }), { path: 'short.txt', content: 'one\ntwo', startLine: 1, endLine: 2, totalLines: 2 });
  assert.deepEqual(await read({ path: 'empty.txt', start_line: null }), { path: 'empty.txt', content: '', startLine: 1, endLine: 0, totalLines: 0 });
  let page = await read({ path: 'long.txt' }), text = '', pages = 0;
  assert.equal(page.truncated, true); assert.match(page.note, /start_line/);
  while (true) {
    assert.ok(JSON.stringify(page).length < 32000); text += page.content; pages++;
    if (page.endLine === page.totalLines) break;
    page = await read({ path: 'long.txt', start_line: page.endLine + 1 });
  }
  assert.ok(pages > 1); assert.equal(text, lines.join('\n') + '\n');
  assert.deepEqual(await read({ path: 'long.txt', start_line: '10', line_count: 2 }), { path: 'long.txt', content: 'line 10 "quoted"\nline 11 "quoted"\n', startLine: 10, endLine: 11, totalLines: 3000 });
  await assert.rejects(read({ path: 'long.txt', start_line: 3001 }), /past the end/);
  for (const bad of [0, -1, 1.5, 'x', true]) await assert.rejects(read({ path: 'long.txt', start_line: bad }), /whole number/);
  await assert.rejects(read({ path: 'long.txt', lines: 3 }), /Invalid tool arguments/);
  await fs.writeFile(path.join(f.root, 'minified.js'), 'x'.repeat(90000));
  const minified = await read({ path: 'minified.js' });
  assert.equal(minified.truncated, true); assert.match(minified.note, /too long/); assert.ok(JSON.stringify(minified).length < 32000);
}));
test('finite command policy never auto-allows scripts, redirection, substitution or chained commands', async () => {
  assert.equal(commandPolicy('pwd'), process.platform === 'win32' ? 'approval' : 'automatic');
  for (const command of ['rm file', 'ls; rm file', 'ls >file', 'ls $(touch file)', 'python -c "print(1)"', 'npm test', '/tmp/pwd', 'git reset --hard', 'pwd\nrm file']) assert.equal(commandPolicy(command), 'approval');
});
test('approval is bound to run, one-shot, and cancelled with Stop', async () => {
  const gate = new ApprovalGate(), controller = new AbortController(); let event;
  const pending = gate.wait({ runId: 'run' }, controller.signal, value => event = value);
  assert.throws(() => gate.decide('other-run', event.approvalId, true));
  gate.decide('run', event.approvalId, false); assert.equal(await pending, false);
  assert.throws(() => gate.decide('run', event.approvalId, true));
  const stopped = gate.wait({ runId: 'next' }, controller.signal, value => event = value);
  controller.abort(); await assert.rejects(stopped); assert.equal(gate.pending.size, 0);
  assert.throws(() => gate.decide('next', event.approvalId, true));
});
test('agent executes automatic edits, consumes tool results, and honors denied deletion', () => fixture(async f => {
  let step = 0; const events = [], approvals = [], payloads = [], histories = [];
  const result = await runAgent({ ...f, id: 'run', settings, onHistory: async value => histories.push(JSON.parse(JSON.stringify(value))), messages: [{ role: 'user', content: 'Create a note' }], context: '', apiKey: '', onToken() {}, onEvent: e => events.push(e), audit: async () => {}, approve: async e => { approvals.push(e); return false; }, fetchImpl: async (_url, init) => {
    payloads.push(JSON.parse(init.body));
    if (step++ === 0) return toolResponse('write_file', { path: 'note.txt', content: 'hello' });
    if (step === 2) return toolResponse('delete_file', { path: 'note.txt' }, 'call_2');
    return textResponse();
  } });
  assert.equal(result.content, 'Done.');
  assert.deepEqual(histories.at(-1).map(m => m.role), ['assistant', 'tool', 'assistant', 'tool', 'assistant']);
  assert.equal(histories[0][0].tool_calls[0].id, histories[0][1].tool_call_id);
  assert.match(histories.at(-1)[3].content, /denied/);
  assert.equal(await fs.readFile(path.join(f.root, 'note.txt'), 'utf8'), 'hello');
  assert.equal(approvals.length, 1); assert.equal(approvals[0].name, 'delete_file');
  assert.ok(events.some(e => e.status === 'denied'));
  assert.ok(payloads[2].messages.some(m => m.role === 'tool' && m.content.includes('denied')));
}));
test('approved shell commands run, report exit code, and Stop kills a running process', { skip: process.platform === 'win32' }, () => fixture(async f => {
  const result = await runCommand('printf hello; exit 3', f.root, f.signal);
  assert.equal(result.exitCode, 3); assert.equal(result.output, 'hello');
  const controller = new AbortController();
  const started = Date.now();
  const running = runCommand('printf ready; sleep 20; touch SHOULD_NOT_EXIST', f.root, controller.signal, () => controller.abort());
  const stopped = await running;
  assert.match(stopped.stopped, /Stopped/); assert.equal(stopped.hint, undefined); assert.ok(Date.now() - started < 3000);
  await assert.rejects(fs.access(path.join(f.root, 'SHOULD_NOT_EXIST')));
}));
test('commands honor a reviewed time limit and keep the start and end of long output', { skip: process.platform === 'win32' }, () => fixture(async f => {
  let plan = await prepareTool(f.root, 'run_command', { command: 'npm test', cwd: '.' });
  assert.equal(plan.seconds, 30); assert.match(plan.preview, /Time limit: 30 seconds/);
  plan = await prepareTool(f.root, 'run_command', { command: 'npm test', cwd: '.', timeout_seconds: 300 });
  assert.ok(plan.reason); assert.match(plan.preview, /Time limit: 5 minutes/);
  for (const bad of [601, 0, 2.5, 'soon']) await assert.rejects(prepareTool(f.root, 'run_command', { command: 'npm test', cwd: '.', timeout_seconds: bad }));
  const started = Date.now();
  const slow = await executeTool(f.root, await prepareTool(f.root, 'run_command', { command: 'printf begun; sleep 20', cwd: '.', timeout_seconds: 1 }), f);
  assert.equal(slow.stopped, 'Command timed out after 1 second'); assert.match(slow.hint, /larger timeout_seconds \(up to 600\)/); assert.equal(slow.output, 'begun'); assert.ok(Date.now() - started < 4000);
  const live = [];
  const noisy = await runCommand('i=0; while [ $i -lt 4000 ]; do echo "line $i of a long and noisy test run"; i=$((i+1)); done; echo FINAL-FAILURE; exit 4', f.root, f.signal, text => live.push(text));
  assert.equal(noisy.exitCode, 4); assert.equal(noisy.stopped, undefined); assert.equal(noisy.truncated, true);
  assert.ok(noisy.output.startsWith('line 0 of')); assert.ok(noisy.output.endsWith('FINAL-FAILURE\n')); assert.match(noisy.output, /characters of output omitted/);
  assert.ok(noisy.output.length < 30000); assert.ok(live.join('').endsWith('FINAL-FAILURE\n'));
}));
test('oversized command results reach the model as valid JSON with the exit code and final output', { skip: process.platform === 'win32' }, () => fixture(async f => {
  let step = 0; const payloads = [];
  await runAgent({ ...f, id: 'long-output', settings, messages: [{ role: 'user', content: 'Run the tests' }], context: '', apiKey: '', onToken() {}, onEvent() {}, audit: async () => {}, approve: async () => true, fetchImpl: async (_url, init) => {
    payloads.push(JSON.parse(init.body));
    return step++ ? textResponse() : toolResponse('run_command', { command: `i=0; while [ $i -lt 600 ]; do echo '${'"'.repeat(40)}'; i=$((i+1)); done; echo LAST-LINE; exit 7`, cwd: '.' });
  } });
  const content = payloads[1].messages.find(m => m.role === 'tool').content, result = JSON.parse(content);
  assert.ok(content.length <= 32000); assert.equal(result.exitCode, 7); assert.equal(result.truncated, true);
  assert.ok(result.output.endsWith('LAST-LINE\n')); assert.match(result.output, /output omitted/);
}));
test('stream parser assembles fragmented tool arguments and rejects truncated requests', async () => {
  const base = { settings, apiKey: '', messages: [], context: '', signal: new AbortController().signal, onToken() {}, tools: [] };
  const chunks = [
    'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"one","function":{"name":"read_file","arguments":"{\\"path\\":"}}]}}]}\n',
    'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\\"a.txt\\"}"}}]},"finish_reason":"tool_calls"}]}\n'
  ];
  const response = await streamCompletion({ ...base, fetchImpl: async () => sse(chunks) });
  assert.deepEqual(JSON.parse(response.tool_calls[0].function.arguments), { path: 'a.txt' });
  await assert.rejects(streamCompletion({ ...base, fetchImpl: async () => sse(chunks.slice(0, 1)) }), /Incomplete/);
});

function prose(content) {
  return sse(['data: ' + JSON.stringify({ choices: [{ delta: { content }, finish_reason: 'stop' }] }) + '\n\ndata: [DONE]\n']);
}
test('fabricated approval prose is withheld and corrected into a real approval gate', () => fixture(async f => {
  await fs.writeFile(path.join(f.root, 'note.txt'), 'keep me');
  const tokens = [], events = []; let step = 0, approvals = 0;
  const result = await runAgent({ ...f, id: 'truthful', settings, messages: [{ role: 'user', content: 'Delete note.txt' }],
    onToken: t => tokens.push(t), onEvent: e => events.push(e), audit: async () => {},
    approve: async () => {
      approvals++;
      assert.deepEqual(tokens, []);
      assert.equal(await fs.readFile(path.join(f.root, 'note.txt'), 'utf8'), 'keep me');
      return false;
    },
    fetchImpl: async (_url, init) => {
      step++;
      if (step === 1) return prose('The deletion request has been prepared again for approval. Please approve the deletion. Agent activity: delete_file — awaiting user approval.');
      if (step === 2) {
        assert.ok(JSON.parse(init.body).messages.some(m => m.role === 'system' && m.content.includes('No approval is pending')));
        return toolResponse('delete_file', { path: 'note.txt' });
      }
      return prose('Deletion was denied. The file was left unchanged.');
    }
  });
  assert.equal(approvals, 1);
  assert.ok(events.some(e => e.status === 'denied'));
  assert.deepEqual(tokens, [result.content]);
  assert.equal(await fs.readFile(path.join(f.root, 'note.txt'), 'utf8'), 'keep me');
}));
test('repeated phantom approval claims stop honestly without creating actions', () => fixture(async f => {
  const tokens = []; let calls = 0;
  const result = await runAgent({ ...f, id: 'bounded', settings, messages: [], onToken: t => tokens.push(t),
    onEvent: () => assert.fail('No tool was called'), audit: async () => {}, approve: () => assert.fail('No approval exists'),
    fetchImpl: async () => { calls++; return prose('I requested approval to delete the file.'); }
  });
  assert.equal(calls, 3);
  assert.match(result.content, /No approval is pending/);
  assert.deepEqual(tokens, [result.content]);
}));
test('ordinary answers remain available without tools', () => fixture(async f => {
  const tokens = [];
  const result = await runAgent({ ...f, id: 'answer', settings, messages: [], onToken: t => tokens.push(t),
    onEvent: () => assert.fail(), audit: async () => {}, approve: () => assert.fail(),
    fetchImpl: async () => prose('A Git branch is a movable reference to a commit.')
  });
  assert.deepEqual(tokens, [result.content]);
  assert.match(result.content, /Git branch/);
}));

test('tool-turn narration is never displayed as completed progress', () => fixture(async f => {
  const tokens = []; let step = 0;
  await runAgent({ ...f, id: 'narration', settings, messages: [], onToken: t => tokens.push(t),
    onEvent() {}, audit: async () => {}, approve: () => assert.fail(),
    fetchImpl: async () => {
      if (step++) return prose('The directory listing is complete.');
      return sse(['data: ' + JSON.stringify({ choices: [{ delta: {
        content: 'I have deleted all files and requested approval.',
        tool_calls: [{ index: 0, id: 'list', type: 'function', function: { name: 'list_files', arguments: '{"path":"."}' } }]
      }, finish_reason: 'tool_calls' }] }) + '\n\ndata: [DONE]\n']);
    }
  });
  assert.deepEqual(tokens, ['The directory listing is complete.']);
}));
