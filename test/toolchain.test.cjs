const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const { existsSync } = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { DEFAULT_PATH, loginPath } = require('../electron/toolchain.cjs');
const { prepareTool, executeTool } = require('../electron/agent-tools.cjs');
const { runAgent } = require('../electron/agent.cjs');
const skip = process.platform === 'win32';
async function fixture(fn) {
  const dir = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'benjamin-toolchain-')));
  const root = path.join(dir, 'workspace'), tools = path.join(dir, 'tools'), backupDir = path.join(dir, 'backups');
  await fs.mkdir(root); await fs.mkdir(tools);
  await fs.writeFile(path.join(tools, 'benjamin-tool'), '#!/bin/sh\necho tool-ran\n', { mode: 0o755 });
  // Stand-in login shells: a script named like a supported shell that runs the requested command after its "startup files".
  const shell = async (name, startup) => { const bin = path.join(dir, name); await fs.mkdir(bin, { recursive: true }); await fs.writeFile(path.join(bin, 'zsh'), `#!/bin/sh\n${startup}\n`, { mode: 0o755 }); return path.join(bin, 'zsh'); };
  try { await fn({ dir, root, tools, backupDir, shell, signal: new AbortController().signal }); }
  finally { await fs.rm(dir, { recursive: true, force: true }); }
}
const withDefaults = (...entries) => [...entries, ...DEFAULT_PATH.split(':').filter(entry => !entries.includes(entry))].join(':');

test('login PATH keeps only existing absolute directories outside the workspace', { skip }, () => fixture(async f => {
  await fs.mkdir(path.join(f.root, 'bin')); await fs.symlink(path.join(f.root, 'bin'), path.join(f.dir, 'linked'));
  const entries = ['.', 'node_modules/.bin', '', f.tools, path.join(f.dir, 'missing'), path.join(f.root, 'bin'), f.root, path.join(f.dir, 'linked'), path.join(f.tools, 'benjamin-tool'), f.tools, '/usr/bin'];
  const shell = await f.shell('noisy', `echo "Welcome back"; echo "PATH=/decoy"\nPATH='${entries.join(':')}'\neval "$4"\necho "logout noise"`);
  assert.equal(await loginPath({ shell, root: f.root, env: {} }), withDefaults(f.tools, '/usr/bin'));
  const unusable = await f.shell('unusable', `PATH='.:${path.join(f.root, 'bin')}'\neval "$4"`);
  assert.equal(await loginPath({ shell: unusable, root: f.root, env: {} }), '');
}));
test('login PATH falls back when the shell is unsupported, silent, failing or slow', { skip }, () => fixture(async f => {
  assert.equal(await loginPath({ shell: '/bin/sh', root: f.root, env: {} }), '');
  assert.equal(await loginPath({ shell: 'zsh', root: f.root, env: {} }), '');
  assert.equal(await loginPath({ shell: path.join(f.dir, 'absent', 'zsh'), root: f.root, env: {} }), '');
  assert.equal(await loginPath({ shell: await f.shell('silent', 'echo "$PATH"; exit 3'), root: f.root, env: {} }), '');
  const pidFile = path.join(f.dir, 'pid'), started = Date.now();
  assert.equal(await loginPath({ shell: await f.shell('slow', 'echo $$ > "$PID_FILE"\nsleep 30 & wait'), root: f.root, env: { PID_FILE: pidFile }, timeout: 400 }), '');
  assert.ok(Date.now() - started < 3000);
  const pid = Number(await fs.readFile(pidFile, 'utf8'));
  for (let i = 0; i < 40; i++) { try { process.kill(pid, 0); await new Promise(resolve => setTimeout(resolve, 25)); } catch { break; } }
  assert.throws(() => process.kill(pid, 0));
  // A startup file may leave a helper holding the output open; the answer must not wait for it.
  const lingering = await f.shell('lingering', `PATH='${f.tools}'\neval "$4"\nsleep 30 &`), again = Date.now();
  assert.equal(await loginPath({ shell: lingering, root: f.root, env: {} }), withDefaults(f.tools));
  assert.ok(Date.now() - again < 3000);
}));
test('a real zsh reports the PATH its startup files set and nothing else', { skip: skip || !existsSync('/bin/zsh') }, () => fixture(async f => {
  const user = path.join(f.dir, 'user'); await fs.mkdir(user);
  await fs.writeFile(path.join(user, '.zshrc'), `export PATH="${f.tools}:$PATH"\nexport STARTUP_SECRET=hunter2\necho "startup banner"\nalias printf='echo hijacked'\n`);
  const value = await loginPath({ shell: '/bin/zsh', root: f.root, env: { HOME: user, ZDOTDIR: user, PATH: '/usr/bin:/bin' } });
  // System startup files may add their own directories (path_helper on macOS).
  const entries = value.split(':');
  assert.equal(entries[0], f.tools); assert.ok(entries.includes('/usr/bin')); assert.ok(entries.every(entry => path.isAbsolute(entry)));
  assert.doesNotMatch(value, /hunter2|banner|hijacked/);
}));
test('approved commands resolve tools from the provided PATH and inherit no other variables', { skip }, () => fixture(async f => {
  const commandPath = withDefaults(f.tools);
  const run = async (command, options) => executeTool(f.root, await prepareTool(f.root, 'run_command', { command, cwd: '.' }), { ...f, ...options });
  assert.equal((await run('benjamin-tool')).exitCode, 127);
  assert.deepEqual(await run('benjamin-tool', { commandPath }), { exitCode: 0, signal: null, output: 'tool-ran\n' });
  process.env.BENJAMIN_TEST_SECRET = 'must-not-leak';
  try {
    const { output } = await run('env', { commandPath });
    const names = output.trim().split('\n').map(line => line.split('=')[0]);
    assert.ok(output.includes(`PATH=${commandPath}\n`)); assert.doesNotMatch(output, /must-not-leak/);
    assert.deepEqual(names.filter(name => !['PATH', 'HOME', 'TMPDIR', 'LANG', 'NO_COLOR', 'PWD', 'OLDPWD', 'SHLVL', '_'].includes(name)), []);
  } finally { delete process.env.BENJAMIN_TEST_SECRET; }
  let step = 0; const payloads = [], events = [];
  await runAgent({ ...f, id: 'toolchain', commandPath, settings: { baseUrl: 'https://example.invalid/v1', model: 'test' }, messages: [{ role: 'user', content: 'Run the tool' }], context: '', apiKey: '', onToken() {}, onEvent: event => events.push(event), audit: async () => {}, approve: async () => true, fetchImpl: async (_url, init) => {
    payloads.push(JSON.parse(init.body));
    const reply = step++ ? { content: 'Done.' } : { tool_calls: [{ index: 0, id: 'call_1', type: 'function', function: { name: 'run_command', arguments: JSON.stringify({ command: 'benjamin-tool', cwd: '.' }) } }] };
    return new Response(`data: ${JSON.stringify({ choices: [{ delta: reply, finish_reason: step === 1 ? 'tool_calls' : 'stop' }] })}\n\ndata: [DONE]\n`);
  } });
  assert.equal(events.find(event => event.status === 'completed').result.output, 'tool-ran\n');
  assert.match(payloads[0].messages[0].content, /PATH from the user's login shell/);
}));
