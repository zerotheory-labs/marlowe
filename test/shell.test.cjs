const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { promisify } = require('node:util');
const execFile = promisify(require('node:child_process').execFile);
const { shellEnvironment } = require('../electron/shell.cjs');

test('zsh styling preserves startup files and colors actual directory output', { skip: process.platform !== 'darwin' }, async () => {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'benjamin-shell-'));
  try {
    const user = path.join(temp, 'user'); await fs.mkdir(user);
    await fs.writeFile(path.join(user, '.zshenv'), 'export STARTUP_ORDER=env\n');
    await fs.writeFile(path.join(user, '.zprofile'), 'STARTUP_ORDER+=profile\n');
    const rc = "STARTUP_ORDER+=rc\nPROMPT='plain> '\n";
    await fs.writeFile(path.join(user, '.zshrc'), rc);
    await fs.writeFile(path.join(user, '.zlogin'), 'STARTUP_ORDER+=login\n');
    await fs.mkdir(path.join(temp, 'directory'));
    const env = await shellEnvironment({ shell: '/bin/zsh', env: { ...process.env, ZDOTDIR: user }, home: os.homedir(), userData: path.join(temp, 'data') });
    delete env.NO_COLOR;
    const { stdout } = await execFile('/bin/zsh', ['-l', '-i', '-c', 'print -r -- "$STARTUP_ORDER" "$ZDOTDIR" "$PROMPT"; CLICOLOR_FORCE=1 ls -d directory; marlowe-colors'], { cwd: temp, env });
    assert.ok(stdout.includes('envprofilerc' + 'login'));
    assert.ok(stdout.includes(user));
    assert.ok(stdout.includes('%F{blue}'));
    assert.match(stdout.split('Marlowe · ANSI palette')[0], /\u001b\[[0-9;]*m/);
    assert.match(stdout, /Marlowe · ANSI palette/);
    assert.equal(await fs.readFile(path.join(user, '.zshrc'), 'utf8'), rc);
    await fs.writeFile(path.join(user, '.zshrc'), "PROMPT='%F{magenta}custom%f> '\nalias ls='ls -lah'\n");
    const custom = await execFile('/bin/zsh', ['-l', '-i', '-c', 'print -r -- "$PROMPT"; alias ls'], { env });
    assert.ok(custom.stdout.includes('%F{magenta}custom%f> '));
    assert.ok(custom.stdout.includes('ls -lah'));
    await fs.writeFile(path.join(user, '.zshrc'), "PROMPT='plain> '\n");
    const plain = await execFile('/bin/zsh', ['-l', '-i', '-c', 'print -r -- "$PROMPT"'], { env: { ...env, NO_COLOR: '1' } });
    assert.equal(plain.stdout.trim(), 'plain>');
  } finally { await fs.rm(temp, { recursive: true, force: true }); }
});

test('segmented prompt shows branch, detached HEAD, and original exit status safely', { skip: process.platform !== 'darwin' }, async () => {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'benjamin-prompt-'));
  try {
    const user = path.join(temp, 'config'); await fs.mkdir(user);
    await fs.writeFile(path.join(user, '.zshrc'), "PROMPT='plain> '\n");
    const repo = path.join(temp, 'repo'); await fs.mkdir(repo);
    await execFile('git', ['init', '-b', 'feature/colors'], { cwd: repo });
    const env = await shellEnvironment({ shell: '/bin/zsh', env: { ...process.env, ZDOTDIR: user }, home: os.homedir(), userData: path.join(temp, 'data') });
    delete env.NO_COLOR;
    const render = async (cwd, command) => (await execFile('/bin/zsh', ['-l', '-i', '-c', command + '; _benjamin_prompt; print -P -- "$PROMPT"'], { cwd, env })).stdout;
    assert.match(await render(repo, 'true'), /git feature\/colors.*OK/);
    assert.match(await render(repo, '(exit 7)'), /EXIT 7/);
    assert.doesNotMatch(await render(temp, 'true'), /git /);
    await execFile('git', ['-c', 'user.name=Benjamin Test', '-c', 'user.email=test@example.invalid', '-c', 'commit.gpgsign=false', 'commit', '--allow-empty', '-m', 'test'], { cwd: repo });
    await execFile('git', ['checkout', '--detach'], { cwd: repo });
    assert.match(await render(repo, 'true'), /git detached [a-f0-9]+/);
    await execFile('git', ['checkout', '-b', 'topic/$(touch${IFS}INJECTED)%F{red}'], { cwd: repo });
    const output = await render(repo, 'true');
    assert.ok(output.includes('$(touch'));
    await assert.rejects(fs.access(path.join(repo, 'INJECTED')));
  } finally { await fs.rm(temp, { recursive: true, force: true }); }
});

test('real interactive hooks preserve user prompts, failure status, Unicode and cwd without dotfile edits', { skip: process.platform !== 'darwin' }, async () => {
  const { spawnSync } = require('node:child_process');
  const { TerminalContext } = require('../electron/terminal-context.cjs');
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'benjamin-tracking-'));
  try {
    const user = path.join(temp, 'user'), target = path.join(temp, 'space café');
    await fs.mkdir(user); await fs.mkdir(target);
    const rc = "PROMPT='%F{magenta}custom%f> '\nprecmd() { print -r -- \"USER_STATUS:$?\"; }\n";
    await fs.writeFile(path.join(user, '.zshrc'), rc);
    const env = await shellEnvironment({ shell: '/bin/zsh', env: { ...process.env, ZDOTDIR: user, BENJAMIN_INTEGRATION_TOKEN: 'test-token' }, home: temp, userData: path.join(temp, 'data') });
    const result = spawnSync('/bin/zsh', ['-l', '-i'], { cwd: temp, env, input: "(exit 7)\ncd 'space café'\nprintf 'hello café\\n'\nexit\n", encoding: 'utf8', timeout: 10000 });
    assert.equal(result.status, 0, result.stderr);
    const tracker = new TerminalContext('test-token', temp, true), states = []; let visible = '';
    tracker.push(result.stdout, chunk => visible += chunk, state => states.push(state));
    assert.ok(states.some(state => state.last?.exitCode === 7));
    const resolvedTarget = await fs.realpath(target);
    assert.ok(states.some(state => state.cwd === resolvedTarget));
    assert.ok(states.some(state => state.last?.command.includes('hello café')));
    assert.match(visible, /hello café/); assert.match(visible, /USER_STATUS:7/);
    assert.equal(await fs.readFile(path.join(user, '.zshrc'), 'utf8'), rc);
  } finally { await fs.rm(temp, { recursive: true, force: true }); }
});
