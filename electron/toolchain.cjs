const { spawn } = require('node:child_process');
const fs = require('node:fs/promises');
const path = require('node:path');
const { randomUUID } = require('node:crypto');

const DEFAULT_PATH = '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin';
const SHELLS = new Set(['zsh', 'bash', 'fish']);
// Keep only real absolute directories outside the workspace. A directory the
// agent can write to without review must not decide what an approved command
// name runs, and a relative entry would follow the command's working directory.
async function usablePath(value, root) {
  const kept = [];
  for (const entry of value.split(':').slice(0, 200)) {
    if (!path.isAbsolute(entry) || entry.length > 1000 || /[\0\r\n]/.test(entry) || kept.includes(entry)) continue;
    try {
      const real = await fs.realpath(entry);
      if (real === root || real.startsWith(root + path.sep) || !(await fs.stat(real)).isDirectory()) continue;
    } catch { continue; }
    kept.push(entry);
  }
  if (!kept.length) return '';
  const joined = [...kept, ...DEFAULT_PATH.split(':').filter(entry => !kept.includes(entry))].join(':');
  return joined.length > 16000 ? '' : joined;
}
// Ask the user's own login shell where their tools are, as a terminal tab
// would start it. Only PATH is read back, between random markers; no other
// variable or startup output reaches agent commands. Resolves to '' (use
// DEFAULT_PATH) on any failure and never rejects.
function loginPath({ shell, root, env, timeout = 5000 }) {
  if (process.platform === 'win32' || typeof shell !== 'string' || !path.isAbsolute(shell) || !SHELLS.has(path.basename(shell))) return Promise.resolve('');
  return new Promise(resolve => {
    const marker = randomUUID();
    let output = '', settled = false, child;
    const settle = () => {
      if (settled) return; settled = true;
      const end = output.lastIndexOf(marker), start = end > 0 ? output.lastIndexOf(marker, end - 1) : -1;
      (start === -1 ? Promise.resolve('') : usablePath(output.slice(start + marker.length, end), root)).then(resolve, () => resolve(''));
    };
    // Its own session: an interactive shell must not take over the terminal
    // Benjamin was launched from, and the whole group can be stopped.
    try { child = spawn(shell, ['-i', '-l', '-c', `command printf '%s%s%s' ${marker} "$PATH" ${marker}`], { cwd: root, env, detached: true, stdio: ['ignore', 'pipe', 'ignore'] }); }
    catch { return resolve(''); }
    const kill = () => { try { process.kill(-child.pid, 'SIGKILL'); } catch {} };
    const timer = setTimeout(() => { kill(); settle(); }, timeout);
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', chunk => {
      if (output.length < 200000) output += chunk;
      // Startup files may leave helpers holding the pipe open; do not wait for them.
      if (output.indexOf(marker) !== output.lastIndexOf(marker)) settle();
    });
    child.once('error', () => { clearTimeout(timer); settle(); });
    child.once('exit', () => { clearTimeout(timer); kill(); });
    child.once('close', settle);
  });
}
module.exports = { DEFAULT_PATH, loginPath, usablePath };
