const fs = require('node:fs/promises');
const path = require('node:path');

async function shellEnvironment({ shell, env, home, userData }) {
  const result = { ...env, TERM: 'xterm-256color', COLORTERM: 'truecolor', TERM_PROGRAM: 'Marlowe', TERM_PROGRAM_VERSION: '0.4.0' };
  if (!Object.hasOwn(result, 'NO_COLOR')) {
    result.CLICOLOR = result.CLICOLOR || '1';
    result.LSCOLORS = result.LSCOLORS || 'exfxcxdxbxegedabagacad';
    result.LS_COLORS = result.LS_COLORS || 'di=34:ln=35:ex=32:pi=33:so=36:bd=33:cd=33:or=31:*.zip=35:*.gz=35:*.tar=35';
  }
  if (path.basename(shell) !== 'zsh') return result;
  // Source the user's normal login files, then style this session only. Files
  // must be outside app.asar because the shell reads them directly from disk.
  const directory = path.join(userData, 'shell', 'zsh');
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  await fs.copyFile(path.join(__dirname, 'shell/colors.zsh'), path.join(directory, 'colors.zsh'));
  await fs.copyFile(path.join(__dirname, 'shell/integration.zsh'), path.join(directory, 'integration.zsh'));
  for (const stage of ['.zshenv', '.zprofile', '.zshrc', '.zlogin']) {
    const script = `# Generated Benjamin startup shim.\nZDOTDIR=$BENJAMIN_USER_ZDOTDIR\n[[ -f "$ZDOTDIR/${stage}" ]] && source "$ZDOTDIR/${stage}"\nBENJAMIN_USER_ZDOTDIR=\${ZDOTDIR:-$HOME}\n` +
      (stage === '.zlogin' ? 'source "$BENJAMIN_SHELL_DIR/colors.zsh"\nsource "$BENJAMIN_SHELL_DIR/integration.zsh"\nunset BENJAMIN_USER_ZDOTDIR BENJAMIN_SHELL_DIR\n' : 'ZDOTDIR=$BENJAMIN_SHELL_DIR\n');
    await fs.writeFile(path.join(directory, stage), script, { mode: 0o600 });
  }
  result.BENJAMIN_USER_ZDOTDIR = env.ZDOTDIR || home;
  result.BENJAMIN_SHELL_DIR = directory;
  result.ZDOTDIR = directory;
  return result;
}
module.exports = { shellEnvironment };
