const { app, BrowserWindow, ipcMain, dialog, safeStorage, Menu } = require('electron');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const { randomUUID } = require('node:crypto');
const pty = require('node-pty');
const { TerminalContext } = require('./terminal-context.cjs');
const { shellEnvironment } = require('./shell.cjs');
const { validateEndpointUrl, validateSettings, streamCompletion, discoverModels, scanLocalRuntimes, testModelConnection } = require('./provider.cjs');
const { runAgent, ApprovalGate, PLAYBOOKS } = require('./agent.cjs');
const { loadDashboard } = require('./reliability.cjs');
const { runReliabilityChecks } = require('./reliability-checks.cjs');
const { cleanMessages, agentHistory } = require('./history.cjs');
const { restoreBackup } = require('./agent-tools.cjs');
const { loginPath } = require('./toolchain.cjs');
const { DEFAULT_SCOPE, validateScopeConfig, redactSecrets } = require('./cyber-scope.cjs');
const { detectSecurityTools } = require('./cyber-toolchain.cjs');
const { scanWorkspaceDna, reconcileWorkspaceFindings, buildWorkspaceGraphs } = require('./cyber-analyzers.cjs');
const { createFindingsStore, toMarkdownReport, toSarifReport } = require('./findings.cjs');
const approvals = new ApprovalGate();
let folderChosen = false;
const backupDir = () => dataFile('agent-backups');
app.setName('Marlowe');
if (process.env.BENJAMIN_TEST_DATA) app.setPath('userData', process.env.BENJAMIN_TEST_DATA);
let win, settings, scope = { ...DEFAULT_SCOPE }, findingsStore, apiKey = '', history = [], folder = os.homedir(), toolPath = Promise.resolve(''), activeRequest, activeRunId, checksRunning = false;
const sessions = new Map();
const terminalContexts = new Map();
const entry = path.join(__dirname, '../dist/index.html');
const defaults = { baseUrl: 'https://api.openai.com/v1', model: 'gpt-4.1', encryptedKey: '' };
const dataFile = name => path.join(app.getPath('userData'), name);
async function readJson(name, fallback) { try { return JSON.parse(await fs.readFile(dataFile(name), 'utf8')); } catch { return fallback; } }
async function writeJson(name, value) {
  await fs.mkdir(app.getPath('userData'), { recursive: true });
  const temp = dataFile(`${name}.tmp`);
  await fs.writeFile(temp, JSON.stringify(value, null, 2), { mode: 0o600 });
  await fs.rename(temp, dataFile(name));
}
function publicSettings() { return { baseUrl: settings.baseUrl, model: settings.model, hasKey: !!apiKey, secureStorage: safeStorage.isEncryptionAvailable() }; }
function send(channel, value) { if (win && !win.isDestroyed()) win.webContents.send(channel, value); }
function handle(channel, fn) {
  ipcMain.handle(channel, (event, ...args) => {
    if (!win || event.sender !== win.webContents || event.senderFrame !== win.webContents.mainFrame || event.senderFrame.url !== pathToFileURL(entry).href) throw new Error('Untrusted request');
    return fn(...args);
  });
}
function terminal(id) { const session = sessions.get(id); if (!session) throw new Error('This shell has ended. Open a new terminal.'); return session; }
async function usableWorkspaceDir(candidate) {
  if (typeof candidate !== 'string' || !path.isAbsolute(candidate)) return null;
  try {
    const real = await fs.realpath(candidate);
    if (real === path.parse(real).root || real === os.homedir()) return null;
    return (await fs.stat(real)).isDirectory() ? real : null;
  } catch { return null; }
}
async function activateWorkspace(nextFolder) {
  folder = nextFolder;
  folderChosen = true;
  const { BENJAMIN_TEST_DATA, ELECTRON_RUN_AS_NODE, ...env } = process.env;
  toolPath = loginPath({ shell: process.env.SHELL || '/bin/zsh', root: folder, env });
  await writeJson('workspace.json', { folder });
  send('findings:changed', await findingsStore.list(folder));
  return folder;
}
function dimensions(cols, rows) {
  if (!Number.isInteger(cols) || !Number.isInteger(rows) || cols < 2 || cols > 500 || rows < 1 || rows > 300) throw new Error('Invalid terminal dimensions.');
}
function registerHandlers() {
  handle('reliability:read', async () => ({ ...await loadDashboard(dataFile('agent-runs'), activeRunId), checks: await readJson('reliability-checks.json', null) }));
  handle('reliability:check', async () => {
    if (activeRequest || checksRunning) throw new Error('Wait for the current run or checks to finish.');
    checksRunning = true;
    try {
      const report = await runReliabilityChecks(app.getVersion());
      const previous = await readJson('reliability-checks.json', []);
      const reports = [report, ...(Array.isArray(previous) ? previous : [previous])].filter(Boolean).slice(0, 20);
      await writeJson('reliability-checks.json', reports); return reports;
    }
    finally { checksRunning = false; }
  });
  handle('app:boot', async () => ({
    settings: publicSettings(), scope, findings: folderChosen ? await findingsStore.list(folder) : [],
    history, folder, folderChosen, platform: process.platform, shell: path.basename(process.env.SHELL || '/bin/zsh')
  }));
  handle('app:folder', async () => {
    if (activeRequest) throw new Error('Stop the active run before changing workspace.');
    const result = await dialog.showOpenDialog(win, { properties: ['openDirectory'], title: 'Choose a Marlowe workspace' });
    if (result.canceled) return null;
    if (activeRequest) throw new Error('A run started while the folder picker was open. Try again after it finishes.');
    const chosen = await usableWorkspaceDir(result.filePaths[0]);
    if (!chosen) throw new Error('Choose a specific project folder rather than your Home directory or disk root.');
    return activateWorkspace(chosen);
  });
  handle('app:adopt-cwd', async sessionId => {
    if (activeRequest) return null;
    const cwd = terminalContexts.get(sessionId)?.state()?.cwd;
    const chosen = await usableWorkspaceDir(cwd);
    if (!chosen) return null;
    return activateWorkspace(chosen);
  });
  handle('cyber:scope-get', () => scope);
  handle('cyber:scope-save', async input => {
    if (activeRequest) throw new Error('Stop the active run before changing Authorized Scope.');
    scope = validateScopeConfig(input);
    await writeJson('scope.json', scope);
    return scope;
  });
  handle('cyber:toolchain', async () => {
    let resolved = await toolPath;
    if (!resolved) {
      const { BENJAMIN_TEST_DATA, ELECTRON_RUN_AS_NODE, ...env } = process.env;
      resolved = await loginPath({ shell: process.env.SHELL || '/bin/zsh', root: folderChosen ? folder : os.homedir(), env });
      if (resolved) toolPath = Promise.resolve(resolved);
    }
    return detectSecurityTools(resolved, { root: folderChosen ? folder : '' });
  });
  handle('cyber:dna', async () => {
    if (!folderChosen) return { workspace: '', files: [], summary: { totalFiles: 0, peakEntropy: 0, highEntropyCount: 0, hotspotCount: 0, readyEngines: [], readyCount: 0, totalEngines: 9 }, needsWorkspace: true };
    let resolved = await toolPath;
    if (!resolved) {
      const { BENJAMIN_TEST_DATA, ELECTRON_RUN_AS_NODE, ...env } = process.env;
      resolved = await loginPath({ shell: process.env.SHELL || '/bin/zsh', root: folder, env });
      if (resolved) toolPath = Promise.resolve(resolved);
    }
    const [doctor, reconciled] = await Promise.all([
      detectSecurityTools(resolved, { root: folder }),
      reconcileWorkspaceFindings(folder, findingsStore)
    ]);
    if (reconciled.mitigatedCount > 0) send('findings:changed', reconciled.findings);
    const dna = await scanWorkspaceDna(folder, { findings: reconciled.findings, tools: doctor.tools });
    return { ...dna, autoMitigated: reconciled.mitigatedCount };
  });
  handle('cyber:graphs', async () => {
    let resolved = await toolPath;
    if (!resolved) {
      const { BENJAMIN_TEST_DATA, ELECTRON_RUN_AS_NODE, ...env } = process.env;
      resolved = await loginPath({ shell: process.env.SHELL || '/bin/zsh', root: folderChosen ? folder : os.homedir(), env });
      if (resolved) toolPath = Promise.resolve(resolved);
    }
    const doctor = await detectSecurityTools(resolved, { root: folderChosen ? folder : '' });
    if (!folderChosen) {
      return buildWorkspaceGraphs('', { findings: [], tools: doctor.tools, scope });
    }
    const reconciled = await reconcileWorkspaceFindings(folder, findingsStore);
    if (reconciled.mitigatedCount > 0) send('findings:changed', reconciled.findings);
    return buildWorkspaceGraphs(folder, { findings: reconciled.findings, tools: doctor.tools, scope });
  });
  handle('cyber:redact', text => {
    if (typeof text !== 'string' || text.length > 32000) throw new Error('Invalid text for secret redaction.');
    return redactSecrets(text);
  });
  handle('findings:list', () => folderChosen ? findingsStore.list(folder) : []);
  handle('findings:update', async (id, patch) => {
    if (!folderChosen) throw new Error('Choose a workspace folder first.');
    const updated = await findingsStore.update(folder, id, patch);
    send('findings:changed', updated);
    return updated;
  });
  handle('findings:delete', async id => {
    if (!folderChosen) throw new Error('Choose a workspace folder first.');
    const updated = await findingsStore.remove(folder, id);
    send('findings:changed', updated);
    return updated;
  });
  handle('findings:clear', async () => {
    if (!folderChosen) throw new Error('Choose a workspace folder first.');
    const updated = await findingsStore.clear(folder);
    send('findings:changed', updated);
    return updated;
  });
  handle('findings:export', async format => {
    if (!folderChosen) throw new Error('Choose a workspace folder before exporting a security report.');
    const kind = ['markdown', 'sarif', 'json'].includes(format) ? format : 'markdown';
    const ext = kind === 'sarif' ? 'sarif.json' : kind === 'json' ? 'json' : 'md';
    const picked = await dialog.showSaveDialog(win, {
      title: 'Export Marlowe Security Report',
      defaultPath: path.join(folder, `marlowe-security-report.${ext}`)
    });
    if (picked.canceled || !picked.filePath) return { canceled: true };
    const list = await findingsStore.list(folder);
    const generatedAt = new Date().toISOString();
    const content = kind === 'sarif'
      ? JSON.stringify(toSarifReport({ workspace: folder, findings: list, appVersion: app.getVersion(), generatedAt }), null, 2)
      : kind === 'json'
        ? JSON.stringify({ generator: 'Marlowe Security Workbench', version: app.getVersion(), generatedAt, workspace: folder, scope, findings: list }, null, 2)
        : toMarkdownReport({ workspace: folder, scope, findings: list, appVersion: app.getVersion(), generatedAt });
    await fs.writeFile(picked.filePath, content, { mode: 0o600 });
    return { canceled: false, filePath: picked.filePath, count: list.length, format: kind };
  });
  handle('terminal:create', async () => {
    if (sessions.size >= 8) throw new Error('You can have up to eight terminals open.');
    const id = randomUUID();
    const shell = process.platform === 'win32' ? 'powershell.exe' : process.env.SHELL || '/bin/zsh';
    const token = randomUUID();
    const env = await shellEnvironment({ shell, env: { ...process.env, BENJAMIN_INTEGRATION_TOKEN: token }, home: os.homedir(), userData: app.getPath('userData') });
    // Keep app launch/testing secrets out of interactive shells.
    if (path.basename(shell) !== 'zsh') delete env.BENJAMIN_INTEGRATION_TOKEN;
    delete env.BENJAMIN_TEST_DATA; delete env.ELECTRON_RUN_AS_NODE;
    const proc = pty.spawn(shell, process.platform === 'win32' ? [] : ['-l'], { name: 'xterm-256color', cols: 80, rows: 24, cwd: folder, env });
    sessions.set(id, proc);
    const tracking = new TerminalContext(token, folder, path.basename(shell) === 'zsh');
    terminalContexts.set(id, tracking);
    proc.onData(data => tracking.push(data, output => send('terminal:data', { id, data: output }), state => send('terminal:state', { id, ...state })));
    proc.onExit(({ exitCode }) => { tracking.exit(data => send('terminal:data', { id, data })); send('terminal:state', { id, ...tracking.state() }); sessions.delete(id); send('terminal:exit', { id, exitCode }); });
    return { id, folder, shell: path.basename(shell) };
  });
  handle('terminal:context-menu', (id, selection) => {
    const tracking = terminalContexts.get(id);
    if (!tracking || typeof selection !== 'string' || selection.length > 16000) throw new Error('Invalid terminal selection.');
    const state = tracking.state();
    // Freeze the menu's target; a later shell event must not change what the
    // user chose to review. Nothing here calls a model or changes workspace.
    const snapshots = {
      selection: selection.trim() ? tracking.snapshot('selection', selection) : null,
      last: state.ready && state.last && !state.running ? tracking.snapshot('last') : null,
      failure: state.ready && state.hasFailure && !state.running ? tracking.snapshot('failure') : null
    };
    const choose = kind => { if (snapshots[kind]) send('terminal:context-request', { id, kind, ...snapshots[kind] }); };
    Menu.buildFromTemplate([
      { label: 'Explain selection', enabled: !!selection.trim(), click: () => choose('selection') },
      { label: 'Explain last command', enabled: state.ready && !!state.last && !state.running, click: () => choose('last') },
      { label: 'Help fix this error', enabled: state.ready && state.hasFailure && !state.running, click: () => choose('failure') },
      { type: 'separator' },
      { label: state.running ? 'Command still running — select text to ask about it' : state.ready ? 'Context stays local until you send it' : 'Command tracking unavailable — select text instead', enabled: false }
    ]).popup({ window: win });
  });
  handle('terminal:state', id => terminalContexts.get(id)?.state() || null);
  handle('terminal:failure-snapshot', (id, maskSecrets = false) => {
    const tracking = terminalContexts.get(id);
    if (!tracking) throw new Error('Terminal session not found.');
    const snap = tracking.snapshot('failure');
    if (!maskSecrets) return { ...snap, redactedCount: 0, redactedTypes: [] };
    const masked = redactSecrets(snap.text);
    return { cwd: snap.cwd, text: masked.text, redactedCount: masked.count, redactedTypes: masked.types };
  });
  handle('terminal:write', (id, data) => {
    if (typeof data !== 'string' || data.length > 100000) throw new Error('Terminal input is too large.');
    terminal(id).write(data);
  });
  handle('terminal:resize', (id, cols, rows) => { dimensions(cols, rows); terminal(id).resize(cols, rows); });
  handle('terminal:close', id => { sessions.get(id)?.kill(); sessions.delete(id); terminalContexts.delete(id); });
  handle('settings:save', async input => {
    const validated = validateSettings(input);
    let nextKey = apiKey;
    if (input.clearKey) nextKey = '';
    else if (typeof input.apiKey === 'string' && input.apiKey.trim()) nextKey = input.apiKey.trim();
    // Never forward an existing credential to a newly selected server.
    if (validated.baseUrl !== settings.baseUrl && !input.apiKey?.trim()) nextKey = '';
    if (nextKey.length > 8192) throw new Error('API key is too long.');
    if (nextKey && !safeStorage.isEncryptionAvailable()) throw new Error('OS encryption is unavailable; an API key cannot be saved securely.');
    const next = { ...validated, encryptedKey: nextKey ? safeStorage.encryptString(nextKey).toString('base64') : '' };
    await writeJson('settings.json', next);
    settings = next; apiKey = nextKey;
    return publicSettings();
  });
  handle('settings:radar', () => scanLocalRuntimes());
  handle('settings:discover', async input => {
    const cleanUrl = validateEndpointUrl(input?.baseUrl);
    const typedKey = typeof input?.apiKey === 'string' && input.apiKey.trim() ? input.apiKey.trim() : '';
    if (typedKey.length > 8192) throw new Error('API key is too long.');
    // Never forward saved API key to a different base URL.
    const effectiveKey = input?.clearKey ? '' : (typedKey || (cleanUrl === settings.baseUrl ? apiKey : ''));
    return discoverModels({ baseUrl: cleanUrl, apiKey: effectiveKey });
  });
  handle('settings:test', async input => {
    const validated = validateSettings(input);
    const typedKey = typeof input?.apiKey === 'string' && input.apiKey.trim() ? input.apiKey.trim() : '';
    if (typedKey.length > 8192) throw new Error('API key is too long.');
    const effectiveKey = input?.clearKey ? '' : (typedKey || (validated.baseUrl === settings.baseUrl ? apiKey : ''));
    return testModelConnection({ ...validated, apiKey: effectiveKey });
  });
  let historyWrites = Promise.resolve();
  handle('history:save', value => {
    const clean = cleanMessages(value);
    historyWrites = historyWrites.catch(() => {}).then(async () => { await writeJson('conversation.json', clean); history = clean; });
    return historyWrites;
  });
  handle('chat:start', async input => {
    if (activeRequest || checksRunning) throw new Error('A response or reliability check is already in progress.');
    if (typeof input.id !== 'string' || input.id.length > 100) throw new Error('Invalid request.');
    const messages = cleanMessages(input.messages);
    if (typeof input.context !== 'string' || input.context.length > 16000) throw new Error('Invalid terminal context.');
    const agent = input.mode === 'agent';
    const playbook = typeof input.playbook === 'string' && Object.hasOwn(PLAYBOOKS, input.playbook) ? input.playbook : 'general';
    if (agent && (!folderChosen || folder === path.parse(folder).root || folder === os.homedir())) throw new Error('Choose a project folder before using Agent mode; the home directory and disk root are too broad.');
    const runRoot = folder, runPath = toolPath, runScope = { ...scope, targets: [...scope.targets] };
    const controller = new AbortController();
    activeRequest = controller; activeRunId = input.id;
    const timeout = setTimeout(() => controller.abort(new Error(agent ? 'Agent run timed out after 30 minutes.' : 'Response timed out after two minutes.')), agent ? 1800000 : 120000);
    try {
      if (agent) {
        const logs = dataFile('agent-runs');
        await fs.mkdir(logs, { recursive: true, mode: 0o700 });
        const agentRunId = randomUUID();
        const logPath = path.join(logs, `${agentRunId}.jsonl`);
        const modelHistory = await agentHistory(messages, runRoot, id => readJson(`agent-runs/${id}.context.json`, null));
        const saveTranscript = transcript => writeJson(`agent-runs/${agentRunId}.context.json`, { version: 1, root: runRoot, messages: transcript });
        const audit = event => fs.appendFile(logPath, JSON.stringify({ time: new Date().toISOString(), ...event }) + '\n', { mode: 0o600 });
        const commandPath = await runPath;
        const doctor = await detectSecurityTools(commandPath, { root: runRoot }).catch(() => ({ tools: [] }));
        const availableScanners = doctor.tools.filter(t => t.available && t.profiles?.length).map(t => t.id);
        await audit({ status: 'started', runId: input.id, workspace: runRoot, model: settings.model, playbook, appVersion: app.getVersion(), telemetryVersion: 1, commandPath: commandPath || 'default' });
        try {
          const result = await runAgent({
            id: input.id, root: runRoot, settings: { ...settings }, apiKey, messages: modelHistory, context: input.context,
            signal: controller.signal, playbook, scope: runScope, findingsStore, availableScanners,
            onFinding: async () => send('findings:changed', await findingsStore.list(runRoot)),
            onHistory: saveTranscript,
            onToken: token => send('chat:token', { id: input.id, token }),
            onEvent: event => send('agent:event', event),
            approve: action => approvals.wait(action, controller.signal, event => send('agent:event', { ...event, status: 'awaiting-approval' })),
            backupDir: backupDir(), commandPath, audit
          });
          await audit({ status: 'finished' });
          return { ...result, agentRunId };
        } catch (error) { await audit({ status: controller.signal.aborted ? 'stopped' : 'error', message: error.message }); return { agentRunId, ...(controller.signal.aborted ? { stopped: true, reason: controller.signal.reason?.message || 'Stopped' } : { error: error.message }) }; }
      }
      const content = await streamCompletion({ settings, apiKey, messages, context: input.context, signal: controller.signal, onToken: token => send('chat:token', { id: input.id, token }) });
      return { content };
    } catch (error) {
      if (controller.signal.aborted) return { stopped: true, reason: controller.signal.reason?.message || 'Stopped' };
      throw error;
    } finally { clearTimeout(timeout); activeRequest = null; activeRunId = null; }
  });
  handle('chat:stop', () => activeRequest?.abort());
  handle('agent:approve', (runId, approvalId, approve) => approvals.decide(runId, approvalId, approve));
  handle('agent:restore', async id => {
    if (activeRequest) throw new Error('Wait for the agent run to finish before restoring files.');
    async function recordUndo(status, message) {
      try {
        const logs = dataFile('agent-runs');
        const files = (await fs.readdir(logs, { withFileTypes: true })).filter(file => file.isFile() && /^[0-9a-f-]{36}\.jsonl$/i.test(file.name));
        for (const file of files) {
          const filePath = path.join(logs, file.name);
          const stat = await fs.stat(filePath); if (stat.size > 8_000_000) continue;
          const lines = (await fs.readFile(filePath, 'utf8')).split('\n');
          if (lines.some(line => { try { return JSON.parse(line).result?.backupId === id; } catch { return false; } })) {
            await fs.appendFile(filePath, JSON.stringify({ time: new Date().toISOString(), status, backupId: id, ...(message ? { message } : {}) }) + '\n'); break;
          }
        }
      } catch { /* Telemetry must not change the restore outcome. */ }
    }
    try { const result = await restoreBackup(backupDir(), id); await recordUndo('undo-completed'); return result; }
    catch (error) { await recordUndo('undo-error', error.message); throw error; }
  });
}
function createWindow() {
  win = new BrowserWindow({ width: 1440, height: 940, minWidth: 940, minHeight: 650, title: 'Marlowe. — Zero Theory Labs', backgroundColor: '#131210', titleBarStyle: 'hiddenInset', trafficLightPosition: { x: 20, y: 23 }, webPreferences: { preload: path.join(__dirname, 'preload.cjs'), contextIsolation: true, nodeIntegration: false, sandbox: true } });
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  win.webContents.on('will-navigate', event => event.preventDefault());
  win.webContents.session.setPermissionRequestHandler((_wc, _permission, callback) => callback(false));
  win.webContents.on('render-process-gone', cleanup);
  win.webContents.on('did-start-loading', () => activeRequest?.abort());
  win.on('closed', () => { cleanup(); win = null; });
  win.loadFile(entry);
}
function cleanup() { activeRequest?.abort(); for (const session of sessions.values()) session.kill(); sessions.clear(); terminalContexts.clear(); }
async function migrateLegacyData() {
  if (process.env.BENJAMIN_TEST_DATA) return;
  try { await fs.access(dataFile('settings.json')); return; } catch {}
  const legacyDir = path.join(app.getPath('appData'), 'Benjamin');
  try { await fs.access(legacyDir); } catch { return; }
  await fs.mkdir(app.getPath('userData'), { recursive: true });
  for (const name of ['settings.json', 'workspace.json', 'scope.json', 'conversation.json', 'findings']) {
    try { await fs.cp(path.join(legacyDir, name), dataFile(name), { recursive: true, force: false }); } catch {}
  }
}
app.whenReady().then(async () => {
  await migrateLegacyData();
  findingsStore = createFindingsStore(dataFile('findings'));
  settings = await readJson('settings.json', defaults);
  try { validateSettings(settings); } catch { settings = defaults; }
  try { scope = validateScopeConfig(await readJson('scope.json', DEFAULT_SCOPE)); } catch { scope = { ...DEFAULT_SCOPE }; }
  const savedWorkspace = await usableWorkspaceDir((await readJson('workspace.json', null))?.folder);
  if (savedWorkspace) {
    folder = savedWorkspace;
    folderChosen = true;
    const { BENJAMIN_TEST_DATA, ELECTRON_RUN_AS_NODE, ...env } = process.env;
    toolPath = loginPath({ shell: process.env.SHELL || '/bin/zsh', root: folder, env });
  }
  try { if (settings.encryptedKey && safeStorage.isEncryptionAvailable()) apiKey = safeStorage.decryptString(Buffer.from(settings.encryptedKey, 'base64')); } catch { apiKey = ''; }
  try { history = cleanMessages(await readJson('conversation.json', [])); } catch { history = []; }
  registerHandlers();
  Menu.setApplicationMenu(Menu.buildFromTemplate([
    ...(process.platform === 'darwin' ? [{ label: 'Marlowe', submenu: [{ role: 'about' }, { type: 'separator' }, { role: 'hide' }, { role: 'quit' }] }] : []),
    { label: 'Edit', submenu: [{ role: 'undo' }, { role: 'redo' }, { type: 'separator' }, { role: 'cut' }, { role: 'copy' }, { role: 'paste' }, { role: 'selectAll' }] },
    { label: 'View', submenu: [{ role: 'toggleDevTools' }, { role: 'resetZoom' }, { role: 'zoomIn' }, { role: 'zoomOut' }, { role: 'togglefullscreen' }] },
    { label: 'Window', submenu: [{ role: 'minimize' }, { role: 'close' }] }
  ]));
  createWindow();
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});
app.on('before-quit', cleanup);
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
