import { conversationTerminal } from './benjamin-terminal.mjs';
import { setupReliability } from './reliability.js';
import { setupCyber } from './cyber.js';
import { setupStageGraphs } from './stage-graphs.js';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import './styles.css';
import { initializeTheme, terminalTheme } from './theme.js';

const api = window.benjamin;
setupReliability(api);
const $ = id => document.getElementById(id);
const terminals = new Map();
const pendingData = new Map();
let stagedContext = null, contextReview = null;
let activeTerminal, config, messages = [], request = null, toastTimer, mode = 'chat', playbook = 'general', folderChosen = false, workspace = '';
let activeScope = { targets: [], allowOsv: true, redactContext: true };
let drawerOpen = true, activeRightTab = 'assistant', split = 64;
const dismissedFailures = new Map();
const actionCards = new Map();
let stageGraphs = null;

initializeTheme(() => {
  for (const session of terminals.values()) session.term.options.theme = terminalTheme();
  stageGraphs?.rerenderTheme();
});

function notify(message) { $('toast').textContent = message; $('toast').hidden = false; clearTimeout(toastTimer); toastTimer = setTimeout(() => $('toast').hidden = true, 6000); }
function errorMessage(error) { return error.message?.replace(/^Error invoking remote method '[^']+': Error: /, '') || String(error); }
function caught(fn) { return (...args) => Promise.resolve().then(() => fn(...args)).catch(error => notify(errorMessage(error))); }
function el(tag, className, text) { const node = document.createElement(tag); if (className) node.className = className; if (text !== undefined) node.textContent = text; return node; }

function switchRightTab(tab) {
  activeRightTab = tab;
  if (!drawerOpen) setDrawer(true);
  const mapping = [['assistant', 'assistant-tab', 'assistant-view'], ['findings', 'findings-button', 'findings-dialog'], ['dna', 'dna-button', 'dna-dialog'], ['scope', 'scope-button', 'scope-dialog']];
  for (const [key, btnId, viewId] of mapping) {
    const active = key === tab;
    $(btnId)?.classList.toggle('active', active);
    $(btnId)?.setAttribute('aria-selected', String(active));
    if ($(viewId)) $(viewId).hidden = !active;
  }
  $('new-chat').hidden = tab !== 'assistant';
}
$('assistant-tab').addEventListener('click', () => { switchRightTab('assistant'); $('prompt').focus(); });

let pendingToolchainInstallSession = null;
let pendingModelPull = null;

async function runCommandInInteractiveShell(command, noticeText) {
  let shellSession = terminals.get(activeTerminal);
  if (!shellSession || shellSession.conversation || shellSession.exited) {
    shellSession = [...terminals.values()].find(s => !s.conversation && !s.exited);
  }
  if (!shellSession) {
    await createTerminal();
    shellSession = terminals.get(activeTerminal);
  } else {
    activate(shellSession.id);
  }
  await api.writeTerminal(shellSession.id, command + '\r');
  shellSession.term.focus();
  if (noticeText) notify(noticeText);
  return shellSession.id;
}

const cyber = setupCyber(api, {
  notify,
  caught,
  onSwitchTab: switchRightTab,
  onInstallCommand: caught(async command => {
    pendingToolchainInstallSession = await runCommandInInteractiveShell(
      command,
      `Running "${command}" in shell — Toolchain Doctor will refresh automatically when finished.`
    );
  }),
  onScopeUpdated(nextScope) {
    activeScope = nextScope || activeScope;
    updateMode();
    stageGraphs?.refreshIfVisible();
  },
  onDraftFix: draftFixForFinding,
  onDraftShield: draftShieldForFinding,
  onAuditFile: auditWorkspaceFile
});

function draftFixForFinding(finding) {
  switchRightTab('assistant');
  if (folderChosen) {
    mode = 'agent';
    playbook = 'general';
    $('playbook-select').value = 'general';
    updateMode();
  }
  const lineMatch = /^(.+?):(\d+)/.exec(finding.location || '');
  const lineHint = lineMatch ? ` around start_line ${Math.max(1, Number(lineMatch[2]) - 35)} (line_count 90)` : '';
  const isTaintSink = /^(?:CWE-78|CWE-79|CWE-89|CWE-94|CWE-502|CWE-918)$/i.test(finding.cwe || '');
  const statusHint = finding.id
    ? ` After applying a real code fix, call update_finding_status (finding_id: "${finding.id}", status: "mitigated").${isTaintSink ? ` Only if reading the code proves this sink renders hardcoded static constants with zero untrusted external/user input, call update_finding_status (finding_id: "${finding.id}", status: "false-positive") instead of editing.` : ''}`
    : '';
  $('prompt').value = `Remediate finding [${finding.severity.toUpperCase()}] "${finding.title}"${finding.cwe ? ' (' + finding.cwe + ')' : ''} at ${finding.location}. Read the relevant section with read_file${lineHint} (and search_text if the sink is further down in a large file), then call edit_file to apply a minimal safe code fix.${statusHint}`;
  $('prompt').focus();
}

function draftShieldForFinding(finding) {
  switchRightTab('assistant');
  if (folderChosen) {
    mode = 'agent';
    playbook = 'upatch';
    $('playbook-select').value = 'upatch';
    updateMode();
  }
  $('prompt').value = `Draft a temporary Shirudo runtime shield (Beefile + scoped Plain BPF C .bpf.c upatch) under shirudo-shields/ to mitigate finding [${finding.severity.toUpperCase()}] "${finding.title}"${finding.cwe ? ' (' + finding.cwe + ')' : ''} at ${finding.location}. Inspect ${finding.location} with read_file first, scope the upatch with explicit [upatches.tree.selector.labels] and SEC("license"), pause at Marlowe's approval gate for review, and validate the draft with audit_shirudo_upatch. Never read or write operator signing keys or push/load shields automatically.`;
  $('prompt').focus();
}

function auditWorkspaceFile(fileItem) {
  switchRightTab('assistant');
  if (folderChosen) {
    mode = 'agent';
    playbook = fileItem.kind === 'binary' || fileItem.kind === 'capture' ? 'dfir' : 'appsec';
    $('playbook-select').value = playbook;
    updateMode();
  }
  const engines = Array.isArray(fileItem.engines) ? fileItem.engines : (fileItem.engineIds || []);
  const openHint = Array.isArray(fileItem.openFindingIds) && fileItem.openFindingIds.length
    ? ` Existing open finding ID(s) on this file: ${fileItem.openFindingIds.join(', ')}. If your code inspection and local scanners confirm any listed finding is a false positive (static constants / no untrusted input) or already remediated, call update_finding_status for each ID with "false-positive" or "mitigated" so the Findings badge and DNA node clear.`
    : '';
  $('prompt').value = fileItem.kind === 'binary' || fileItem.kind === 'capture'
    ? `Run deep forensic & binary triage on "${fileItem.path}" (measured Shannon entropy ${fileItem.entropy} bits/byte). Use triage_artifact, extract_iocs, or analyze_logs as appropriate, and record only verified threats.${openHint}`
    : `Perform a targeted security & secret audit of "${fileItem.path}" (Shannon entropy ${fileItem.entropy} bits/byte; engines: ${engines.join(', ')}). Read the file to verify real untrusted-input reachability and record any confirmed vulnerabilities.${openHint}`;
  $('prompt').focus();
}

function renderFailureHud() {
  const hud = $('failure-hud');
  if (!hud) return;
  const session = terminals.get(activeTerminal);
  const last = session?.tracking?.last;
  if (!session || session.conversation || session.exited || !session.tracking?.ready || session.tracking.running || !last || last.exitCode === 0 || last.interrupted || dismissedFailures.get(session.id) === last.sequence) {
    hud.hidden = true;
    return;
  }
  const cmd = (last.commandPreview || last.command || 'command').replace(/\s+/g, ' ').trim();
  $('failure-hud-title').textContent = `EXIT ${last.exitCode} · ${cmd.length > 54 ? cmd.slice(0, 54) + '…' : cmd}`;
  const secrets = last.secretCount || 0;
  const tag = $('failure-hud-secrets');
  tag.hidden = secrets === 0;
  if (secrets > 0) tag.textContent = `${secrets} secret${secrets === 1 ? '' : 's'} in output`;
  $('failure-diagnose').textContent = secrets > 0 ? 'Mask Secret & Help Fix' : 'Help Fix Error';
  hud.hidden = false;
}

function setFolder(folder) {
  workspace = folder;
  $('folder-name').textContent = folder.split(/[\\/]/).filter(Boolean).at(-1) || folder;
  $('choose-folder').title = `Workspace: ${folder} (click to switch project)`;
}
function fit(session) { if (!session || session.exited) return; session.fit.fit(); if (session.conversation) return; api.resizeTerminal(session.id, session.term.cols, session.term.rows).catch(() => {}); }
function activate(id) {
  activeTerminal = id;
  const isGraph = stageGraphs?.isGraphId(id);
  for (const [key, session] of terminals) {
    const active = !isGraph && key === id;
    session.host.classList.toggle('inactive', !active);
    session.tab.classList.toggle('active', active);
    session.select.setAttribute('aria-selected', String(active));
  }
  if (isGraph) {
    stageGraphs.activate(id);
    $('shell-status').textContent = id === 'convergence' ? 'Marlowe · 10-CLI Convergence' : 'Marlowe · Attack Reachability';
    $('shell-path').textContent = folderChosen ? workspace : '';
    $('shell-path').title = folderChosen ? `Workspace: ${workspace}` : '';
    $('shell-dot').style.background = '';
    renderFailureHud();
    return;
  }
  stageGraphs?.deactivateAll();
  const session = terminals.get(id);
  renderTerminalStatus(session);
  renderFailureHud();
  $('shell-dot').style.background = session && !session.exited ? '' : 'var(--dim)';
  if (session) { fit(session); session.term.focus(); }
}
function renderTerminalStatus(session) {
  if (session?.conversation) { $('shell-status').textContent = `Marlowe · ${mode === 'agent' && playbook !== 'general' ? 'agent/' + playbook : mode} · ${request ? 'working' : 'ready'}`; $('shell-path').textContent = workspace; $('shell-path').title = 'Agent workspace; shell tabs keep their own directory'; return; }
  $('shell-status').textContent = session ? (session.exited ? `Shell exited (${session.exitCode})` : `${session.shell} · ${session.tracking?.running ? 'running' : 'interactive'}`) : 'No active terminal';
  $('shell-path').textContent = session?.tracking?.ready ? session.tracking.cwd : session?.folder || '';
  $('shell-path').title = (session?.tracking?.ready ? 'Current directory: ' : 'Starting directory (tracking unavailable): ') + $('shell-path').textContent;
}
api.onTerminalState(state => {
  const session = terminals.get(state.id); if (!session) return;
  const wasRunning = Boolean(session.tracking?.running);
  session.tracking = state;
  if (activeTerminal === state.id) { renderTerminalStatus(session); renderFailureHud(); }
  if (pendingToolchainInstallSession === state.id && wasRunning && !state.running) {
    pendingToolchainInstallSession = null;
    if (state.last?.exitCode === 0) {
      cyber.refreshToolchain();
      notify('Scanner installation finished · Toolchain Doctor updated.');
    }
  }
  if (pendingModelPull?.sessionId === state.id && wasRunning && !state.running) {
    const pulled = pendingModelPull;
    pendingModelPull = null;
    if (state.last?.exitCode === 0) {
      api.saveSettings({ baseUrl: pulled.baseUrl, model: pulled.model, apiKey: '', clearKey: false })
        .then(saved => {
          updateConfig(saved);
          notify(`Pulled and connected ${pulled.model}.`);
        })
        .catch(() => notify(`Pulled ${pulled.model} — select it in Settings.`));
    }
  }
});
async function createTerminal() {
  const session = await api.createTerminal();
  const host = el('div', 'terminal-host');
  host.dataset.session = session.id;
  $('terminal-stage').append(host);
  const term = new Terminal({ cursorBlink: true, cursorStyle: 'bar', fontSize: 12, lineHeight: 1.45, fontFamily: '"Geist Mono", Menlo, monospace', scrollback: 5000, theme: terminalTheme() });
  const fitAddon = new FitAddon(); term.loadAddon(fitAddon); term.open(host);
  const tab = el('div', 'terminal-tab');
  const select = el('button', 'tab-select', `${session.shell} · ${[...terminals.values()].filter(value => !value.conversation).length + 1}`); select.setAttribute('role', 'tab');
  const close = el('button', 'tab-close', '×'); close.setAttribute('aria-label', 'Close terminal');
  tab.append(select, close);
  const logTab = terminals.get('marlowe')?.tab;
  if (logTab) logTab.before(tab); else $('terminal-tabs').append(tab);
  const value = { ...session, term, fit: fitAddon, host, tab, select };
  terminals.set(session.id, value);
  host.addEventListener('contextmenu', event => { event.preventDefault(); api.terminalContextMenu(session.id, term.getSelection().slice(0, 16000)).catch(error => notify(errorMessage(error))); });
  value.tracking = await api.terminalState(session.id);
  select.addEventListener('click', () => activate(session.id));
  close.addEventListener('click', caught(async () => {
    await api.closeTerminal(session.id); term.dispose(); host.remove(); tab.remove(); terminals.delete(session.id);
    $('terminal-count').textContent = terminals.size;
    if (activeTerminal === session.id) activate([...terminals.keys()].at(-1));
    if (!terminals.size) await createTerminal();
  }));
  term.onData(data => api.writeTerminal(session.id, data).catch(error => notify(errorMessage(error))));
  term.attachCustomKeyEventHandler(event => {
    if (event.type === 'keydown' && (event.metaKey || event.ctrlKey) && event.key === ',') { openSettings(); return false; }
    if (event.type === 'keydown' && event.metaKey && event.key.toLowerCase() === 't') { caught(createTerminal)(); return false; }
    if (event.type === 'keydown' && (event.metaKey || (event.ctrlKey && event.shiftKey)) && event.key.toLowerCase() === 'j') { toggleDrawer(); return false; }
    return true;
  });
  for (const data of pendingData.get(session.id) || []) term.write(data);
  pendingData.delete(session.id);
  $('terminal-count').textContent = terminals.size;
  activate(session.id);
}
function marloweSession() {
  let session = terminals.get('marlowe');
  if (session) return session;
  const host = el('div', 'terminal-host'); host.dataset.session = 'marlowe'; $('terminal-stage').append(host);
  const term = new Terminal({ cursorBlink: true, cursorStyle: 'bar', fontSize: 12, lineHeight: 1.35, fontFamily: '"Geist Mono", Menlo, monospace', scrollback: 5000, theme: terminalTheme() });
  const fitAddon = new FitAddon(); term.loadAddon(fitAddon); term.open(host);
  const tab = el('div', 'terminal-tab terminal-tab-log'), select = el('button', 'tab-select', 'Marlowe'); select.setAttribute('role', 'tab');
  tab.append(select); $('terminal-tabs').append(tab);
  session = { id: 'marlowe', folder: workspace, term, fit: fitAddon, host, tab, select };
  session.conversation = conversationTerminal(term, {
    getMode: () => mode,
    stop: () => api.stopChat().catch(error => notify(errorMessage(error))),
    send: text => { submitMessage(text, true).catch(error => notify(errorMessage(error))); }
  });
  terminals.set('marlowe', session);
  select.addEventListener('click', () => activate('marlowe'));
  host.addEventListener('contextmenu', event => {
    event.preventDefault(); const text = term.getSelection().slice(0, 16000);
    if (text) reviewContext({ text, cwd: workspace }, 'selection');
  });
  $('terminal-count').textContent = terminals.size;
  session.conversation.line('MARLOWE. · Security for AI. A little more careful.', 'heading');
  session.conversation.line('Enter to send · Ctrl+C to stop · Press ⌘J to show/hide the side panel', 'muted');
  return session;
}
api.onTerminalData(({ id, data }) => {
  const session = terminals.get(id);
  if (session) session.term.write(data);
  else { const queue = pendingData.get(id) || []; if (queue.length < 100) queue.push(data); pendingData.set(id, queue); }
});
api.onTerminalExit(({ id, exitCode }) => {
  const session = terminals.get(id); if (!session) return;
  session.exited = true; session.exitCode = exitCode;
  session.term.write(`\r\n\x1b[90m[Shell exited with code ${exitCode}. Open a new terminal with +.]\x1b[0m\r\n`);
  if (activeTerminal === id) activate(id);
});
new ResizeObserver(() => fit(terminals.get(activeTerminal))).observe($('terminal-stage'));
function contextText() {
  const session = terminals.get(activeTerminal); if (!session) return '';
  const buffer = session.term.buffer.active; const lines = [];
  for (let i = Math.max(0, buffer.length - 180); i < buffer.length; i++) lines.push(buffer.getLine(i)?.translateToString(true) || '');
  return lines.join('\n').trimEnd().slice(-16000);
}
function updateConfig(value) {
  config = value;
  $('model-button').textContent = config.model;
  let host = '';
  try { host = new URL(config.baseUrl).hostname; } catch {}
  $('connection-status').textContent = config.hasKey ? 'Key saved' : CLOUD_HOSTS_REQUIRING_KEY.has(host) ? 'Add API key' : 'Custom endpoint';
  $('model-button').title = `${config.model} · ${$('connection-status').textContent}`;
}
const PROVIDER_PRESETS = [
  // Local OpenAI-compatible servers (auto-probed via local port radar)
  { id: 'ollama', label: 'Ollama', baseUrl: 'http://127.0.0.1:11434/v1', local: true, keyHint: 'Optional for local Ollama', suggested: [] },
  { id: 'lmstudio', label: 'LM Studio', baseUrl: 'http://127.0.0.1:1234/v1', local: true, keyHint: 'Optional for LM Studio', suggested: [] },
  { id: 'jan', label: 'Jan', baseUrl: 'http://127.0.0.1:1337/v1', local: true, keyHint: 'Optional for local Jan server', suggested: [] },
  { id: 'vllm', label: 'vLLM', baseUrl: 'http://127.0.0.1:8000/v1', local: true, keyHint: 'Optional unless --api-key set', suggested: [] },
  // First-party & frontier cloud providers
  { id: 'anthropic', label: 'Claude', baseUrl: 'https://api.anthropic.com/v1', local: false, keyHint: 'sk-ant-api03-… (Anthropic Console)', suggested: ['claude-sonnet-4-0', 'claude-opus-4-1', 'claude-3-7-sonnet-latest', 'claude-3-5-haiku-latest'] },
  { id: 'openai', label: 'OpenAI', baseUrl: 'https://api.openai.com/v1', local: false, keyHint: 'sk-proj-… (OpenAI Platform)', suggested: ['gpt-4.1', 'o4-mini', 'gpt-4.1-mini', 'gpt-4o'] },
  { id: 'gemini', label: 'Gemini', baseUrl: 'https://generativelanguage.googleapis.com/v1beta/openai', local: false, keyHint: 'AIzaSy… (Google AI Studio)', suggested: ['gemini-2.5-pro', 'gemini-2.5-flash', 'gemini-2.5-flash-lite'] },
  { id: 'xai', label: 'xAI Grok', baseUrl: 'https://api.x.ai/v1', local: false, keyHint: 'xai-… (xAI Console)', suggested: ['grok-3', 'grok-3-mini'] },
  { id: 'deepseek', label: 'DeepSeek', baseUrl: 'https://api.deepseek.com/v1', local: false, keyHint: 'sk-… (DeepSeek Platform)', suggested: ['deepseek-chat', 'deepseek-reasoner'] },
  { id: 'mistral', label: 'Mistral', baseUrl: 'https://api.mistral.ai/v1', local: false, keyHint: 'Mistral / La Plateforme API key', suggested: ['codestral-latest', 'mistral-large-latest', 'devstral-small-latest'] },
  { id: 'groq', label: 'Groq', baseUrl: 'https://api.groq.com/openai/v1', local: false, keyHint: 'gsk_… (GroqCloud)', suggested: ['llama-3.3-70b-versatile', 'qwen-qwq-32b'] },
  { id: 'together', label: 'Together', baseUrl: 'https://api.together.xyz/v1', local: false, keyHint: 'Together AI key', suggested: ['Qwen/Qwen2.5-Coder-32B-Instruct', 'deepseek-ai/DeepSeek-V3'] },
  { id: 'fireworks', label: 'Fireworks', baseUrl: 'https://api.fireworks.ai/inference/v1', local: false, keyHint: 'fw_… (Fireworks AI)', suggested: ['accounts/fireworks/models/deepseek-v3', 'accounts/fireworks/models/qwen2p5-coder-32b-instruct'] },
  { id: 'openrouter', label: 'OpenRouter', baseUrl: 'https://openrouter.ai/api/v1', local: false, keyHint: 'sk-or-v1-… (OpenRouter)', suggested: ['anthropic/claude-sonnet-4', 'google/gemini-2.5-pro', 'qwen/qwen3-coder', 'deepseek/deepseek-chat-v3-0324'] }
];

const CLOUD_HOSTS_REQUIRING_KEY = new Set(
  PROVIDER_PRESETS.filter(p => !p.local).map(p => new URL(p.baseUrl).hostname)
);

const OLLAMA_SECURITY_PICKS = [
  { id: 'qwen2.5-coder:14b', note: '14B Coder · Best balance' },
  { id: 'qwen3:14b', note: '14B Reasoning · Strong tools' },
  { id: 'qwen2.5-coder:32b', note: '32B Coder · Deepest local SAST' }
];

let radarState = new Map();
let discoveredForCurrentUrl = [];

function normalizeUrlKey(raw) {
  try {
    const u = new URL(String(raw || '').trim());
    const host = u.hostname === 'localhost' ? '127.0.0.1' : u.hostname;
    return `${u.protocol}//${host}${u.port ? ':' + u.port : ''}${u.pathname.replace(/\/$/, '')}`;
  } catch {
    return String(raw || '').trim().replace(/\/$/, '');
  }
}

function isLocalEndpointUrl(raw) {
  try {
    const u = new URL(String(raw || '').trim());
    return ['127.0.0.1', 'localhost', '[::1]'].includes(u.hostname);
  } catch {
    return false;
  }
}

function evaluateModelSecurityFit(modelId, meta = null) {
  const m = String(modelId || '').trim();
  if (!m) return null;
  const isVision = Boolean(meta?.isVision || /(?:^|[-:_/])vl(?:[-:_/]|$)|vision|llava|moondream|minicpm-v/i.test(m));
  const paramMatch = /(?:^|[-:_])(\d+(?:\.\d+)?)b\b/i.exec(m) || /^(\d+(?:\.\d+)?)B$/i.exec(meta?.parameterSize || '');
  const paramsB = paramMatch ? Number(paramMatch[1]) : null;
  const isCoder = /coder|codestral|deepseek-coder|starcoder|devstral/i.test(m);
  const isFrontier = /^(?:gpt-4\.1|gpt-4o|o3|o4|grok-3)|claude-(?:3[-.][57]|sonnet-4|opus-4)|gemini-2\.5|deepseek-(?:r1|reasoner|chat|v3)|llama-3\.[13]-(?:70|405)b|qwq-32b/i.test(m);

  if (isVision && (paramsB === null || paramsB <= 12)) {
    return {
      tone: 'warn',
      badge: 'VISION / SMALL MODEL',
      text: 'Part of this model’s capacity is reserved for vision. Great for quick terminal Q&A, but prone to noisy false positives on 48-step AppSec taint audits — consider qwen2.5-coder:14b or qwen3:14b.'
    };
  }
  if (paramsB !== null && paramsB <= 9 && !isCoder) {
    return {
      tone: 'warn',
      badge: `${paramsB}B COMPACT MODEL`,
      text: 'Fast local footprint for shell explanations & quick edits. For multi-tool security audits with fewer false positives, a 14B+ coder/reasoning model is recommended.'
    };
  }
  if (isCoder || isFrontier || (paramsB !== null && paramsB >= 14)) {
    return {
      tone: 'ok',
      badge: isCoder ? 'SECURITY & CODE FIT' : 'HIGH-REASONING FIT',
      text: 'Strong code comprehension and structured tool-calling accuracy for AppSec, Recon, and DFIR playbooks.'
    };
  }
  return {
    tone: 'neutral',
    badge: isLocalEndpointUrl($('base-url')?.value) ? 'LOCAL ENDPOINT' : 'CUSTOM MODEL',
    text: 'Click "Test connection" below to verify streaming SSE support before running Agent playbooks.'
  };
}

function selectPreset(p) {
  const rt = radarState.get(p.id);
  $('base-url').value = p.baseUrl;
  $('settings-error').textContent = '';
  $('settings-test-result').hidden = true;
  updateEndpointChrome();
  if (rt?.online && rt.models?.length) {
    discoveredForCurrentUrl = rt.models;
    if (!$('model-id').value.trim() || !rt.models.some(m => m.id === $('model-id').value.trim())) {
      const best = rt.models.find(m => /coder/i.test(m.id) && !m.isVision) || rt.models.find(m => !m.isVision) || rt.models[0];
      if (best) $('model-id').value = best.id;
    }
    renderModelPicker('INSTALLED ON ' + p.label.toUpperCase(), `${rt.models.length} local`);
  } else if (p.suggested.length) {
    discoveredForCurrentUrl = p.suggested.map(id => ({ id, suggested: true }));
    if (!$('model-id').value.trim() || !p.suggested.includes($('model-id').value.trim())) {
      $('model-id').value = p.suggested[0];
    }
    renderModelPicker(`${p.label.toUpperCase()} MODELS`, 'click chip or Detect models');
  } else {
    discoveredForCurrentUrl = [];
    renderModelPicker();
    probeEndpointModels(false);
  }
  renderProviderPresets();
  renderModelAdvisor();
}

function renderProviderPresets() {
  const host = $('provider-presets');
  if (!host) return;
  host.replaceChildren();
  const currentNorm = normalizeUrlKey($('base-url').value);

  const makeRow = (groupLabel, items) => {
    const row = el('div', 'preset-group-row');
    row.append(el('span', 'preset-group-tag', groupLabel));
    const pills = el('div', 'preset-group-pills');
    for (const p of items) {
      const rt = radarState.get(p.id);
      const active = currentNorm === normalizeUrlKey(p.baseUrl);
      const btn = el('button', `preset-pill${active ? ' active' : ''}`);
      btn.type = 'button';
      if (p.local) {
        btn.append(el('i', `preset-dot ${rt?.online ? 'online' : 'offline'}`));
      }
      btn.append(el('span', '', p.label));
      if (rt?.online && rt.modelCount > 0) {
        btn.append(el('span', 'preset-count', String(rt.modelCount)));
      }
      btn.addEventListener('click', () => selectPreset(p));
      pills.append(btn);
    }
    row.append(pills);
    return row;
  };

  host.append(
    makeRow('LOCAL', PROVIDER_PRESETS.filter(p => p.local)),
    makeRow('CLOUD', PROVIDER_PRESETS.filter(p => !p.local))
  );
}

function renderModelAdvisor() {
  const box = $('model-advisor');
  if (!box) return;
  const val = $('model-id').value.trim();
  const meta = discoveredForCurrentUrl.find(m => m.id === val) || null;
  const fit = evaluateModelSecurityFit(val, meta);
  if (!fit) {
    box.hidden = true;
    return;
  }
  box.hidden = false;
  box.dataset.tone = fit.tone;
  box.replaceChildren(
    el('span', `zt-tag ${fit.tone === 'ok' ? 'green' : fit.tone === 'warn' ? 'sand' : 'sky'}`, fit.badge),
    el('span', 'model-advisor-text', fit.text)
  );
}

function renderModelPicker(titleText = 'DISCOVERED MODELS', metaText = '') {
  const panel = $('model-picker-panel');
  const chips = $('model-picker-chips');
  const pullBar = $('ollama-pull-bar');
  if (!panel || !chips || !pullBar) return;

  const currentNorm = normalizeUrlKey($('base-url').value);
  const isOllama = currentNorm === normalizeUrlKey('http://127.0.0.1:11434/v1');
  const currentModel = $('model-id').value.trim();

  chips.replaceChildren();
  pullBar.replaceChildren();

  if (!discoveredForCurrentUrl.length && !isOllama) {
    panel.hidden = true;
    return;
  }
  panel.hidden = false;
  $('model-picker-title').textContent = titleText;
  $('model-picker-meta').textContent = metaText;

  for (const m of discoveredForCurrentUrl.slice(0, 18)) {
    const chip = el('button', `model-pick-chip${m.id === currentModel ? ' active' : ''}`);
    chip.type = 'button';
    chip.append(el('span', 'model-pick-name', m.id));
    const detail = [m.parameterSize, m.isVision ? 'VL' : '', m.sizeLabel].filter(Boolean).join(' · ');
    if (detail) chip.append(el('span', 'model-pick-meta', detail));
    chip.addEventListener('click', () => {
      $('model-id').value = m.id;
      $('settings-test-result').hidden = true;
      renderModelPicker(titleText, metaText);
      renderModelAdvisor();
    });
    chips.append(chip);
  }

  if (isOllama) {
    const installedIds = new Set(discoveredForCurrentUrl.map(m => m.id));
    const missingPicks = OLLAMA_SECURITY_PICKS.filter(p => !installedIds.has(p.id));
    if (missingPicks.length) {
      pullBar.hidden = false;
      pullBar.append(el('span', 'ollama-pull-label', 'RECOMMENDED FOR APPSEC:'));
      for (const rec of missingPicks) {
        const pullBtn = el('button', 'ollama-pull-chip');
        pullBtn.type = 'button';
        pullBtn.title = `${rec.note} — runs "ollama pull ${rec.id}" in your zsh tab`;
        pullBtn.append(el('strong', '', `Pull ${rec.id}`), el('span', '', ` · ${rec.note} →`));
        pullBtn.addEventListener('click', caught(async () => {
          $('settings-dialog').close();
          const sid = await runCommandInInteractiveShell(
            `ollama pull ${rec.id}`,
            `Pulling ${rec.id} in zsh — Marlowe will connect it automatically when complete.`
          );
          pendingModelPull = { sessionId: sid, baseUrl: 'http://127.0.0.1:11434/v1', model: rec.id };
        }));
        pullBar.append(pullBtn);
      }
    } else {
      pullBar.hidden = true;
    }
  } else {
    pullBar.hidden = true;
  }
}

function updateEndpointChrome() {
  const url = $('base-url').value;
  const local = isLocalEndpointUrl(url);
  const currentNorm = normalizeUrlKey(url);
  const matched = PROVIDER_PRESETS.find(p => normalizeUrlKey(p.baseUrl) === currentNorm);
  const badge = $('api-key-badge');
  if (badge) {
    const sameSaved = config?.hasKey && currentNorm === normalizeUrlKey(config.baseUrl);
    badge.textContent = local
      ? 'no key needed · local server'
      : sameSaved
        ? 'saved in OS keychain'
        : `required · ${matched?.label || 'cloud API'}`;
  }
  const keyInput = $('api-key');
  if (keyInput) {
    const sameSaved = config?.hasKey && currentNorm === normalizeUrlKey(config.baseUrl);
    keyInput.placeholder = sameSaved
      ? 'Saved securely · leave blank to keep'
      : (matched?.keyHint || 'Enter API key');
  }
}

async function probeEndpointModels(manual = false) {
  const btn = $('fetch-models-btn');
  const rawUrl = $('base-url').value.trim();
  if (!rawUrl) return;
  if (btn) { btn.disabled = true; btn.textContent = 'Detecting…'; }
  try {
    const res = await api.discoverModels({
      baseUrl: rawUrl,
      apiKey: $('api-key').value,
      clearKey: $('clear-key').checked
    });
    discoveredForCurrentUrl = res.models || [];
    renderModelPicker(
      discoveredForCurrentUrl.length ? 'DISCOVERED ON SERVER' : 'NO MODELS REPORTED',
      `${discoveredForCurrentUrl.length} available`
    );
    renderModelAdvisor();
    if (manual && discoveredForCurrentUrl.length) {
      if (!$('model-id').value.trim()) {
        $('model-id').value = discoveredForCurrentUrl[0].id;
        renderModelPicker('DISCOVERED ON SERVER', `${discoveredForCurrentUrl.length} available`);
        renderModelAdvisor();
      }
    }
  } catch (err) {
    if (manual) $('settings-error').textContent = errorMessage(err);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Detect models'; }
  }
}

async function refreshLocalRadar() {
  const statusEl = $('local-radar-status');
  if (statusEl) statusEl.textContent = 'Scanning local ports…';
  try {
    const res = await api.scanLocalModels();
    radarState = new Map((res.runtimes || []).map(rt => [rt.id, rt]));
    const online = (res.runtimes || []).filter(rt => rt.online);
    if (statusEl) {
      statusEl.textContent = online.length
        ? `${online.map(r => `${r.label} (${r.modelCount})`).join(' · ')} online`
        : 'No local servers detected on :11434 / :1234 / :8000';
      statusEl.dataset.online = online.length ? 'true' : 'false';
    }
    renderProviderPresets();

    // Auto-populate discovered chips if current base-url matches an online local runtime
    const currentNorm = normalizeUrlKey($('base-url').value);
    const matchedLocal = online.find(r => normalizeUrlKey(r.baseUrl) === currentNorm);
    if (matchedLocal) {
      discoveredForCurrentUrl = matchedLocal.models || [];
      renderModelPicker(`INSTALLED ON ${matchedLocal.label.toUpperCase()}`, `${discoveredForCurrentUrl.length} local`);
      renderModelAdvisor();
    } else {
      const matchedCloud = PROVIDER_PRESETS.find(p => !p.local && normalizeUrlKey(p.baseUrl) === currentNorm);
      if (matchedCloud?.suggested.length && !discoveredForCurrentUrl.length) {
        discoveredForCurrentUrl = matchedCloud.suggested.map(id => ({ id, suggested: true }));
        renderModelPicker(`${matchedCloud.label.toUpperCase()} QUICK PICKS`, 'or click Detect models');
      }
    }
  } catch {
    if (statusEl) statusEl.textContent = 'Local port check unavailable';
  }
}

function openSettings() {
  if (!config) return;
  discoveredForCurrentUrl = [];
  $('base-url').value = config.baseUrl; $('model-id').value = config.model; $('api-key').value = ''; $('clear-key').checked = false;
  $('api-key').placeholder = config.hasKey ? 'Saved securely · leave blank to keep' : 'Enter API key';
  $('settings-error').textContent = '';
  $('settings-test-result').hidden = true;
  $('key-note').textContent = config.secureStorage ? 'Your key is encrypted by your operating system and is never exposed to the interface.' : 'OS encryption is unavailable. You can use a local server without an API key.';
  updateEndpointChrome();
  renderProviderPresets();
  renderModelPicker();
  renderModelAdvisor();
  $('settings-dialog').showModal();
  refreshLocalRadar();
}

$('base-url').addEventListener('input', () => {
  discoveredForCurrentUrl = [];
  $('settings-test-result').hidden = true;
  updateEndpointChrome();
  renderProviderPresets();
  renderModelPicker();
  renderModelAdvisor();
});
$('model-id').addEventListener('input', () => {
  $('settings-test-result').hidden = true;
  renderModelAdvisor();
  if (!$('model-picker-panel').hidden) {
    renderModelPicker($('model-picker-title').textContent, $('model-picker-meta').textContent);
  }
});
$('api-key').addEventListener('input', () => {
  $('settings-test-result').hidden = true;
  const k = $('api-key').value.trim();
  if (!k) return;
  // Auto-select matching cloud provider preset when user pastes a recognizable key prefix
  const byPrefix = k.startsWith('sk-ant-') ? 'anthropic'
    : k.startsWith('AIza') ? 'gemini'
    : k.startsWith('xai-') ? 'xai'
    : k.startsWith('gsk_') ? 'groq'
    : k.startsWith('sk-or-') ? 'openrouter'
    : k.startsWith('fw_') ? 'fireworks'
    : k.startsWith('sk-proj-') ? 'openai'
    : null;
  if (byPrefix) {
    const preset = PROVIDER_PRESETS.find(p => p.id === byPrefix);
    if (preset && normalizeUrlKey($('base-url').value) !== normalizeUrlKey(preset.baseUrl)) {
      selectPreset(preset);
    }
  }
});
$('fetch-models-btn').addEventListener('click', () => probeEndpointModels(true));
$('test-connection-btn').addEventListener('click', async () => {
  const btn = $('test-connection-btn');
  const out = $('settings-test-result');
  $('settings-error').textContent = '';
  btn.disabled = true;
  btn.textContent = 'Testing…';
  out.hidden = true;
  try {
    const res = await api.testConnection({
      baseUrl: $('base-url').value,
      model: $('model-id').value,
      apiKey: $('api-key').value,
      clearKey: $('clear-key').checked
    });
    out.hidden = false;
    out.dataset.ok = 'true';
    out.textContent = `✓ Connected to ${res.model} · Streaming SSE verified (${res.latencyMs} ms)`;
  } catch (err) {
    out.hidden = false;
    out.dataset.ok = 'false';
    out.textContent = `✕ ${errorMessage(err)}`;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Test connection';
  }
});

$('settings-form').addEventListener('submit', async event => {
  event.preventDefault(); const button = event.submitter; button.disabled = true;
  try {
    updateConfig(await api.saveSettings({ baseUrl: $('base-url').value, model: $('model-id').value, apiKey: $('api-key').value, clearKey: $('clear-key').checked }));
    $('api-key').value = ''; $('settings-dialog').close(); notify('Connection saved. Send a message to try it.');
  } catch (error) { $('settings-error').textContent = errorMessage(error); } finally { button.disabled = false; }
});
for (const button of document.querySelectorAll('.close-dialog')) button.addEventListener('click', () => button.closest('dialog').close());
$('settings-dialog').addEventListener('close', () => $('api-key').value = '');
$('settings-button').addEventListener('click', openSettings); $('model-button').addEventListener('click', openSettings);
$('new-terminal').addEventListener('click', caught(createTerminal));
$('clear-terminal').addEventListener('click', () => {
  if (stageGraphs?.isGraphId(activeTerminal)) { stageGraphs.refreshIfVisible(); return; }
  terminals.get(activeTerminal)?.term.clear();
});
$('failure-dismiss').addEventListener('click', () => {
  const session = terminals.get(activeTerminal);
  if (session?.tracking?.last) dismissedFailures.set(session.id, session.tracking.last.sequence);
  renderFailureHud();
  session?.term.focus();
});
$('failure-diagnose').addEventListener('click', caught(async () => {
  const session = terminals.get(activeTerminal);
  if (!session) return;
  const mask = (session.tracking?.last?.secretCount || 0) > 0;
  const snap = await api.failureSnapshot(session.id, mask);
  if (session.tracking?.last) dismissedFailures.set(session.id, session.tracking.last.sequence);
  renderFailureHud();
  switchRightTab('assistant');
  reviewContext({ text: snap.text, cwd: snap.cwd }, 'failure');
  if (snap.redactedCount > 0) notify(`Masked ${snap.redactedCount} secret(s) (${snap.redactedTypes.join(', ')}) locally before review.`);
}));
$('choose-folder').addEventListener('click', caught(async () => {
  const folder = await api.chooseFolder();
  if (folder) {
    folderChosen = true;
    setFolder(folder);
    updateMode();
    if (activeRightTab === 'dna') cyber.refreshDna();
    stageGraphs?.refreshIfVisible();
    notify(`Workspace switched to ${folder}`);
  }
}));
function reviewContext(snapshot, kind = null) {
  contextReview = { ...snapshot, kind };
  $('context-preview').hidden = true;
  $('context-editor').hidden = false; $('context-review-actions').hidden = false;
  $('context-editor').value = snapshot.text;
  $('redact-context').hidden = activeScope?.redactContext === false;
  const mismatch = snapshot.cwd && folderChosen && snapshot.cwd !== workspace ? ` Terminal directory: ${snapshot.cwd}. Agent workspace stays ${workspace}; this action does not change it.` : '';
  $('context-description').textContent = 'Review and remove any secrets below (or click Redact secrets). Attach to draft keeps this snapshot local; only Send shares it with your model.' + mismatch;
  $('context-dialog').showModal();
}
api.onTerminalContext(snapshot => reviewContext(snapshot, snapshot.kind));
$('preview-context').addEventListener('click', () => {
  if (stagedContext) { reviewContext(stagedContext); return; }
  reviewContext({ text: contextText() || '(No terminal output yet)', cwd: terminals.get(activeTerminal)?.tracking?.cwd || null });
});
$('redact-context').addEventListener('click', caught(async () => {
  const res = await api.redactText($('context-editor').value);
  $('context-editor').value = res.text;
  notify(res.count ? `Masked ${res.count} secret(s) (${res.types.join(', ')}).` : 'No known credential patterns detected in this snapshot.');
}));
$('attach-context').addEventListener('click', () => {
  if (!contextReview) return;
  stagedContext = { text: $('context-editor').value.slice(0, 16000), cwd: contextReview.cwd };
  $('share-context').checked = true;
  if (contextReview.kind) {
    const question = contextReview.kind === 'selection' ? 'Explain the selected terminal text.' : contextReview.kind === 'failure' ? 'Help me understand the failed command in the attached context and propose next steps. Do not run commands or edit files.' : 'Explain the command and its result in the attached context.';
    $('prompt').value = [$('prompt').value.trim(), question].filter(Boolean).join('\n\n');
    mode = 'chat'; updateMode();
  }
  $('context-dialog').close();
  switchRightTab('assistant');
  $('prompt').focus();
  notify('Snapshot attached to your next send. Nothing has been shared yet.');
});
$('context-dialog').addEventListener('close', () => { contextReview = null; $('context-editor').value = ''; });
$('share-context').addEventListener('change', () => {
  if ($('share-context').checked) {
    if (!stagedContext) stagedContext = { text: contextText(), cwd: terminals.get(activeTerminal)?.tracking?.cwd || null };
  } else stagedContext = null;
});
function scrollMessages() { $('messages').scrollTop = $('messages').scrollHeight; }

function renderInline(parent, text) {
  const tokenRe = /`([^`\n]+)`|\*\*((?:[^*]|\*(?!\*))+)\*\*|(?<!\*)\*([^*\n]+)\*(?!\*)/g;
  let last = 0, m;
  while ((m = tokenRe.exec(text))) {
    if (m.index > last) parent.append(document.createTextNode(text.slice(last, m.index)));
    if (m[1] !== undefined) {
      parent.append(el('code', 'md-code', m[1]));
    } else if (m[2] !== undefined) {
      const strong = el('strong', 'md-strong');
      renderInline(strong, m[2]);
      parent.append(strong);
    } else if (m[3] !== undefined) {
      const em = el('em', 'md-em');
      renderInline(em, m[3]);
      parent.append(em);
    }
    last = tokenRe.lastIndex;
  }
  if (last < text.length) parent.append(document.createTextNode(text.slice(last)));
}

function splitTableRow(line) {
  return line.trim().replace(/^\|/, '').replace(/\|$/, '').split('|').map(c => c.trim());
}

function renderMarkdownSegment(container, segment) {
  const lines = segment.replace(/\r\n/g, '\n').split('\n');
  const isSpecial = line => {
    if (!line.trim()) return true;
    if (/^\s*(?:---+|\*\*\*+|___+)\s*$/.test(line)) return true;
    if (/^\s*#{1,6}\s+/.test(line)) return true;
    if (/^\s*>\s?/.test(line)) return true;
    if (/^ *(?:[-*•]|\d+\.)\s+/.test(line)) return true;
    return false;
  };

  for (let i = 0; i < lines.length;) {
    const line = lines[i];
    if (!line.trim()) { i++; continue; }

    if (/^\s*(?:---+|\*\*\*+|___+)\s*$/.test(line)) {
      container.append(el('hr', 'md-hr'));
      i++;
      continue;
    }

    const hMatch = /^\s*(#{1,6})\s+(.+?)\s*$/.exec(line);
    if (hMatch) {
      const level = hMatch[1].length;
      const cleanTitle = hMatch[2].replace(/^\*\*(.+)\*\*$/, '$1').trim();
      const tag = level <= 2 ? 'h3' : level === 3 ? 'h4' : 'h5';
      const cls = level <= 2 ? 'md-h2' : level === 3 ? 'md-h3' : 'md-h4';
      const h = el(tag, cls);
      renderInline(h, cleanTitle);
      container.append(h);
      i++;
      continue;
    }

    if (line.trim().startsWith('|') && i + 1 < lines.length && /^\s*\|?[\s:-]+\|[\s|:-]*$/.test(lines[i + 1])) {
      const wrap = el('div', 'md-table-wrap'), table = el('table', 'md-table');
      const thead = el('thead'), headTr = el('tr');
      for (const cell of splitTableRow(line)) {
        const th = el('th'); renderInline(th, cell); headTr.append(th);
      }
      thead.append(headTr);
      table.append(thead);
      i += 2;
      const tbody = el('tbody');
      while (i < lines.length && lines[i].trim().startsWith('|')) {
        const tr = el('tr');
        for (const cell of splitTableRow(lines[i])) {
          const td = el('td'); renderInline(td, cell); tr.append(td);
        }
        tbody.append(tr);
        i++;
      }
      table.append(tbody);
      wrap.append(table);
      container.append(wrap);
      continue;
    }

    if (/^\s*>\s?/.test(line)) {
      const quote = el('blockquote', 'md-quote');
      let first = true;
      while (i < lines.length && /^\s*>\s?/.test(lines[i])) {
        if (!first) quote.append(document.createElement('br'));
        renderInline(quote, lines[i].replace(/^\s*>\s?/, ''));
        first = false;
        i++;
      }
      container.append(quote);
      continue;
    }

    const listMatch = /^( *)([-*•]|\d+\.)\s+(.*)$/.exec(line);
    if (listMatch) {
      const ordered = /^\d+\.$/.test(listMatch[2]);
      const list = el(ordered ? 'ol' : 'ul', 'md-list');
      let lastTopLi = null;
      while (i < lines.length) {
        if (!lines[i].trim()) {
          if (i + 1 < lines.length && /^( *)([-*•]|\d+\.)\s+/.test(lines[i + 1])) { i++; continue; }
          break;
        }
        const m = /^( *)([-*•]|\d+\.)\s+(.*)$/.exec(lines[i]);
        if (!m) break;
        const indent = m[1].length;
        const itemContent = m[3];
        const li = el('li', 'md-li');
        const span = el('span', 'md-li-text');
        renderInline(span, itemContent);
        li.append(span);
        if (indent >= 2 && lastTopLi) {
          let sub = lastTopLi.querySelector(':scope > .md-sublist');
          if (!sub) {
            sub = el(/^\d+\.$/.test(m[2]) ? 'ol' : 'ul', 'md-sublist');
            lastTopLi.append(sub);
          }
          sub.append(li);
        } else {
          list.append(li);
          lastTopLi = li;
        }
        i++;
      }
      container.append(list);
      continue;
    }

    const p = el('p', 'md-p');
    let firstLine = true;
    while (i < lines.length && lines[i].trim() && !isSpecial(lines[i])) {
      if (lines[i].trim().startsWith('|') && i + 1 < lines.length && /^\s*\|?[\s:-]+\|[\s|:-]*$/.test(lines[i + 1])) break;
      if (!firstLine) p.append(document.createElement('br'));
      renderInline(p, lines[i]);
      firstLine = false;
      i++;
    }
    container.append(p);
  }
}

function renderProseWithCode(container, prose) {
  const pattern = /```([\w+-]*)\n([\s\S]*?)```/g;
  let last = 0, match;
  while ((match = pattern.exec(prose))) {
    if (match.index > last) renderMarkdownSegment(container, prose.slice(last, match.index));
    const block = el('div', 'code-block'), toolbar = el('div', 'code-toolbar');
    toolbar.append(el('span', '', match[1] || 'code'));
    const code = match[2].replace(/\n$/, '');
    const copy = el('button', '', 'Copy'); copy.addEventListener('click', caught(async () => { await navigator.clipboard.writeText(code); notify('Copied to clipboard.'); })); toolbar.append(copy);
    if (['sh', 'bash', 'zsh', 'shell'].includes(match[1])) {
      const insert = el('button', '', 'Use command');
      insert.title = 'Copy this command, then review and paste it into the terminal';
      insert.addEventListener('click', () => {
        caught(async () => { await navigator.clipboard.writeText(code); notify('Command copied. Review it, then paste into the terminal when ready.'); terminals.get(activeTerminal)?.term.focus(); })();
      }); toolbar.append(insert);
    }
    block.append(toolbar, el('pre', '', code)); container.append(block); last = pattern.lastIndex;
  }
  if (last < prose.length) renderMarkdownSegment(container, prose.slice(last));
}

function renderBody(body, text) {
  body.replaceChildren();
  const splitMatch = /(?:^|\n\n)Agent activity:\n([\s\S]+)$/.exec(text);
  const prose = splitMatch ? text.slice(0, splitMatch.index) : text;
  if (prose) renderProseWithCode(body, prose);
  if (splitMatch) {
    const steps = splitMatch[1].split('\n').map(s => s.trim()).filter(Boolean);
    const details = el('details', 'saved-activity');
    details.append(el('summary', '', `Run activity · ${steps.length} tool action${steps.length === 1 ? '' : 's'}`));
    const list = el('div', 'saved-activity-list');
    for (const step of steps) list.append(el('div', 'saved-activity-item', step));
    details.append(list);
    body.append(details);
  }
}

function appendMessage(message) {
  $('welcome')?.remove();
  const node = el('article', `message ${message.role}`), heading = el('div', 'message-heading');
  const badge = el('span', 'badge');
  if (message.role === 'user') badge.textContent = 'Y';
  else badge.append('m', el('span', 'm-dot', '.'));
  heading.append(badge, el('span', '', message.role === 'user' ? 'YOU' : 'MARLOWE'));
  const body = el('div', 'message-body');
  if (message.role === 'user') body.textContent = message.content;
  else renderBody(body, message.content);
  node.append(heading, body); $('messages').append(node); scrollMessages(); return { node, body };
}
const welcomeMarkup = $('messages').innerHTML;
function wireSuggestions() {
  document.querySelectorAll('[data-prompt]').forEach(button => button.addEventListener('click', () => {
    if (button.dataset.playbook) {
      playbook = button.dataset.playbook;
      $('playbook-select').value = playbook;
      if (folderChosen) { mode = 'agent'; updateMode(); }
    }
    $('prompt').value = button.dataset.prompt;
    $('prompt').focus();
  }));
}
wireSuggestions();
function busy(value) { $('chat-mode').disabled = value; $('agent-mode').disabled = value; $('playbook-select').disabled = value; $('choose-folder').disabled = value; document.querySelectorAll('[data-restore="true"]').forEach(button => button.disabled = value); $('send-button').hidden = value; $('stop-button').hidden = !value; $('new-chat').disabled = value; $('app-status').textContent = value ? 'Marlowe is thinking' : 'All systems ready'; }
async function saveHistory() { await api.saveHistory(messages.slice(-200)); }
function updateMode() {
  terminals.get('marlowe')?.conversation.redraw();
  if (activeTerminal === 'marlowe') renderTerminalStatus(terminals.get('marlowe'));
  $('chat-mode').setAttribute('aria-pressed', String(mode === 'chat'));
  $('agent-mode').setAttribute('aria-pressed', String(mode === 'agent'));
  $('playbook-select').hidden = mode !== 'agent';
  $('playbook-select').value = playbook;
}
$('chat-mode').addEventListener('click', () => { mode = 'chat'; updateMode(); });
async function ensureShellWorkspace(openPicker = false) {
  if (folderChosen) return true;
  const shellCandidate = terminals.get(activeTerminal) && !terminals.get(activeTerminal).conversation
    ? terminals.get(activeTerminal)
    : [...terminals.values()].find(s => !s.conversation && !s.exited);
  const adopted = shellCandidate ? await api.adoptTerminalCwd(shellCandidate.id) : null;
  if (adopted) {
    folderChosen = true;
    setFolder(adopted);
    updateMode();
    notify(`Workspace set to ${adopted}`);
    return true;
  }
  if (openPicker) {
    const picked = await api.chooseFolder();
    if (picked) {
      folderChosen = true;
      setFolder(picked);
      updateMode();
      return true;
    }
  }
  return false;
}

$('agent-mode').addEventListener('click', caught(async () => {
  if (!await ensureShellWorkspace(true)) return;
  mode = 'agent'; updateMode();
}));
$('playbook-select').addEventListener('change', () => { playbook = $('playbook-select').value; updateMode(); });

// Diff text is model- and file-supplied: it is only ever set as textContent.
function diffView(diff) {
  const view = el('div', 'diff');
  if (!diff.hunks.length) view.append(el('div', 'diff-note', 'No line changes.'));
  for (const hunk of diff.hunks) {
    view.append(el('div', 'diff-hunk', `@@ -${hunk.oldStart},${hunk.oldLines} +${hunk.newStart},${hunk.newLines} @@`));
    for (const line of hunk.lines) {
      const row = el('div', 'diff-line', line.type === '\\' ? line.text : `${line.type === '-' ? '−' : line.type} ${line.text}`);
      row.dataset.kind = ({ '+': 'added', '-': 'removed', '\\': 'note' })[line.type] || 'context'; view.append(row);
    }
  }
  if (diff.truncated) view.append(el('div', 'diff-note', 'Long diff shortened. Show full file to review everything.'));
  return view;
}
function showFullFile(card, full) { card.pre.hidden = !full; card.diffView.hidden = full; card.toggle.textContent = full ? 'Show changes' : 'Show full file'; }
api.onAgentEvent(event => {
  if (!request || request.id !== event.runId) return;
  request.hadActions = true;
  const terminal = request.terminal, diff = event.diff || actionCards.get(event.actionId)?.diff;
  if (event.status === 'output') terminal.conversation.token(event.output);
  else if (event.status !== 'planned') {
    const detail = event.status === 'awaiting-approval' ? ` — ${event.reason} Use Approve once or Deny in the conversation panel.` : '';
    const tone = ({ 'awaiting-approval': 'warning', approved: 'success', denied: 'warning', running: 'info', completed: 'success', error: 'error' })[event.status];
    terminal.conversation.line(`[${event.status}] ${(event.name || 'action').replaceAll('_', ' ')} · ${event.title || ''}${diff && ['awaiting-approval', 'completed'].includes(event.status) ? ` (+${diff.added} −${diff.removed})` : ''}${detail}`, tone);
    if (event.status === 'completed' && event.result) {
      const result = event.result;
      terminal.conversation.line(Object.hasOwn(result, 'exitCode') && !result.summary ? `Exit code: ${result.exitCode ?? result.signal}` : result.summary || result.error || result.content || (result.entries ? result.entries.map(entry => entry.name + (entry.type === 'directory' ? '/' : '')).join('  ') || '(Empty directory)' : JSON.stringify(result)), result.error || (Object.hasOwn(result, 'exitCode') && result.exitCode !== 0) ? 'error' : 'muted');
      const locations = [
        ...(result.findings || []).map(f => `  ↳ ${f.path}:${f.line} [${f.cwe}] ${f.label}`),
        ...(result.matches || []).filter(m => m.cwe).map(m => `  ↳ ${m.path}:${m.line} [${m.cwe}] ${m.title}`),
        ...(result.manifests?.length ? [`  ↳ Manifests: ${result.manifests.slice(0, 4).join(', ')}${result.manifests.length > 4 ? ` (+${result.manifests.length - 4} more)` : ''}`] : []),
        ...(result.vulnerabilities || []).map(v => `  ↳ ${v.id}: ${v.package}@${v.version} (${v.source})`),
        ...(result.alerts || []).map(a => `  ↳ line ${a.line} [${a.mitre}] ${a.label}`)
      ];
      for (const loc of locations.slice(0, 6)) terminal.conversation.line(loc, 'muted');
      if (locations.length > 6) terminal.conversation.line(`  … +${locations.length - 6} more in card Details`, 'muted');
      if (result.backupId) terminal.conversation.line('Backup saved · Undo available after this run', 'muted');
    }
    if (event.status === 'error') terminal.conversation.line(event.error || event.result?.error || 'Action failed. See Details.', 'error');
  }
  let card = actionCards.get(event.actionId);
  if (!card) {
    const node = el('section', 'action-card'), header = el('div', 'action-heading');
    const name = el('strong', '', event.name?.replaceAll('_', ' ') || 'Action');
    const status = el('span', 'action-status', event.status);
    header.append(name, status);
    const title = el('div', 'action-title', event.title || '');
    const reason = el('p', 'action-reason'); reason.hidden = true;
    const details = el('details', 'action-details');
    details.append(el('summary', '', 'Details'), el('pre', '', event.preview || ''));
    const buttons = el('div', 'action-buttons');
    node.append(header, title, reason, details, buttons);
    request.node.insertBefore(node, request.body);
    card = { node, status, reason, details, pre: details.querySelector('pre'), buttons, output: '', backupId: null };
    if (event.diff) {
      title.append(' ', el('span', 'diff-added', `+${event.diff.added}`), ' ', el('span', 'diff-removed', `−${event.diff.removed}`));
      card.diff = event.diff; card.diffView = diffView(event.diff); card.toggle = el('button', 'diff-toggle', '');
      card.toggle.type = 'button'; card.toggle.addEventListener('click', () => showFullFile(card, card.pre.hidden));
      card.pre.before(card.diffView); details.append(card.toggle); showFullFile(card, false);
    }
    actionCards.set(event.actionId, card);
  }
  if (event.status === 'output') {
    card.output = (card.output + event.output).slice(-32000); card.pre.textContent = card.output; return;
  }
  card.node.dataset.status = event.status;
  card.status.textContent = event.status.replaceAll('-', ' ');
  clearInterval(card.timer);
  if (event.status === 'running' && ['run_command', 'run_security_scanner'].includes(event.name)) {
    const started = Date.now();
    card.timer = setInterval(() => { card.status.textContent = `running · ${Math.round((Date.now() - started) / 1000)}s`; }, 1000);
  }
  if (event.preview && !card.output) card.pre.textContent = event.preview;
  if (event.status === 'awaiting-approval') {
    switchRightTab('assistant');
    card.reason.textContent = event.reason + '\nWorkspace: ' + event.root; card.reason.hidden = false; card.details.open = true;
    $('app-status').textContent = 'Waiting for your approval';
    card.buttons.replaceChildren();
    for (const [label, approve] of [['Deny', false], ['Approve once', true]]) {
      const button = el('button', approve ? 'primary-button' : 'secondary-button', label);
      button.addEventListener('click', caught(async () => {
        await api.approveAction(event.runId, event.approvalId, approve);
        for (const child of card.buttons.children) child.disabled = true;
      })); card.buttons.append(button);
    }
  } else {
    if (['approved', 'denied', 'running', 'completed', 'error'].includes(event.status)) card.buttons.replaceChildren();
    if (event.status === 'running') $('app-status').textContent = 'Marlowe is working';
    if (['denied', 'completed', 'error'].includes(event.status)) $('app-status').textContent = 'Marlowe is thinking';
    if (event.result) {
      const result = event.result;
      const isReadFile = event.name === 'read_file' && typeof result.content === 'string';
      const summary = result.error || (isReadFile
        ? `Lines ${result.startLine}–${result.endLine} of ${result.totalLines}${result.truncated ? ` · pass start_line ${result.endLine + 1} for more` : ''}`
        : Object.hasOwn(result, 'exitCode') && !result.structuredFindings
          ? `Exit code: ${result.exitCode ?? result.signal}\n${result.stopped || ''}\n${result.output}`
          : result.summary || JSON.stringify(result, null, 2));
      if (event.preview && result.backupId) card.pre.textContent = event.preview;
      else if (card.diff) { card.diffView.remove(); card.toggle.remove(); card.pre.hidden = false; card.pre.textContent = summary; }
      else if (isReadFile) { card.pre.textContent = `${summary}\n\n${result.content}`; }
      else {
        const extraLines = [
          ...(result.files || []),
          ...(result.matches || []).map(match => `${match.path}:${match.line}: ${match.title ? `[${match.cwe || match.severity}] ${match.title} — ${match.snippet}` : match.text}`),
          ...(result.findings || []).map(f => f.maskedPreview ? `${f.path}:${f.line}: [${f.severity.toUpperCase()} · ${f.cwe}] ${f.label} — ${f.maskedPreview}` : `[${(f.severity || 'info').toUpperCase()}${f.cwe ? ' · ' + f.cwe : ''}] ${f.title} — ${f.location}`),
          ...(result.vulnerabilities || []).map(v => `${v.id} (${v.package}@${v.version}) — ${v.advisoryUrl}`),
          ...(result.issues || []).map(i => `[${i.severity.toUpperCase()} · ${i.cwe}] ${i.issue}`),
          ...(result.alerts || []).slice(0, 20).map(a => `line ${a.line} [${a.mitre}] ${a.label}: ${a.sample}`)
        ];
        card.pre.textContent = [summary, ...extraLines].join('\n');
      }
      request.activity.push(`${event.name}: ${event.title} — ${summary.slice(0, 1500)}`);
      if (result.backupId) {
        const restore = el('button', 'secondary-button', 'Undo file change'); restore.disabled = true;
        restore.dataset.restore = 'true';
        restore.addEventListener('click', caught(async () => {
          try { await api.restoreFile(result.backupId); } catch (error) { terminal.conversation.line('[undo failed] ' + errorMessage(error), 'error'); throw error; } restore.disabled = true; restore.dataset.restore = 'done';
          card.status.textContent = 'restored';
          terminal.conversation.line(`[undo completed] ${event.title} — previous contents restored.`, 'success');
          messages.push({ role: 'user', content: 'I restored the previous contents of ' + event.title + ' using Undo file change.' });
          await saveHistory(); notify('File change undone.');
        })); card.buttons.append(restore);
      }
    }
    if (event.status === 'denied') request.activity.push(`${event.name}: ${event.title} — denied by user; not executed.`);
  }
  scrollMessages();
});
api.onChatToken(({ id, token }) => {
  if (!request || request.id !== id) return;
  if (!request.content) request.terminal.conversation.line('MARLOWE', 'heading');
  request.terminal.conversation.reply(token);
  request.content += token; request.body.classList.remove('thinking');
  renderBody(request.body, request.content); scrollMessages();
});
async function submitMessage(text, fromTerminal = false) {
  const prompt = text.trim(); if (!prompt || request) return;
  if (!config.hasKey && CLOUD_HOSTS_REQUIRING_KEY.has(new URL(config.baseUrl).hostname)) { openSettings(); notify('Add your API key to connect Marlowe. Your draft is preserved.'); return; }
  if (mode === 'agent' && playbook === 'recon' && (!activeScope?.targets || activeScope.targets.length === 0)) {
    cyber.openScopeDialog();
    $('scope-target-input')?.focus();
    notify('Add at least one authorized domain, URL, or IP in Scope before running Authorized Recon (or switch playbook to AppSec Audit for local code).');
    return;
  }
  const context = !fromTerminal && $('share-context').checked ? (stagedContext?.text || '') : '';
  if (!fromTerminal) { stagedContext = null; $('share-context').checked = false; }
  const terminal = marloweSession();
  if (fromTerminal) activate(terminal.id);
  terminal.conversation.begin(prompt, mode === 'agent' ? `workspace ${workspace} · playbook ${playbook}` : '');
  messages.push({ role: 'user', content: prompt }); appendMessage(messages.at(-1)); if (!fromTerminal) $('prompt').value = '';
  const { node, body } = appendMessage({ role: 'assistant', content: 'Thinking…' }); body.classList.add('thinking');
  request = { id: crypto.randomUUID(), content: '', body, node, activity: [], hadActions: false, terminal }; busy(true); renderTerminalStatus(terminals.get(activeTerminal));
  let content = '';
  try {
    await saveHistory();
    const result = await api.chat({ id: request.id, messages: messages.slice(-40), context, mode, playbook });
    request.agentRunId = result.agentRunId;
    if (result.error) throw new Error(result.error);
    content = request.content || result.content || '';
    if (!request.content && content) terminal.conversation.reply(content);
    terminal.conversation.flushReply();
    if (result.stopped) terminal.conversation.line('[stopped] ' + (result.reason || 'Response stopped.'), 'warning');
    if (result.stopped) node.append(el('div', 'message-error', result.reason?.includes('timed out') ? result.reason : 'Response stopped.'));
    if (result.paused) {
      terminal.conversation.line(`[paused] ${result.pauseReason} — send a follow-up or click Continue in the Assistant pane.`, 'warning');
      const bar = el('div', 'message-continue-bar');
      bar.append(el('span', 'continue-label', `${result.pauseReason} · Progress & findings saved`));
      const contBtn = el('button', 'primary-button compact-btn', 'Continue →');
      contBtn.type = 'button';
      contBtn.addEventListener('click', () => {
        if (request) return;
        contBtn.disabled = true;
        caught(() => submitMessage('Continue from where you left off, complete any remaining verification or finding records, and provide the final summary.'))();
      });
      bar.append(contBtn);
      node.append(bar);
    }
  } catch (error) {
    content = request.content;
    terminal.conversation.flushReply();
    terminal.conversation.line('[error] ' + errorMessage(error), 'error');
    node.append(el('div', 'message-error', errorMessage(error)));
    if (!content && !request.hadActions && !request.agentRunId) { if (!fromTerminal) $('prompt').value = prompt; messages.pop(); }
  } finally {
    body.classList.remove('thinking');
    const record = [content, request.activity.length ? 'Agent activity:\n' + request.activity.join('\n') : ''].filter(Boolean).join('\n\n').slice(0, 250000);
    // Keep live actionCards in DOM during session; render prose cleanly above them.
    renderBody(body, content);
    if (record || request.agentRunId) messages.push({ role: 'assistant', content: record || 'Agent run ended without a final response.', ...(request.agentRunId ? { agentRunId: request.agentRunId } : {}) });
    for (const card of actionCards.values()) {
      clearInterval(card.timer);
      if (['awaiting-approval', 'planned', 'approved', 'running'].includes(card.node.dataset.status)) {
        card.status.textContent = 'stopped'; card.node.dataset.status = 'stopped'; card.buttons.replaceChildren();
      }
      const restore = card.buttons.querySelector('[data-restore="true"]'); if (restore) restore.disabled = false;
    }
    terminal.conversation.flushReply();
    terminal.conversation.line('[run ended]', 'muted');
    request = null; terminal.conversation.end(); busy(false); scrollMessages();
    if (fromTerminal) terminal.term.focus(); else $('prompt').focus();
    renderTerminalStatus(terminals.get(activeTerminal));
    saveHistory().catch(error => notify('Could not save conversation: ' + errorMessage(error)));
  }
}
$('chat-form').addEventListener('submit', event => { event.preventDefault(); caught(() => submitMessage($('prompt').value))(); });
$('stop-button').addEventListener('click', caught(() => api.stopChat()));
$('prompt').addEventListener('keydown', event => { if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) { event.preventDefault(); $('chat-form').requestSubmit(); } });
$('new-chat').addEventListener('click', () => { if (messages.length) $('new-chat-dialog').showModal(); else $('prompt').focus(); });
$('confirm-new-chat').addEventListener('click', caught(async () => { await api.saveHistory([]); messages = []; terminals.get('marlowe')?.conversation.line('—— New conversation · earlier terminal entries are display history only ——'); $('messages').innerHTML = welcomeMarkup; $('messages').scrollTop = 0; $('share-context').checked = false; stagedContext = null; wireSuggestions(); $('new-chat-dialog').close(); $('prompt').focus(); }));
document.addEventListener('keydown', event => {
  if (!(event.metaKey || event.ctrlKey)) return;
  if (event.key === ',') { event.preventDefault(); if (!$('settings-dialog').open) openSettings(); }
  if (event.key.toLowerCase() === 't' && !event.target.closest('.xterm')) { event.preventDefault(); caught(createTerminal)(); }
  if (event.key.toLowerCase() === 'l' && event.shiftKey) { event.preventDefault(); switchRightTab('assistant'); $('prompt').focus(); }
  if (event.key.toLowerCase() === 'j' && (event.metaKey || event.shiftKey || !event.target.closest('.xterm'))) { event.preventDefault(); toggleDrawer(); }
});
function applyWorkbenchGrid() {
  $('workbench').style.gridTemplateColumns = drawerOpen ? `minmax(0, ${split}fr) 4px minmax(0, ${100 - split}fr)` : 'minmax(0, 1fr)';
  $('splitter').hidden = !drawerOpen;
  $('chat-pane').hidden = !drawerOpen;
  $('workbench').classList.toggle('drawer-closed', !drawerOpen);
  $('toggle-drawer')?.setAttribute('aria-expanded', String(drawerOpen));
  requestAnimationFrame(() => fit(terminals.get(activeTerminal)));
}
function setDrawer(open) {
  drawerOpen = Boolean(open);
  applyWorkbenchGrid();
  if (!drawerOpen) terminals.get(activeTerminal)?.term.focus();
}
function toggleDrawer() { setDrawer(!drawerOpen); }
$('toggle-drawer')?.addEventListener('click', toggleDrawer);
function setSplit(value) { split = Math.max(40, Math.min(78, value)); $('splitter').setAttribute('aria-valuenow', Math.round(split)); if (drawerOpen) applyWorkbenchGrid(); }
applyWorkbenchGrid();
$('splitter').addEventListener('pointerdown', event => { $('splitter').setPointerCapture(event.pointerId); });
$('splitter').addEventListener('pointermove', event => { if (!$('splitter').hasPointerCapture(event.pointerId)) return; const rect = $('workbench').getBoundingClientRect(); setSplit((event.clientX - rect.left) / rect.width * 100); });
$('splitter').addEventListener('pointerup', event => $('splitter').releasePointerCapture(event.pointerId));
$('splitter').addEventListener('keydown', event => { if (['ArrowLeft', 'ArrowRight'].includes(event.key)) { event.preventDefault(); setSplit(split + (event.key === 'ArrowRight' ? 2 : -2)); } });
async function boot() {
  const state = await api.boot(); updateConfig(state.settings); setFolder(state.folder); messages = state.history; folderChosen = state.folderChosen;
  cyber.init(state.scope, state.findings);
  updateMode();
  if (state.platform !== 'darwin') document.querySelector('.window-space').style.width = '0';
  for (const message of messages) appendMessage(message);
  await document.fonts.load('12px "Geist Mono"');
  await createTerminal();
  const shellId = activeTerminal;
  marloweSession();
  stageGraphs = setupStageGraphs(api, {
    stageHost: $('terminal-stage'),
    tabsHost: $('terminal-tabs'),
    caught,
    notify,
    onSelectGraphTab: id => activate(id),
    onEnsureWorkspace: openPicker => ensureShellWorkspace(openPicker),
    onAuditAsset: item => auditWorkspaceFile(item),
    onDraftFix: finding => draftFixForFinding(finding),
    onDraftShield: finding => draftShieldForFinding(finding),
    onOpenDna: () => cyber.openDnaDialog(),
    onOpenScope: () => cyber.openScopeDialog(),
    onFindingsMutated: () => cyber.syncFindings()
  });
  api.onFindingsChanged(() => stageGraphs?.refreshIfVisible());
  api.onScansChanged(() => {
    stageGraphs?.refreshIfVisible();
    if (activeRightTab === 'dna') cyber.refreshDna();
  });
  activate(shellId);
}
boot().catch(error => { $('app-status').textContent = 'Startup needs attention'; notify(errorMessage(error)); });
