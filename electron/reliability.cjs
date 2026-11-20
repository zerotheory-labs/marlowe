const fs = require('node:fs/promises');
const path = require('node:path');

function summarizeRun(id, events, activeRunId) {
  const start = events.find(e => e.status === 'started') || {};
  const end = events.findLast(e => ['finished', 'stopped', 'error'].includes(e.status) && !e.actionId);
  const actions = new Map();
  for (const event of events) {
    if (!event.actionId) continue;
    const action = actions.get(event.actionId) || { id: event.actionId, name: event.name || 'unknown', title: event.title || '', approval: 'not requested', status: 'unknown', failed: false };
    if (event.status === 'awaiting-approval') action.approval = 'pending';
    if (['approved', 'denied'].includes(event.status)) action.approval = event.status;
    action.status = event.status;
    const result = event.result;
    if (result) {
      action.failed = !!result.error || !!result.stopped || (Object.hasOwn(result, 'exitCode') && result.exitCode !== 0);
      action.detail = result.error || result.stopped || (Object.hasOwn(result, 'exitCode') ? `Command exit code: ${result.exitCode ?? 'none'}` : result.summary || 'Tool returned a result');
    }
    if (event.status === 'error') action.failed = true;
    actions.set(event.actionId, action);
  }
  const status = end?.status || (start.runId === activeRunId ? 'active' : 'incomplete');
  for (const action of actions.values()) if (action.approval === 'pending' && status !== 'active') action.approval = 'unresolved';
  return {
    id, model: start.model || 'Unknown (legacy)', version: start.appVersion || 'Unknown (legacy)',
    playbook: start.playbook || 'general',
    findingsRecorded: events.reduce((sum, e) => e.status === 'completed' ? sum + (e.name === 'record_finding' ? 1 : e.name === 'record_findings' ? (e.result?.recordedCount || 0) : 0) : sum, 0),
    workspace: start.workspace || '', time: start.time || '', status,
    durationMs: end && Number.isFinite(Date.parse(end.time) - Date.parse(start.time)) ? Math.max(0, Date.parse(end.time) - Date.parse(start.time)) : null,
    guards: events.filter(e => e.status === 'response-rejected').length,
    guardInstrumented: start.telemetryVersion >= 1,
    exhausted: events.some(e => e.status === 'response-recovery-exhausted'),
    error: end?.message || '', actions: [...actions.values()],
    undo: events.filter(e => ['undo-completed', 'undo-error'].includes(e.status)).map(e => ({ status: e.status, time: e.time, message: e.message || '' }))
  };
}
async function loadDashboard(directory, activeRunId) {
  let files;
  try { files = await fs.readdir(directory, { withFileTypes: true }); } catch (e) { if (e.code === 'ENOENT') return { runs: [], skipped: 0, limited: false }; throw e; }
  const candidates = [];
  for (const file of files) if (file.isFile() && /^[0-9a-f-]{36}\.jsonl$/i.test(file.name)) {
    const stat = await fs.stat(path.join(directory, file.name)); candidates.push({ name: file.name, time: stat.mtimeMs, size: stat.size });
  }
  candidates.sort((a, b) => b.time - a.time);
  const runs = []; let skipped = 0;
  for (const file of candidates.slice(0, 200)) {
    if (file.size > 8_000_000) { skipped++; continue; }
    try {
      const events = []; let partial = false;
      for (const line of (await fs.readFile(path.join(directory, file.name), 'utf8')).split('\n').filter(Boolean)) {
        try { const e = JSON.parse(line); if (e && typeof e === 'object') events.push(e); else partial = true; } catch { partial = true; }
      }
      if (partial) skipped++;
      if (events.length) runs.push({ ...summarizeRun(file.name.slice(0, -6), events, activeRunId), partial });
    } catch { skipped++; }
  }
  return { runs, skipped, limited: candidates.length > 200 };
}
module.exports = { summarizeRun, loadDashboard };
