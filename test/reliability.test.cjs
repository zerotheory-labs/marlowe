const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { summarizeRun, loadDashboard } = require('../electron/reliability.cjs');
const { runReliabilityChecks } = require('../electron/reliability-checks.cjs');
test('metrics distinguish command failures, denials, guards, run finish and Undo', () => {
  const result = summarizeRun('id', [
    { status: 'started', runId: 'active', model: 'local', appVersion: '0.2', telemetryVersion: 1, time: '2026-01-01T00:00:00Z' },
    { status: 'response-rejected' }, { status: 'response-recovery-exhausted' },
    { actionId: 'a', name: 'run_command', status: 'planned' },
    { actionId: 'a', status: 'awaiting-approval' }, { actionId: 'a', status: 'approved' },
    { actionId: 'a', status: 'completed', result: { exitCode: 2, output: 'PRIVATE CONTENT' } },
    { actionId: 'b', name: 'delete_file', status: 'awaiting-approval' }, { actionId: 'b', status: 'denied' },
    { status: 'finished', time: '2026-01-01T00:00:02Z' },
    { status: 'undo-completed' }, { status: 'undo-error', message: 'File changed' }
  ]);
  assert.equal(result.status, 'finished'); assert.equal(result.durationMs, 2000);
  assert.equal(result.guards, 1); assert.equal(result.exhausted, true);
  assert.equal(result.actions[0].failed, true); assert.equal(result.actions[0].approval, 'approved');
  assert.equal(result.actions[1].approval, 'denied'); assert.equal(result.actions[1].failed, false);
  assert.equal(result.undo.length, 2); assert.doesNotMatch(JSON.stringify(result), /PRIVATE CONTENT/);
});
test('legacy and interrupted runs are not labeled successful or zero-claim measurements', () => {
  const events = [{ status: 'started', runId: 'run' }, { actionId: 'a', status: 'awaiting-approval' }];
  const legacy = summarizeRun('id', events);
  assert.equal(legacy.status, 'incomplete'); assert.equal(legacy.guardInstrumented, false);
  assert.equal(legacy.actions[0].approval, 'unresolved'); assert.match(legacy.model, /legacy/);
  const active = summarizeRun('id', events, 'run'); assert.equal(active.status, 'active'); assert.equal(active.actions[0].approval, 'pending');
});
test('dashboard handles missing directories and partial logs without reading context files', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'benjamin-metrics-'));
  try {
    assert.deepEqual((await loadDashboard(path.join(dir, 'missing'))).runs, []);
    await fs.writeFile(path.join(dir, '11111111-1111-4111-8111-111111111111.jsonl'), '{"status":"started"}\nBROKEN\n');
    await fs.writeFile(path.join(dir, '11111111-1111-4111-8111-111111111111.context.json'), 'private');
    const data = await loadDashboard(dir); assert.equal(data.runs.length, 1); assert.equal(data.skipped, 1); assert.equal(data.runs[0].partial, true);
  } finally { await fs.rm(dir, { recursive: true, force: true }); }
});
test('built-in recovery checks exercise production tools in isolation', async () => {
  const report = await runReliabilityChecks('test-version');
  assert.equal(report.version, 'test-version'); assert.equal(report.checks.length, process.platform === 'win32' ? 9 : 10);
  for (const check of report.checks) assert.equal(check.passed, true, `${check.name}: ${check.error}`);
});
