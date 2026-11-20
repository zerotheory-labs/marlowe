export function setupReliability(api) {
  const $ = id => document.getElementById(id);
  const make = (tag, text, cls) => { const n = document.createElement(tag); if (text !== undefined) n.textContent = text; if (cls) n.className = cls; return n; };
  let data = { runs: [] };
  function checks(reports) {
    const history = Array.isArray(reports) ? reports : reports ? [reports] : [];
    const report = history[0];
    const host = $('reliability-check-results'); host.replaceChildren();
    if (!report) { host.append(make('p', 'No checks recorded yet.', 'settings-note')); return; }
    host.append(make('p', `${new Date(report.time).toLocaleString()} · app ${report.version}`, 'settings-note'));
    for (const check of report.checks) {
      const row = make('div', undefined, 'reliability-check-result');
      const glyph = make('i', undefined, `glyph ${check.passed ? 'holds' : 'fails'}`);
      glyph.setAttribute('aria-hidden', 'true');
      row.append(glyph, document.createTextNode(`${check.passed ? 'PASS' : 'FAIL'} · ${check.name}${check.error ? ' — ' + check.error : ''}`));
      row.dataset.passed = String(check.passed); host.append(row);
    }
    if (history.length > 1) {
      const older = make('details'); older.append(make('summary', 'Previous checks (up to 20 reports)'));
      for (const previous of history.slice(1)) older.append(make('p', `${new Date(previous.time).toLocaleString()} · app ${previous.version} · ${previous.checks.filter(c => c.passed).length}/${previous.checks.length} passed`, 'settings-note'));
      host.append(older);
    }
  }
  function render() {
    const runs = data.runs.filter(r => (!$('reliability-model').value || r.model === $('reliability-model').value) && (!$('reliability-version').value || r.version === $('reliability-version').value));
    const actions = runs.flatMap(r => r.actions), requested = actions.filter(a => a.approval !== 'not requested');
    const measured = runs.filter(r => r.guardInstrumented), guardRuns = measured.filter(r => r.guards > 0);
    const metrics = [
      ['Runs', runs.length, `${runs.filter(r => r.status === 'finished').length} finished · ${runs.filter(r => r.status === 'error').length} errored · ${runs.filter(r => r.status === 'stopped').length} stopped · ${runs.filter(r => ['active', 'incomplete'].includes(r.status)).length} active/incomplete`],
      ['Tool failures', actions.filter(a => a.failed).length, `of ${actions.length} recorded actions; includes command failures`],
      ['Approval requests', requested.length, `${requested.filter(a => a.approval === 'approved').length} approved · ${requested.filter(a => a.approval === 'denied').length} denied · ${requested.filter(a => ['pending', 'unresolved'].includes(a.approval)).length} pending/unresolved`],
      ['Unsupported claims detected', measured.length ? measured.reduce((n, r) => n + r.guards, 0) : '—', `${measured.length} instrumented runs; detection is heuristic, not a count of all false claims`],
      ['Claim recovery', guardRuns.length ? `${guardRuns.filter(r => r.status === 'finished' && !r.exhausted).length}/${guardRuns.length}` : '—', 'Flagged runs that finished without exhausting retries; not proof of task success'],
      ['Undo outcomes', runs.reduce((n, r) => n + r.undo.filter(e => e.status === 'undo-completed').length, 0), `${runs.reduce((n, r) => n + r.undo.filter(e => e.status === 'undo-error').length, 0)} failed restores; only recorded outcomes`]
    ];
    const host = $('reliability-metrics'); host.replaceChildren();
    for (const [label, value, note] of metrics) { const card = make('div', undefined, 'reliability-metric'); card.append(make('span', label), make('strong', String(value)), make('small', note)); host.append(card); }
    $('reliability-notice').textContent = `${runs.length} matching runs. Latest 200 local run logs. ${data.limited ? 'Older runs omitted. ' : ''}${data.skipped ? data.skipped + ' logs unreadable, partial, or oversized. ' : ''}Legacy runs may lack model, version, claim-detection, and Undo telemetry. Use Refresh to update.`;
    const list = $('reliability-runs'); list.replaceChildren();
    if (!runs.length) list.append(make('p', 'No runs match these filters. Use Agent mode to collect evidence.', 'settings-note'));
    for (const run of runs) {
      const row = make('details', undefined, 'reliability-run');
      row.append(make('summary', `${run.time ? new Date(run.time).toLocaleString() : 'Unknown time'} · ${run.model} · v${run.version} · ${run.status}${run.exhausted ? ' · recovery exhausted' : ''}${run.partial ? ' · partial log' : ''}`));
      row.append(make('p', `Workspace: ${run.workspace || 'Unknown'} · ${run.durationMs === null ? 'Duration unavailable' : (run.durationMs / 1000).toFixed(1) + 's'} · ${run.guardInstrumented ? run.guards + ' detected claims' : 'Claim detection not recorded'} · Run ${run.id}`));
      if (run.error) row.append(make('p', run.error));
      const table = make('table'), header = make('tr'); for (const name of ['Tool / target', 'Outcome', 'Approval']) header.append(make('th', name)); table.append(header);
      for (const action of run.actions) { const tr = make('tr'); tr.append(make('td', `${action.name} · ${action.title}`), make('td', `${action.failed ? 'failed' : action.status}${action.detail ? ' — ' + action.detail : ''}`), make('td', action.approval)); table.append(tr); }
      row.append(table);
      for (const undo of run.undo) row.append(make('p', `${undo.status}: ${undo.time}${undo.message ? ' — ' + undo.message : ''}`));
      list.append(row);
    }
  }
  async function refresh() {
    $('reliability-refresh').disabled = true;
    try {
      data = await api.reliability();
      for (const [id, key, label] of [['reliability-model', 'model', 'All models'], ['reliability-version', 'version', 'All versions']]) {
        const select = $(id), previous = select.value; select.replaceChildren(new Option(label, ''));
        for (const value of [...new Set(data.runs.map(r => r[key]))].sort()) select.add(new Option(value, value));
        if ([...select.options].some(o => o.value === previous)) select.value = previous;
      }
      render(); checks(data.checks);
    } catch (e) { $('reliability-notice').textContent = 'Could not load reliability data: ' + e.message; }
    finally { $('reliability-refresh').disabled = false; }
  }
  $('reliability-button').addEventListener('click', () => { $('reliability-dialog').showModal(); refresh(); });
  $('reliability-refresh').addEventListener('click', refresh);
  for (const id of ['reliability-model', 'reliability-version']) $(id).addEventListener('change', render);
  $('reliability-check').addEventListener('click', async () => {
    const button = $('reliability-check'); button.disabled = true; button.textContent = 'Running checks…';
    try { const result = await api.runReliabilityChecks(); data.checks = result; checks(result); }
    catch (e) { $('reliability-check-results').textContent = e.message; }
    finally { button.disabled = false; button.textContent = 'Run checks'; }
  });
}
