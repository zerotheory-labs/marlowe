const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const STATUSES = ['open', 'verified', 'mitigated', 'false-positive'];
const CORE_PACK_IDS = ['gitleaks', 'osv-scanner', 'trivy', 'semgrep'];

export function setupCyber(api, { notify, caught, onDraftFix, onDraftShield, onAuditFile, onScopeUpdated, onSwitchTab, onInstallCommand }) {
  const $ = id => document.getElementById(id);
  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  };

  let scope = { targets: [], allowOsv: true, redactContext: true };
  let draftTargets = [];
  let findings = [];
  let dnaData = null;
  let dnaFilter = 'all';
  let lockedDnaPath = null;

  function updateBadge() {
    const active = findings.filter(f => f.status === 'open' || f.status === 'verified').length;
    const badge = $('findings-badge');
    if (badge) {
      badge.textContent = String(active);
      badge.hidden = active === 0;
    }
  }

  function updateScopeBadge() {
    const count = scope?.targets?.length || 0;
    const badge = $('scope-count-badge');
    if (badge) {
      badge.textContent = String(count);
      badge.hidden = count === 0;
    }
  }

  function renderScopeTargets() {
    const host = $('scope-targets-list');
    host.replaceChildren();
    if (!draftTargets.length) {
      host.append(el('p', 'settings-note', 'Workspace-only mode (no external network targets authorized).'));
      return;
    }
    for (const target of draftTargets) {
      const chip = el('span', 'scope-chip');
      chip.append(el('code', '', target));
      const remove = el('button', 'scope-chip-remove', '×');
      remove.type = 'button';
      remove.setAttribute('aria-label', `Remove ${target}`);
      remove.addEventListener('click', () => {
        draftTargets = draftTargets.filter(t => t !== target);
        renderScopeTargets();
      });
      chip.append(remove);
      host.append(chip);
    }
  }

  async function refreshToolchain() {
    const button = $('toolchain-refresh');
    const host = $('toolchain-results');
    button.disabled = true;
    button.textContent = 'Scanning…';
    try {
      const report = await api.scanToolchain();
      host.replaceChildren();
      $('toolchain-summary').textContent = `${report.availableCount} of ${report.totalCount} local security CLIs ready on login PATH.`;
      const missingCore = report.tools.filter(t => CORE_PACK_IDS.includes(t.id) && !t.available);
      const installCoreBtn = $('toolchain-install-core');
      if (installCoreBtn) {
        installCoreBtn.hidden = missingCore.length === 0 || !onInstallCommand;
        if (missingCore.length > 0) {
          installCoreBtn.textContent = `Install Core Pack (${missingCore.length})`;
          installCoreBtn.onclick = () => onInstallCommand(`brew install ${missingCore.map(t => t.id).join(' ')}`);
        }
      }
      for (const tool of report.tools) {
        const card = el('div', 'toolchain-card');
        card.dataset.available = String(tool.available);
        const top = el('div', 'toolchain-card-head');
        const labelWrap = el('span', 'toolchain-title-wrap');
        const glyph = el('i', `glyph ${tool.available ? 'holds' : 'unknown'}`);
        glyph.setAttribute('aria-hidden', 'true');
        labelWrap.append(glyph, el('strong', '', tool.label));
        top.append(labelWrap, el('span', `zt-tag ${tool.available ? 'green' : ''}`, tool.available ? 'READY' : 'MISSING'));
        const meta = el('div', 'toolchain-meta', `${tool.category}${tool.profiles?.length ? ' · ' + tool.profiles.join(', ') : ''}`);
        const detailRow = el('div', 'toolchain-detail-row');
        const detail = el('div', 'toolchain-detail', tool.available ? `${tool.version} (${tool.binaryPath})` : tool.installHint);
        detailRow.append(detail);
        if (!tool.available && onInstallCommand && /^brew install [a-z0-9-]+$/i.test(tool.installHint || '')) {
          const installBtn = el('button', 'secondary-button toolchain-install-btn', 'Install →');
          installBtn.type = 'button';
          installBtn.addEventListener('click', () => onInstallCommand(tool.installHint));
          detailRow.append(installBtn);
        }
        card.append(top, meta, detailRow);
        host.append(card);
      }
    } catch (error) {
      $('toolchain-summary').textContent = 'Could not scan local security toolchain: ' + error.message;
    } finally {
      button.disabled = false;
      button.textContent = 'Refresh';
    }
  }

  function openScopeView() {
    draftTargets = [...(scope.targets || [])];
    $('scope-allow-osv').checked = scope.allowOsv !== false;
    $('scope-redact-context').checked = scope.redactContext !== false;
    $('scope-target-input').value = '';
    $('scope-error').textContent = '';
    renderScopeTargets();
    onSwitchTab('scope');
    refreshToolchain();
  }

  $('add-scope-target').addEventListener('click', () => {
    const raw = $('scope-target-input').value.trim();
    if (!raw) return;
    $('scope-error').textContent = '';
    if (!draftTargets.some(t => t.toLowerCase() === raw.toLowerCase())) {
      draftTargets.push(raw);
      renderScopeTargets();
    }
    $('scope-target-input').value = '';
    $('scope-target-input').focus();
  });

  $('scope-target-input').addEventListener('keydown', event => {
    if (event.key === 'Enter') {
      event.preventDefault();
      $('add-scope-target').click();
    }
  });

  $('scope-form').addEventListener('submit', async event => {
    event.preventDefault();
    const pendingInput = $('scope-target-input').value.trim();
    if (pendingInput && !draftTargets.some(t => t.toLowerCase() === pendingInput.toLowerCase())) {
      draftTargets.push(pendingInput);
      $('scope-target-input').value = '';
    }
    const submitter = event.submitter;
    if (submitter) submitter.disabled = true;
    $('scope-error').textContent = '';
    try {
      scope = await api.saveScope({
        targets: draftTargets,
        allowOsv: $('scope-allow-osv').checked,
        redactContext: $('scope-redact-context').checked
      });
      draftTargets = [...scope.targets];
      renderScopeTargets();
      updateScopeBadge();
      onScopeUpdated(scope);
      notify(`Authorized Scope saved (${scope.targets.length} target${scope.targets.length === 1 ? '' : 's'}).`);
    } catch (error) {
      $('scope-error').textContent = error.message?.replace(/^Error invoking remote method '[^']+': Error: /, '') || String(error);
    } finally {
      if (submitter) submitter.disabled = false;
    }
  });

  $('toolchain-refresh').addEventListener('click', refreshToolchain);
  $('scope-button').addEventListener('click', openScopeView);

  function renderFindings() {
    const sevFilter = $('findings-severity-filter').value;
    const statusFilter = $('findings-status-filter').value;
    const metricsHost = $('findings-metrics');
    metricsHost.replaceChildren();
    for (const sev of SEVERITIES) {
      const count = findings.filter(f => f.severity === sev && (f.status === 'open' || f.status === 'verified')).length;
      const card = el('div', 'finding-metric');
      card.dataset.severity = sev;
      card.append(el('span', '', sev.slice(0, 4).toUpperCase()), el('strong', '', String(count)));
      metricsHost.append(card);
    }

    const filtered = findings.filter(f => {
      if (sevFilter && f.severity !== sevFilter) return false;
      if (statusFilter === 'active') return f.status === 'open' || f.status === 'verified';
      if (statusFilter && f.status !== statusFilter) return false;
      return true;
    });
    const listHost = $('findings-list');
    listHost.replaceChildren();
    $('findings-empty').hidden = filtered.length > 0;
    $('clear-findings').disabled = findings.length === 0;
    for (const item of filtered) {
      const isResolved = item.status === 'mitigated' || item.status === 'false-positive';
      const card = el('article', 'finding-card');
      card.dataset.severity = item.severity;
      if (isResolved) card.dataset.resolved = 'true';
      const head = el('div', 'finding-head');
      const glyph = el('i', `glyph ${isResolved ? 'holds' : ['critical', 'high'].includes(item.severity) ? 'fails' : item.severity === 'medium' ? 'unknown' : 'holds'}`);
      glyph.setAttribute('aria-hidden', 'true');
      const tagColor = isResolved ? 'green' : ['critical', 'high'].includes(item.severity) ? 'rose' : item.severity === 'medium' ? 'sand' : 'sky';
      const pill = el('span', `zt-tag ${tagColor} severity-pill`, isResolved ? item.status.toUpperCase() : item.severity.toUpperCase());
      pill.dataset.severity = item.severity;
      const title = el('strong', 'finding-title', item.title);
      head.append(glyph, pill, title);

      const metaLine = [item.location, item.cwe, item.mitre, item.cvss !== null && item.cvss !== undefined ? `CVSS ${item.cvss}` : ''].filter(Boolean).join(' · ');
      const loc = el('div', 'finding-location', metaLine);
      const details = el('details', 'finding-details');
      details.append(el('summary', '', 'Evidence & remediation'));
      if (item.evidence) details.append(el('div', 'finding-section-label', 'Evidence'), el('pre', '', item.evidence));
      if (item.remediation) details.append(el('div', 'finding-section-label', 'Remediation'), el('p', 'finding-remediation', item.remediation));

      const actions = el('div', 'finding-actions');
      const statusSelect = el('select', 'finding-status-select');
      statusSelect.setAttribute('aria-label', `Status for ${item.title}`);
      for (const st of STATUSES) {
        statusSelect.add(new Option(st, st, st === item.status, st === item.status));
      }
      statusSelect.addEventListener('change', caught(async () => {
        findings = await api.updateFinding(item.id, { status: statusSelect.value });
        updateBadge();
        renderFindings();
      }));

      const fixBtn = el('button', 'secondary-button compact-btn', 'Draft Fix');
      fixBtn.type = 'button';
      fixBtn.addEventListener('click', () => {
        onSwitchTab('assistant');
        onDraftFix(item);
      });

      let shieldBtn = null;
      if (!isResolved && onDraftShield) {
        shieldBtn = el('button', 'secondary-button compact-btn', 'Draft Shield');
        shieldBtn.type = 'button';
        shieldBtn.title = 'Draft a temporary Shirudo eBPF upatch shield in Agent mode';
        shieldBtn.addEventListener('click', () => {
          onSwitchTab('assistant');
          onDraftShield(item);
        });
      }

      const sameTitleActive = findings.filter(f => (f.status === 'open' || f.status === 'verified') && f.title === item.title);
      let dismissRuleBtn = null;
      if (!isResolved && sameTitleActive.length > 1) {
        dismissRuleBtn = el('button', 'secondary-button compact-btn', `Dismiss Rule (×${sameTitleActive.length})`);
        dismissRuleBtn.type = 'button';
        dismissRuleBtn.title = `Mark all ${sameTitleActive.length} "${item.title}" findings as false-positive`;
        dismissRuleBtn.addEventListener('click', caught(async () => {
          dismissRuleBtn.disabled = true;
          for (const dup of sameTitleActive) {
            findings = await api.updateFinding(dup.id, { status: 'false-positive' });
          }
          updateBadge();
          renderFindings();
          notify(`Marked all ${sameTitleActive.length} "${item.title}" findings as false-positive.`);
        }));
      }

      const delBtn = el('button', 'text-button', 'Delete');
      delBtn.type = 'button';
      delBtn.addEventListener('click', caught(async () => {
        findings = await api.deleteFinding(item.id);
        updateBadge();
        renderFindings();
      }));

      actions.append(statusSelect, fixBtn, ...(shieldBtn ? [shieldBtn] : []), ...(dismissRuleBtn ? [dismissRuleBtn] : []), delBtn);
      card.append(head, loc, details, actions);
      listHost.append(card);
    }
  }

  async function openFindingsView() {
    findings = await api.listFindings();
    updateBadge();
    renderFindings();
    onSwitchTab('findings');
  }

  $('findings-button').addEventListener('click', caught(openFindingsView));
  $('findings-severity-filter').addEventListener('change', renderFindings);
  $('findings-status-filter').addEventListener('change', renderFindings);
  $('clear-findings').addEventListener('click', caught(async () => {
    findings = await api.clearFindings();
    updateBadge();
    renderFindings();
    notify('Cleared workspace findings ledger.');
  }));

  for (const [id, format] of [['export-markdown', 'markdown'], ['export-sarif', 'sarif'], ['export-json', 'json']]) {
    $(id).addEventListener('click', caught(async () => {
      const res = await api.exportFindings(format);
      if (!res.canceled) notify(`Exported ${res.count} finding(s) as ${res.format.toUpperCase()} to ${res.filePath}`);
    }));
  }

  let dnaRefreshing = false;
  api.onFindingsChanged(next => {
    findings = Array.isArray(next) ? next : [];
    updateBadge();
    if (!$('findings-dialog').hidden) renderFindings();
    if (!$('dna-dialog')?.hidden && !dnaRefreshing) refreshDna();
  });

  function formatBytes(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  }

  function dotStatusColor(item) {
    if (item.maxSeverity === 'critical' || item.maxSeverity === 'high') return { cls: 'crit', hex: '#f26d5b', label: item.maxSeverity.toUpperCase() };
    if (item.maxSeverity === 'medium' || item.maxSeverity === 'low' || item.maxSeverity === 'info') {
      return { cls: 'warn', hex: '#f2c14e', label: item.maxSeverity.toUpperCase() };
    }
    if (item.kind === 'binary' || item.kind === 'capture') return { cls: 'binary', hex: '#7eafff', label: item.kind.toUpperCase() };
    if (item.kind === 'upatch') return { cls: 'clean', hex: '#3ddc97', label: 'UPATCH' };
    return { cls: 'clean', hex: '#3ddc97', label: 'CLEAN' };
  }

  function renderDnaInspector(item) {
    const box = $('dna-inspector');
    if (!box) return;
    if (!item) {
      box.hidden = true;
      return;
    }
    box.hidden = false;
    box.replaceChildren();
    const st = dotStatusColor(item);

    const head = el('div', 'dna-insp-head');
    const pathEl = el('code', 'dna-insp-path', item.path);
    const badge = el('span', `zt-tag ${st.cls === 'crit' ? 'rose' : st.cls === 'warn' ? 'sand' : st.cls === 'binary' ? 'sky' : 'green'}`, st.label);
    head.append(pathEl, badge);

    const meta = el('div', 'dna-insp-meta', `${item.kind.toUpperCase()} · ${formatBytes(item.size)} · Shannon entropy ${item.entropy.toFixed(2)} / 8.00 b/B`);

    const barTrack = el('div', 'dna-entropy-track');
    const barFill = el('div', 'dna-entropy-fill');
    barFill.style.width = `${Math.min(100, Math.round((item.entropy / 8) * 100))}%`;
    barFill.style.background = st.hex;
    const thresholdMark = el('span', 'dna-entropy-mark');
    thresholdMark.style.left = '80%'; // 6.4 / 8.0
    barTrack.append(barFill, thresholdMark);

    const enginesRow = el('div', 'dna-engines-row');
    enginesRow.append(el('span', 'dna-engines-label', 'CLI COVERAGE:'));
    for (const eng of item.engines || []) {
      enginesRow.append(el('span', 'dna-engine-chip', eng));
    }

    box.append(head, meta, barTrack, enginesRow);

    if (item.topFinding) {
      const fNote = el('div', 'dna-finding-callout', `[${item.topFinding.severity.toUpperCase()}${item.topFinding.cwe ? ' · ' + item.topFinding.cwe : ''}] ${item.topFinding.title}${item.findingCount > 1 ? ` (+${item.findingCount - 1} more)` : ''}`);
      box.append(fNote);
    }

    const actions = el('div', 'dna-insp-actions');
    if (onAuditFile) {
      const auditBtn = el('button', 'primary-button compact-btn', item.kind === 'binary' || item.kind === 'capture' ? 'Triage Artifact →' : 'Audit File →');
      auditBtn.type = 'button';
      auditBtn.addEventListener('click', () => onAuditFile(item));
      actions.append(auditBtn);
    }
    if (item.findingCount > 0) {
      if (Array.isArray(item.openFindingIds) && item.openFindingIds.length > 0) {
        const applyBulkStatus = (nextStatus, verb) => caught(async () => {
          for (const fid of item.openFindingIds) {
            findings = await api.updateFinding(fid, { status: nextStatus });
          }
          updateBadge();
          await refreshDna();
          notify(`Marked ${item.openFindingIds.length} finding(s) in ${item.path} as ${verb}.`);
        });
        const resolveBtn = el('button', 'secondary-button compact-btn', 'Mark Mitigated ✓');
        resolveBtn.type = 'button';
        resolveBtn.addEventListener('click', applyBulkStatus('mitigated', 'mitigated'));
        const fpBtn = el('button', 'secondary-button compact-btn', 'False Positive');
        fpBtn.type = 'button';
        fpBtn.addEventListener('click', applyBulkStatus('false-positive', 'false-positive'));
        actions.append(resolveBtn, fpBtn);
      }
      const viewBtn = el('button', 'secondary-button compact-btn', `View Finding (${item.findingCount})`);
      viewBtn.type = 'button';
      viewBtn.addEventListener('click', caught(openFindingsView));
      actions.append(viewBtn);
    }
    box.append(actions);
  }

  function svgEl(tag, attrs = {}, text = '') {
    const n = document.createElementNS('http://www.w3.org/2000/svg', tag);
    for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, String(v));
    if (text) n.textContent = text;
    return n;
  }

  function renderDna() {
    const metricsHost = $('dna-metrics');
    const emptyNote = $('dna-empty');
    const stageWrap = $('dna-stage-wrap');
    const svg = $('dna-svg');
    if (!metricsHost || !svg) return;

    metricsHost.replaceChildren();
    svg.replaceChildren();

    if (!dnaData || dnaData.needsWorkspace) {
      emptyNote.textContent = 'Choose a project workspace folder in the top bar (or cd into a project in zsh and click Agent) to map its file entropy & security DNA.';
      emptyNote.hidden = false;
      stageWrap.hidden = true;
      renderDnaInspector(null);
      return;
    }

    const s = dnaData.summary;
    const issueCount = s.openFindingsCount ?? s.hotspotCount ?? 0;
    for (const [label, val, tone] of [
      ['FILES', String(s.totalFiles), ''],
      ['PEAK b/B', s.peakEntropy.toFixed(2), s.peakEntropy >= 6.8 ? 'warn' : ''],
      ['OPEN ISSUES', String(issueCount), issueCount > 0 ? 'crit' : ''],
      ['CLIs', `${s.readyCount}/${s.totalEngines}`, 'ok']
    ]) {
      const tile = el('div', 'finding-metric');
      if (tone === 'crit') tile.dataset.severity = 'critical';
      if (tone === 'warn') tile.dataset.severity = 'medium';
      if (tone === 'ok') tile.dataset.severity = 'ok';
      tile.append(el('span', '', label), el('strong', '', val));
      metricsHost.append(tile);
    }

    const filtered = dnaData.files.filter(f => {
      if (dnaFilter === 'hotspots') return f.findingCount > 0 || (f.entropy >= 7.2 && !/\.(?:woff2|png|jpg|mp4|gz|zip)$/i.test(f.path));
      if (dnaFilter === 'entropy') return f.entropy >= 6.4;
      if (dnaFilter === 'artifacts') return f.kind === 'binary' || f.kind === 'capture' || f.kind === 'manifest' || f.kind === 'upatch';
      return true;
    });

    if (!filtered.length) {
      emptyNote.textContent = 'No workspace files match the selected DNA filter.';
      emptyNote.hidden = false;
      stageWrap.hidden = true;
      renderDnaInspector(null);
      return;
    }
    emptyNote.hidden = true;
    stageWrap.hidden = false;

    // Group by top-level directory swimlanes (up to 12 lanes; merge tail into other/)
    const laneMap = new Map();
    for (const item of filtered) {
      const key = item.group;
      if (!laneMap.has(key)) laneMap.set(key, []);
      laneMap.get(key).push(item);
    }
    const sortedLanes = [...laneMap.entries()].sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]));
    const lanes = sortedLanes.slice(0, 10);
    if (sortedLanes.length > 10) {
      lanes.push(['other/', sortedLanes.slice(10).flatMap(([, arr]) => arr)]);
    }

    const W = 440;
    const X_MIN = 96;
    const X_MAX = 424;
    const TOP_PAD = 28;
    const LANE_H = 34;
    const H = TOP_PAD + lanes.length * LANE_H + 14;
    svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
    svg.style.height = `${H}px`;

    const xForEntropy = e => {
      const clamped = Math.max(2.0, Math.min(8.0, e || 2.0));
      return Math.round(X_MIN + ((clamped - 2.0) / 6.0) * (X_MAX - X_MIN));
    };

    // Entropy axis ticks & 6.4 b/B high-entropy boundary
    for (const tick of [2, 4, 5, 6.4, 8]) {
      const tx = xForEntropy(tick);
      svg.append(
        svgEl('line', {
          x1: tx, y1: 20, x2: tx, y2: H - 8,
          stroke: tick === 6.4 ? '#f2c14e' : 'currentColor',
          'stroke-opacity': tick === 6.4 ? '0.45' : '0.1',
          'stroke-dasharray': tick === 6.4 ? '3 3' : 'none'
        }),
        svgEl('text', {
          x: tx, y: 14,
          'text-anchor': tick === 8 ? 'end' : tick === 2 ? 'start' : 'middle',
          fill: tick === 6.4 ? '#f2c14e' : 'currentColor',
          'fill-opacity': tick === 6.4 ? '0.9' : '0.5',
          'font-size': '8.5'
        }, tick === 6.4 ? '6.4 HIGH' : `${tick}.0`)
      );
    }

    let defaultTarget = filtered.find(f => f.path === lockedDnaPath)
      || filtered.find(f => f.findingCount > 0)
      || filtered.reduce((best, f) => (!best || f.entropy > best.entropy ? f : best), null);

    lanes.forEach(([laneName, laneFiles], rowIdx) => {
      const cyBase = TOP_PAD + rowIdx * LANE_H + 14;
      svg.append(
        svgEl('line', { x1: X_MIN, y1: cyBase, x2: X_MAX, y2: cyBase, stroke: 'currentColor', 'stroke-opacity': '0.07' }),
        svgEl('text', { x: 6, y: cyBase + 3.5, fill: 'currentColor', 'fill-opacity': '0.68', 'font-size': '9.5' }, laneName.length > 12 ? laneName.slice(0, 11) + '…' : laneName)
      );

      // Gentle vertical jitter within swimlane when multiple files share identical X buckets
      const bucketCounts = new Map();
      laneFiles.forEach(fileItem => {
        const baseX = xForEntropy(fileItem.entropy);
        const bucket = Math.round(baseX / 7);
        const seen = bucketCounts.get(bucket) || 0;
        bucketCounts.set(bucket, seen + 1);
        const offsetY = seen === 0 ? 0 : (seen % 2 === 1 ? -1 : 1) * Math.min(9, Math.ceil(seen / 2) * 4.5);
        const cx = baseX;
        const cy = cyBase + offsetY;
        const st = dotStatusColor(fileItem);
        const r = fileItem.findingCount > 0 ? 5.6 : Math.max(3.3, Math.min(5.2, 2.6 + Math.log10(Math.max(10, fileItem.size)) * 0.55));
        const isLocked = lockedDnaPath === fileItem.path;

        const g = svgEl('g', { class: 'dna-dot-node' });
        if (fileItem.findingCount > 0 || st.cls === 'warn') {
          g.append(svgEl('circle', { cx, cy, r: r + 3.8, fill: 'none', stroke: st.hex, 'stroke-opacity': '0.42', 'stroke-width': '1.2' }));
        }
        if (isLocked) {
          g.append(svgEl('circle', { cx, cy, r: r + 5.5, fill: 'none', stroke: 'currentColor', 'stroke-width': '1.4' }));
        }
        g.append(svgEl('circle', {
          cx, cy, r,
          fill: st.hex,
          'fill-opacity': fileItem.findingCount > 0 || isLocked ? '1' : '0.78'
        }));
        if (fileItem.findingCount > 1) {
          g.append(svgEl('text', {
            x: cx + r + 3.5,
            y: cy - r + 1,
            fill: st.hex,
            'font-size': '8.5',
            'font-weight': '600'
          }, `×${fileItem.findingCount}`));
        }
        g.addEventListener('mouseenter', () => {
          if (!lockedDnaPath) renderDnaInspector(fileItem);
        });
        g.addEventListener('click', () => {
          lockedDnaPath = lockedDnaPath === fileItem.path ? null : fileItem.path;
          renderDna();
          renderDnaInspector(fileItem);
        });
        svg.append(g);
      });
    });

    renderDnaInspector(defaultTarget);
  }

  async function refreshDna() {
    const btn = $('dna-refresh');
    dnaRefreshing = true;
    if (btn) { btn.disabled = true; btn.textContent = 'Mapping…'; }
    try {
      dnaData = await api.scanDna();
      renderDna();
      if (dnaData?.autoMitigated > 0) {
        notify(`Cleared ${dnaData.autoMitigated} remediated finding(s) → node marked Clean.`);
      }
    } catch (err) {
      notify('Could not map workspace DNA: ' + err.message);
    } finally {
      dnaRefreshing = false;
      if (btn) { btn.disabled = false; btn.textContent = 'Rescan'; }
    }
  }

  async function openDnaView() {
    onSwitchTab('dna');
    await refreshDna();
  }

  $('dna-button')?.addEventListener('click', caught(openDnaView));
  $('dna-refresh')?.addEventListener('click', caught(refreshDna));
  document.querySelectorAll('[data-dna-filter]').forEach(btn => {
    btn.addEventListener('click', () => {
      dnaFilter = btn.dataset.dnaFilter;
      document.querySelectorAll('[data-dna-filter]').forEach(b => b.classList.toggle('active', b === btn));
      renderDna();
    });
  });

  return {
    init(initialScope, initialFindings) {
      if (initialScope) scope = initialScope;
      if (Array.isArray(initialFindings)) findings = initialFindings;
      updateBadge();
      updateScopeBadge();
      onScopeUpdated(scope);
    },
    getScope: () => scope,
    syncFindings: async () => {
      findings = await api.listFindings();
      updateBadge();
      if (!$('findings-dialog').hidden) renderFindings();
      if (!$('dna-dialog')?.hidden) refreshDna();
    },
    refreshToolchain,
    refreshDna,
    openDnaDialog: openDnaView,
    openScopeDialog: openScopeView,
    openFindingsDialog: openFindingsView
  };
}
