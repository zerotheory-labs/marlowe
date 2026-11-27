const NS = 'http://www.w3.org/2000/svg';

function el(tag, className, text) {
  const n = document.createElement(tag);
  if (className) n.className = className;
  if (text !== undefined) n.textContent = text;
  return n;
}

function svgEl(tag, attrs = {}, text = '') {
  const n = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, String(v));
  if (text) n.textContent = text;
  return n;
}

function themeColors() {
  const light = document.documentElement.dataset.theme === 'light';
  return {
    bg: light ? '#f8f6f1' : '#1b1917',
    stage: light ? '#eae6dc' : '#151412',
    ink: light ? '#131210' : '#f2efe8',
    soft: light ? '#383530' : '#d2cec5',
    mute: light ? '#6b665e' : '#a39f96',
    line: light ? '#d1ccc0' : '#363430',
    signal: light ? '#176b45' : '#3ddc97',
    signalFill: '#3ddc97',
    crit: light ? '#c93b2b' : '#f26d5b',
    warn: light ? '#8a5b00' : '#f2c14e',
    info: light ? '#1f56b5' : '#7eafff'
  };
}

function fitText(str, max) {
  const s = String(str || '');
  return s.length > max ? s.slice(0, max - 1) + '…' : s;
}

function colorForStatus(status, c) {
  if (status === 'not-scanned') return c.mute;
  if (status === 'scanned') return c.info;
  if (status === 'crit') return c.crit;
  if (status === 'warn') return c.warn;
  if (status === 'binary' || status === 'scope') return c.info;
  return c.signal;
}

export function setupStageGraphs(api, {
  stageHost,
  tabsHost,
  caught,
  notify,
  onSelectGraphTab,
  onEnsureWorkspace,
  onAuditAsset,
  onDraftFix,
  onDraftShield,
  onOpenDna,
  onOpenScope,
  onFindingsMutated
}) {
  let graphData = null;
  let activeGraph = null; // 'convergence' | 'reachability' | null
  let selectedConvId = null;
  let selectedLaneId = null;
  let loading = false;
  let refreshPending = false;

  const views = new Map();

  function createGraphTab(id, label, titleText, subtitleText) {
    const tab = el('div', 'terminal-tab terminal-tab-graph');
    const select = el('button', 'tab-select', label);
    select.id = `${id}-tab`;
    select.type = 'button';
    select.setAttribute('role', 'tab');
    select.setAttribute('aria-selected', 'false');
    tab.append(select);
    tabsHost.append(tab);

    const host = el('div', 'stage-graph-host inactive');
    host.id = `${id}-stage`;
    host.dataset.graph = id;

    const head = el('div', 'stage-graph-head');
    const headLeft = el('div', 'stage-graph-titles');
    headLeft.append(el('h3', 'stage-graph-title', titleText), el('p', 'stage-graph-sub', subtitleText));

    const headRight = el('div', 'stage-graph-controls');
    const pills = el('div', 'stage-graph-pills');
    const rescanBtn = el('button', 'secondary-button compact-btn', 'Rescan');
    rescanBtn.type = 'button';
    rescanBtn.addEventListener('click', caught(() => refresh(true)));
    headRight.append(pills, rescanBtn);
    head.append(headLeft, headRight);

    const canvasWrap = el('div', 'stage-graph-canvas');
    const svg = svgEl('svg', {
      class: 'stage-graph-svg',
      viewBox: '0 0 860 430',
      preserveAspectRatio: 'xMidYMid meet',
      'aria-label': titleText
    });
    canvasWrap.append(svg);

    const emptyBanner = el('div', 'stage-graph-empty');
    emptyBanner.hidden = true;

    const inspector = el('div', 'stage-graph-inspector');
    const inspInfo = el('div', 'stage-insp-info');
    const inspBadge = el('span', 'zt-tag green', 'READY');
    const inspText = el('span', 'stage-insp-text', 'Select a node to inspect scanner results and recorded findings.');
    inspInfo.append(inspBadge, inspText);
    const inspActions = el('div', 'stage-insp-actions');
    inspector.append(inspInfo, inspActions);

    host.append(head, emptyBanner, canvasWrap, inspector);
    stageHost.append(host);

    select.addEventListener('click', () => onSelectGraphTab(id));

    views.set(id, { id, tab, select, host, pills, rescanBtn, emptyBanner, svg, inspBadge, inspText, inspActions });
  }

  createGraphTab(
    'convergence',
    '10-CLI Convergence',
    '10-CLI Security Convergence',
    'Local security tools, their applicable files, and recorded scan results.'
  );
  createGraphTab(
    'reachability',
    'Attack Reachability',
    'Attack Surface Reachability',
    'Entry surfaces → handlers → code & binary sinks → actionable blast radius vs. severed false positives.'
  );

  function setInspector(view, { badge, tagTone = 'green', text, actions = [] }) {
    view.inspBadge.className = `zt-tag ${tagTone}`;
    view.inspBadge.textContent = badge;
    view.inspText.textContent = text;
    view.inspActions.replaceChildren(...actions);
  }

  function renderPills(view, s) {
    view.pills.replaceChildren();
    if (!s) return;
    view.pills.append(
      el('span', 'zt-tag green', `${s.readyCount}/${s.totalEngines} CLIs`),
      el('span', `zt-tag ${s.openFindingsCount > 0 ? 'rose' : 'green'}`, `${s.openFindingsCount} OPEN`),
      el('span', 'zt-tag sky', `${s.totalFiles} FILES`)
    );
    if (s.resolvedCount > 0) {
      view.pills.append(el('span', 'zt-tag sand', `${s.resolvedCount} SUPPRESSED`));
    }
  }

  function renderConvergence() {
    const view = views.get('convergence');
    if (!view || !graphData) return;
    const c = themeColors();
    const { summary: s, convergence, needsWorkspace } = graphData;
    renderPills(view, s);
    view.svg.replaceChildren();

    view.emptyBanner.replaceChildren();
    if (needsWorkspace) {
      view.emptyBanner.hidden = false;
      view.emptyBanner.append(
        el('span', '', 'No project workspace selected yet — showing installed CLI posture. '),
        (() => {
          const b = el('button', 'primary-button compact-btn', 'Choose Workspace →');
          b.type = 'button';
          b.addEventListener('click', caught(async () => {
            await onEnsureWorkspace(true);
            await refresh();
          }));
          return b;
        })()
      );
    } else {
      view.emptyBanner.hidden = true;
    }

    const { engines, assets, impacts } = convergence;

    // Column headers
    for (const [label, x] of [
      [`01 · LOCAL CLIs (${s.readyCount}/${s.totalEngines} READY)`, 24],
      ['02 · LIVE WORKSPACE & SCOPE ASSETS', 300],
      ['03 · RECORDED RESULTS', 612]
    ]) {
      view.svg.append(svgEl('text', {
        x, y: 22, fill: c.mute, 'font-size': '10', 'letter-spacing': '1.2', 'font-weight': '500'
      }, label));
    }

    const engStep = engines.length > 1 ? Math.min(41, Math.floor(338 / (engines.length - 1))) : 0;
    const engPos = new Map();
    engines.forEach((eng, i) => {
      engPos.set(eng.id, { ...eng, x: 24, w: 192, y: 48 + i * engStep });
    });

    const assetSpacing = assets.length > 1 ? Math.min(58, Math.floor(336 / Math.max(1, assets.length - 1))) : 0;
    const assetStartY = assets.length ? Math.round(228 - ((assets.length - 1) * assetSpacing) / 2) : 220;
    const assetPos = new Map();
    assets.forEach((a, i) => {
      assetPos.set(a.id, { ...a, x: 300, w: 224, y: assetStartY + i * assetSpacing });
    });

    const impSpacing = impacts.length > 1 ? Math.min(64, Math.floor(320 / Math.max(1, impacts.length - 1))) : 0;
    const impStartY = impacts.length ? Math.round(228 - ((impacts.length - 1) * impSpacing) / 2) : 220;
    const impPos = new Map();
    impacts.forEach((imp, i) => {
      impPos.set(imp.id, { ...imp, x: 612, w: 224, y: impStartY + i * impSpacing });
    });

    const isHighlightedEdge = (engId, asset, impId) => {
      if (!selectedConvId) return true;
      if (selectedConvId === `eng:${engId}`) return true;
      if (selectedConvId === asset.id) return true;
      if (impId && selectedConvId === impId) return true;
      if (selectedConvId.startsWith('imp:') && asset.impactIds.includes(selectedConvId) && (!engId || asset.engineIds.includes(engId))) return true;
      return false;
    };

    // Curves: Engines -> Assets
    for (const a of assetPos.values()) {
      const col = colorForStatus(a.status, c);
      for (const engId of a.engineIds) {
        const e = engPos.get(engId);
        if (!e) continue;
        const active = isHighlightedEdge(engId, a, null);
        const d = `M ${e.x + e.w} ${e.y} C ${e.x + e.w + 48} ${e.y}, ${a.x - 48} ${a.y}, ${a.x} ${a.y}`;
        view.svg.append(svgEl('path', {
          d,
          fill: 'none',
          stroke: e.available ? col : c.line,
          'stroke-width': active && selectedConvId ? '2.1' : '1.45',
          'stroke-dasharray': a.scannedBy?.includes(engId) ? 'none' : '4 4',
          'stroke-opacity': active ? (e.available ? '0.62' : '0.28') : '0.1'
        }));
      }
    }

    // Curves: Assets -> Impacts
    for (const a of assetPos.values()) {
      for (const impId of a.impactIds) {
        const imp = impPos.get(impId);
        if (!imp) continue;
        const col = colorForStatus(imp.status, c);
        const active = isHighlightedEdge(null, a, impId);
        const d = `M ${a.x + a.w} ${a.y} C ${a.x + a.w + 46} ${a.y}, ${imp.x - 46} ${imp.y}, ${imp.x} ${imp.y}`;
        view.svg.append(svgEl('path', {
          d,
          fill: 'none',
          stroke: col,
          'stroke-width': active && selectedConvId ? '2.6' : '2.0',
          'stroke-opacity': active ? '0.82' : '0.12'
        }));
      }
    }

    if (!assets.length) {
      view.svg.append(svgEl('text', {
        x: 405, y: 224, 'text-anchor': 'middle', fill: c.mute, 'font-size': '12'
      }, 'Choose a workspace folder to connect your 10 CLIs to live source files & binaries.'));
    }

    const inspectEngine = e => {
      const covered = assets.filter(a => a.engineIds.includes(e.id));
      const scopeBtn = el('button', 'secondary-button compact-btn', 'Toolchain Doctor');
      scopeBtn.type = 'button';
      scopeBtn.addEventListener('click', () => onOpenScope());
      setInspector(view, {
        badge: e.available ? 'CLI READY' : 'MISSING',
        tagTone: e.available ? 'green' : 'sand',
        text: `${e.label}${e.version ? ` (${e.version})` : ''} · ${e.category} · Applicable to ${covered.length} mapped asset(s).`,
        actions: [scopeBtn]
      });
    };

    const inspectAsset = a => {
      const btns = [];
      if (a.kind !== 'scope' && onAuditAsset) {
        const auditBtn = el('button', 'primary-button compact-btn', a.kind === 'binary' || a.kind === 'capture' ? 'Triage Artifact →' : 'Audit File →');
        auditBtn.type = 'button';
        auditBtn.addEventListener('click', () => onAuditAsset(a));
        btns.push(auditBtn);
      }
      if (a.openFindingIds?.length > 0) {
        for (const [label, st] of [['Mark Mitigated ✓', 'mitigated'], ['False Positive', 'false-positive']]) {
          const b = el('button', 'secondary-button compact-btn', label);
          b.type = 'button';
          b.addEventListener('click', caught(async () => {
            for (const fid of a.openFindingIds) await api.updateFinding(fid, { status: st });
            await onFindingsMutated();
            await refresh();
            notify(`Updated ${a.openFindingIds.length} finding(s) on ${a.path} → ${st}.`);
          }));
          btns.push(b);
        }
      }
      const dnaBtn = el('button', 'secondary-button compact-btn', 'View in DNA');
      dnaBtn.type = 'button';
      dnaBtn.addEventListener('click', () => onOpenDna());
      btns.push(dnaBtn);

      setInspector(view, {
        badge: a.findingCount > 0 ? `${a.findingCount} OPEN` : a.kind === 'scope' ? 'IN SCOPE' : a.scannedBy?.length ? 'Scanned' : 'Not scanned',
        tagTone: a.status === 'crit' ? 'rose' : a.status === 'warn' ? 'sand' : a.status === 'not-scanned' ? 'muted' : 'sky',
        text: a.detail,
        actions: btns
      });
    };

    const inspectImpact = imp => {
      const btns = [];
      if (imp.findingId) {
        const dnaBtn = el('button', 'secondary-button compact-btn', 'Inspect DNA');
        dnaBtn.type = 'button';
        dnaBtn.addEventListener('click', () => onOpenDna());
        btns.push(dnaBtn);
      }
      setInspector(view, {
        badge: imp.badge,
        tagTone: imp.status === 'crit' ? 'rose' : imp.status === 'warn' ? 'sand' : imp.status === 'not-scanned' ? 'muted' : 'sky',
        text: imp.detail,
        actions: btns
      });
    };

    // Draw Engine nodes
    for (const e of engPos.values()) {
      const nodeKey = `eng:${e.id}`;
      const isSel = selectedConvId === nodeKey;
      const g = svgEl('g', { class: 'stage-svg-node' });
      g.append(
        svgEl('rect', {
          x: e.x, y: e.y - 13, width: e.w, height: 26, rx: 13,
          fill: c.bg,
          stroke: isSel ? c.signalFill : c.line,
          'stroke-width': isSel ? '1.8' : '1.1'
        }),
        svgEl('circle', { cx: e.x + 14, cy: e.y, r: 4, fill: e.available ? c.signalFill : c.mute }),
        svgEl('text', { x: e.x + 25, y: e.y + 3.8, fill: c.ink, 'font-size': '10.8', 'font-weight': '500' }, fitText(e.label, 24))
      );
      g.addEventListener('mouseenter', () => { if (!selectedConvId) inspectEngine(e); });
      g.addEventListener('click', () => {
        selectedConvId = selectedConvId === nodeKey ? null : nodeKey;
        renderConvergence();
        inspectEngine(e);
      });
      view.svg.append(g);
    }

    // Draw Asset nodes
    for (const a of assetPos.values()) {
      const col = colorForStatus(a.status, c);
      const isSel = selectedConvId === a.id;
      const g = svgEl('g', { class: 'stage-svg-node' });
      g.append(
        svgEl('rect', {
          x: a.x, y: a.y - 17, width: a.w, height: 34, rx: 8,
          fill: c.bg,
          stroke: col,
          'stroke-width': isSel ? '2.2' : '1.35'
        }),
        svgEl('text', { x: a.x + 12, y: a.y - 1, fill: c.ink, 'font-size': '11', 'font-weight': '600' }, a.label),
        svgEl('text', {
          x: a.x + 12, y: a.y + 11.5, fill: col, 'font-size': '9.2'
        }, a.kind === 'scope' ? 'AUTHORIZED SCOPE' : `${a.kind.toUpperCase()} · ${a.entropy.toFixed(2)} b/B${a.findingCount ? ` · ×${a.findingCount}` : ''}`)
      );
      g.addEventListener('mouseenter', () => { if (!selectedConvId) inspectAsset(a); });
      g.addEventListener('click', () => {
        selectedConvId = selectedConvId === a.id ? null : a.id;
        renderConvergence();
        inspectAsset(a);
      });
      view.svg.append(g);
    }

    // Draw Impact nodes
    for (const imp of impPos.values()) {
      const col = colorForStatus(imp.status, c);
      const isSel = selectedConvId === imp.id;
      const g = svgEl('g', { class: 'stage-svg-node' });
      g.append(
        svgEl('rect', {
          x: imp.x, y: imp.y - 16, width: imp.w, height: 32, rx: 16,
          fill: c.bg,
          stroke: col,
          'stroke-width': isSel ? '2.2' : '1.35'
        }),
        svgEl('text', { x: imp.x + 14, y: imp.y - 1, fill: col, 'font-size': '10.5', 'font-weight': '600' }, imp.label),
        svgEl('text', { x: imp.x + 14, y: imp.y + 11, fill: c.mute, 'font-size': '8.8' }, imp.badge)
      );
      g.addEventListener('mouseenter', () => { if (!selectedConvId) inspectImpact(imp); });
      g.addEventListener('click', () => {
        selectedConvId = selectedConvId === imp.id ? null : imp.id;
        renderConvergence();
        inspectImpact(imp);
      });
      view.svg.append(g);
    }

    if (!selectedConvId) {
      const firstHot = assets.find(a => a.findingCount > 0) || assets[0];
      if (firstHot) inspectAsset(firstHot);
    }
  }

  function renderReachability() {
    const view = views.get('reachability');
    if (!view || !graphData) return;
    const c = themeColors();
    const { summary: s, reachability, needsWorkspace } = graphData;
    renderPills(view, s);
    view.svg.replaceChildren();

    view.emptyBanner.replaceChildren();
    if (needsWorkspace) {
      view.emptyBanner.hidden = false;
      view.emptyBanner.append(
        el('span', '', 'Choose a project workspace to trace live source-to-sink reachability and severed false positives. '),
        (() => {
          const b = el('button', 'primary-button compact-btn', 'Choose Workspace →');
          b.type = 'button';
          b.addEventListener('click', caught(async () => {
            await onEnsureWorkspace(true);
            await refresh();
          }));
          return b;
        })()
      );
    } else {
      view.emptyBanner.hidden = true;
    }

    const COLS = [
      { title: '01 · ENTRY SURFACE', x: 20, w: 174, maxMain: 22, maxSub: 25 },
      { title: '02 · HANDLER / MODULE', x: 230, w: 176, maxMain: 22, maxSub: 25 },
      { title: '03 · CODE / ARTIFACT SINK', x: 442, w: 192, maxMain: 24, maxSub: 27 },
      { title: '04 · BLAST RADIUS', x: 670, w: 168, maxMain: 21, maxSub: 24 }
    ];
    for (const col of COLS) {
      view.svg.append(svgEl('text', {
        x: col.x, y: 22, fill: c.mute, 'font-size': '10', 'letter-spacing': '1.2', 'font-weight': '500'
      }, col.title));
    }

    const lanes = reachability.lanes || [];
    if (!lanes.length) {
      view.svg.append(svgEl('text', {
        x: 430, y: 220, 'text-anchor': 'middle', fill: c.mute, 'font-size': '12'
      }, 'Select a workspace folder to inspect source-to-sink reachability lanes.'));
      return;
    }

    const laneGap = Math.min(64, Math.floor(352 / Math.max(1, lanes.length)));
    const startY = Math.round(58 + Math.max(0, (356 - lanes.length * laneGap) / 2));

    const inspectLane = lane => {
      const btns = [];
      if (lane.finding && onDraftFix) {
        const fixBtn = el('button', 'primary-button compact-btn', 'Draft Fix →');
        fixBtn.type = 'button';
        fixBtn.addEventListener('click', () => onDraftFix(lane.finding));
        btns.push(fixBtn);
      }
      if (lane.finding && onDraftShield && lane.finding.status !== 'mitigated' && lane.finding.status !== 'false-positive') {
        const shieldBtn = el('button', 'secondary-button compact-btn', 'Draft Shield');
        shieldBtn.type = 'button';
        shieldBtn.addEventListener('click', () => onDraftShield(lane.finding));
        btns.push(shieldBtn);
      }
      if (lane.findingIds?.length) {
        for (const [label, st] of [['Mark Mitigated ✓', 'mitigated'], ['False Positive', 'false-positive']]) {
          const b = el('button', 'secondary-button compact-btn', label);
          b.type = 'button';
          b.addEventListener('click', caught(async () => {
            for (const fid of lane.findingIds) await api.updateFinding(fid, { status: st });
            await onFindingsMutated();
            await refresh();
            notify(`Marked ${lane.findingIds.length} finding(s) as ${st} — path severed.`);
          }));
          btns.push(b);
        }
      } else if (lane.path && onAuditAsset) {
        const auditBtn = el('button', 'secondary-button compact-btn', 'Audit Module →');
        auditBtn.type = 'button';
        auditBtn.addEventListener('click', () => onAuditAsset({ path: lane.path, kind: 'code', entropy: 4.8, engines: ['semgrep', 'gitleaks', 'trivy'], openFindingIds: [] }));
        btns.push(auditBtn);
      }

      const tone = lane.state === 'reachable' ? 'rose' : lane.state === 'unverified' ? 'sand' : lane.state === 'not-scanned' ? 'muted' : 'sky';
      const badge = lane.state === 'reachable'
        ? 'REACHABLE PATH'
        : lane.state === 'unverified'
          ? 'UNVERIFIED SINK'
          : lane.state === 'severed'
            ? 'PATH SEVERED'
            : lane.gateLabel;
      setInspector(view, { badge, tagTone: tone, text: lane.detail, actions: btns });
    };

    lanes.forEach((lane, idx) => {
      const cy = startY + idx * laneGap;
      const isSel = selectedLaneId === lane.id;
      const dim = selectedLaneId && !isSel;
      const strokeCol = lane.state === 'reachable'
        ? c.crit
        : lane.state === 'unverified'
          ? c.warn
          : colorForStatus(lane.state, c);
      const connCol = lane.state === 'severed' ? c.mute : strokeCol;
      const dashed = lane.state === 'severed' || lane.state === 'unverified' ? '4 4' : 'none';

      const rowGroup = svgEl('g', {
        class: 'stage-svg-node',
        opacity: dim ? '0.28' : '1'
      });

      // Connectors between the 4 stages
      const pairs = [
        [COLS[0].x + COLS[0].w, COLS[1].x],
        [COLS[1].x + COLS[1].w, COLS[2].x],
        [COLS[2].x + COLS[2].w, COLS[3].x]
      ];
      pairs.forEach(([x1, x2], pIdx) => {
        rowGroup.append(svgEl('line', {
          x1, y1: cy, x2, y2: cy,
          stroke: connCol,
          'stroke-width': lane.state === 'reachable' ? '2.4' : '1.6',
          'stroke-dasharray': dashed
        }));
        if (lane.state === 'severed' && pIdx === 1) {
          // Severance X pill on middle connector
          const mx = Math.round((x1 + x2) / 2);
          rowGroup.append(
            svgEl('circle', { cx: mx, cy, r: 8, fill: c.bg, stroke: c.signalFill, 'stroke-width': '1.4' }),
            svgEl('text', { x: mx, y: cy + 3.5, 'text-anchor': 'middle', fill: c.signalFill, 'font-size': '9.5', 'font-weight': '700' }, '✕')
          );
        }
      });

      const cells = [lane.entry, lane.handler, lane.sink, lane.impact];
      cells.forEach((cell, cIdx) => {
        const col = COLS[cIdx];
        const boxStroke = lane.state === 'severed' && cIdx < 3 ? c.line : strokeCol;
        const subCol = lane.state === 'severed' && cIdx === 3 ? c.signal : strokeCol;
        rowGroup.append(
          svgEl('rect', {
            x: col.x, y: cy - 21, width: col.w, height: 42, rx: 8,
            fill: c.bg,
            stroke: boxStroke,
            'stroke-width': isSel ? '2.1' : '1.3'
          }),
          svgEl('text', {
            x: col.x + 10, y: cy - 3, fill: c.ink, 'font-size': '10.6', 'font-weight': '600'
          }, fitText(cell.label, col.maxMain)),
          svgEl('text', {
            x: col.x + 10, y: cy + 12, fill: cIdx === 0 && lane.state === 'severed' ? c.mute : subCol, 'font-size': '9.1'
          }, fitText(cell.sub, col.maxSub))
        );
      });

      rowGroup.addEventListener('mouseenter', () => { if (!selectedLaneId) inspectLane(lane); });
      rowGroup.addEventListener('click', () => {
        selectedLaneId = selectedLaneId === lane.id ? null : lane.id;
        renderReachability();
        inspectLane(lane);
      });
      view.svg.append(rowGroup);
    });

    if (!selectedLaneId) {
      inspectLane(lanes[0]);
    }
  }

  function renderAll() {
    if (!graphData) return;
    renderConvergence();
    renderReachability();
  }

  async function refresh(manual = false) {
    if (loading) { refreshPending = true; return; }
    loading = true;
    for (const v of views.values()) {
      v.rescanBtn.disabled = true;
      v.rescanBtn.textContent = 'Scanning…';
    }
    try {
      await onEnsureWorkspace(false);
      graphData = await api.scanGraphs();
      renderAll();
      if (manual) notify('Updated 10-CLI Convergence & Attack Reachability maps.');
    } catch (err) {
      notify('Could not build security graphs: ' + (err.message || err));
    } finally {
      loading = false;
      for (const v of views.values()) {
        v.rescanBtn.disabled = false;
        v.rescanBtn.textContent = 'Rescan';
      }
      if (refreshPending) {
        refreshPending = false;
        if (activeGraph) await refresh();
      }
    }
  }

  return {
    isGraphId: id => views.has(id),
    async activate(id) {
      activeGraph = views.has(id) ? id : null;
      for (const [key, v] of views) {
        const on = key === activeGraph;
        v.host.classList.toggle('inactive', !on);
        v.tab.classList.toggle('active', on);
        v.select.setAttribute('aria-selected', String(on));
      }
      if (activeGraph) await refresh(false);
    },
    deactivateAll() {
      activeGraph = null;
      for (const v of views.values()) {
        v.host.classList.add('inactive');
        v.tab.classList.remove('active');
        v.select.setAttribute('aria-selected', 'false');
      }
    },
    refreshIfVisible() {
      if (activeGraph) refresh(false);
    },
    rerenderTheme() {
      if (graphData) renderAll();
    }
  };
}
