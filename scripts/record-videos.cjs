const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { createServer } = require('node:http');
const { spawn } = require('node:child_process');
const { pathToFileURL } = require('node:url');
const { _electron: electron, chromium } = require('@playwright/test');
const { createFindingsStore } = require('../electron/findings.cjs');

const WEB_DIR = process.env.MARLOWE_WEB_DIR || path.resolve(__dirname, '../../ZeroTheoryLabs/web/public');
const ASSETS_DIR = path.join(WEB_DIR, 'assets');
const MARLOWE_HTML = path.join(WEB_DIR, 'marlowe.html');
const APP_ROOT = path.resolve(__dirname, '..');

const sleep = ms => new Promise(r => setTimeout(r, ms));

async function typeHuman(page, text, delay = 22) {
  for (const ch of text) {
    await page.keyboard.type(ch);
    await sleep(delay);
  }
}

async function smoothScrollTo(page, targetY, durationMs = 1050) {
  await page.evaluate(({ y, ms }) => new Promise(resolve => {
    const startY = window.scrollY;
    const delta = y - startY;
    const t0 = performance.now();
    const ease = t => t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;
    function step(now) {
      const p = Math.min(1, (now - t0) / ms);
      window.scrollTo(0, startY + delta * ease(p));
      if (p < 1) requestAnimationFrame(step);
      else resolve();
    }
    requestAnimationFrame(step);
  }), { y: targetY, ms: durationMs });
}

async function startMp4Recorder(page, outputPath, { fps = 30, maxWidth = 2880, maxHeight = 1800 } = {}) {
  const cdp = await page.context().newCDPSession(page);
  let latestFrame = await page.screenshot({ type: 'jpeg', quality: 94 });

  cdp.on('Page.screencastFrame', async ({ data, sessionId }) => {
    latestFrame = Buffer.from(data, 'base64');
    await cdp.send('Page.screencastFrameAck', { sessionId }).catch(() => {});
  });
  await cdp.send('Page.startScreencast', {
    format: 'jpeg',
    quality: 94,
    maxWidth,
    maxHeight,
    everyNthFrame: 1
  });

  const ff = spawn('ffmpeg', [
    '-y',
    '-f', 'image2pipe',
    '-vcodec', 'mjpeg',
    '-framerate', String(fps),
    '-i', '-',
    '-vf', 'scale=trunc(iw/2)*2:trunc(ih/2)*2',
    '-c:v', 'libx264',
    '-pix_fmt', 'yuv420p',
    '-crf', '18',
    '-preset', 'fast',
    '-movflags', '+faststart',
    outputPath
  ], { stdio: ['pipe', 'ignore', 'pipe'] });

  let ffErr = '';
  ff.stderr.on('data', d => { ffErr += d.toString(); });

  const startedAt = Date.now();
  let writing = false;
  const interval = setInterval(() => {
    if (writing || !latestFrame || ff.stdin.destroyed) return;
    writing = true;
    const ok = ff.stdin.write(latestFrame);
    if (ok) writing = false;
    else ff.stdin.once('drain', () => { writing = false; });
  }, Math.round(1000 / fps));

  return {
    elapsedSeconds() {
      return Math.max(0, Math.round(((Date.now() - startedAt) / 1000) * 10) / 10);
    },
    async stop() {
      clearInterval(interval);
      await cdp.send('Page.stopScreencast').catch(() => {});
      await new Promise((resolve, reject) => {
        ff.once('exit', code => code === 0 ? resolve() : reject(new Error(`ffmpeg exited ${code}: ${ffErr.slice(-500)}`)));
        ff.stdin.end();
      });
    }
  };
}

async function setChapterBanner(page, stepLabel, titleText) {
  await page.evaluate(({ step, title }) => {
    let banner = document.getElementById('zt-demo-chapter');
    if (!banner) {
      banner = document.createElement('div');
      banner.id = 'zt-demo-chapter';
      Object.assign(banner.style, {
        position: 'fixed',
        bottom: '38px',
        left: '50%',
        transform: 'translateX(-50%)',
        zIndex: '40',
        display: 'inline-flex',
        alignItems: 'center',
        gap: '10px',
        padding: '7px 16px',
        borderRadius: '999px',
        background: 'rgba(19, 18, 16, 0.92)',
        border: '1px solid #3ddc97',
        boxShadow: '0 14px 36px rgba(0,0,0,0.65)',
        backdropFilter: 'blur(8px)',
        pointerEvents: 'none',
        transition: 'opacity 0.25s ease'
      });
      const badge = document.createElement('span');
      badge.id = 'zt-demo-chapter-step';
      Object.assign(badge.style, {
        padding: '2px 8px',
        borderRadius: '999px',
        background: '#1c3e2e',
        color: '#3ddc97',
        font: '600 10px/1.4 "Geist Mono", monospace',
        letterSpacing: '0.1em'
      });
      const text = document.createElement('span');
      text.id = 'zt-demo-chapter-title';
      Object.assign(text.style, {
        color: '#f2efe8',
        font: '500 12px/1.3 "Geist", sans-serif',
        whiteSpace: 'nowrap'
      });
      banner.append(badge, text);
      document.body.appendChild(banner);
    }
    if (!step) {
      banner.style.opacity = '0';
      return;
    }
    banner.style.opacity = '1';
    document.getElementById('zt-demo-chapter-step').textContent = step;
    document.getElementById('zt-demo-chapter-title').textContent = title;
  }, { step: stepLabel, title: titleText });
}

function call(name, args, index = 0) {
  return { index, id: `demo_call_${Date.now()}_${index}`, type: 'function', function: { name, arguments: JSON.stringify(args) } };
}

async function applicationSize(app, w, h) {
  await app.evaluate(({ BrowserWindow }, { w, h }) => {
    const win = BrowserWindow.getAllWindows()[0];
    win.setSize(w, h);
    win.center();
  }, { w, h });
}

async function recordAppDemo() {
  console.log('1/2 Recording full 6-chapter Marlowe v0.6 desktop app demo...');
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'marlowe-demo-v06-'));
  const demoRepoParent = path.join(dataDir, 'projects');
  const demoRepo = path.join(demoRepoParent, 'aegis-payments');
  await fs.mkdir(path.join(demoRepo, 'src'), { recursive: true });
  await fs.mkdir(path.join(demoRepo, 'visuals'), { recursive: true });
  await fs.mkdir(path.join(demoRepo, 'infra'), { recursive: true });
  await fs.mkdir(path.join(demoRepo, 'captures'), { recursive: true });
  await fs.mkdir(path.join(demoRepo, 'bin'), { recursive: true });
  await fs.mkdir(path.join(demoRepo, 'shirudo-shields'), { recursive: true });

  const fakePat = 'ghp_' + 'LiveDemoSecretTokenForMarloweShowcase99';
  // File 1: src/ledger.js (will be remediated via Approve once -> auto-mitigated!)
  await fs.writeFile(path.join(demoRepo, 'src/ledger.js'), [
    'export async function fetchAccount(db, accountId) {',
    '  return db.query(`SELECT id, balance FROM accounts WHERE id = ${accountId}`);',
    '}',
    ''
  ].join('\n'));

  // File 2: src/webhook.js (reachable HTTP taint + hardcoded secret -> stays open so DNA/Convergence/Reachability glow!)
  await fs.writeFile(path.join(demoRepo, 'src/webhook.js'), [
    `const WEBHOOK_TOKEN = "${fakePat}";`,
    '',
    'export async function verifyCharge(req, db) {',
    '  const chargeId = req.body.chargeId;',
    '  return db.query(`SELECT * FROM charges WHERE id = ${chargeId}`);',
    '}',
    ''
  ].join('\n'));

  await fs.writeFile(path.join(demoRepo, 'src/session.js'), 'export function verifyHmac(sig, mac) {\n  return typeof sig === "string" && mac.verify(sig);\n}\n');
  await fs.writeFile(path.join(demoRepo, 'visuals/console.html'), '<!doctype html><script>const ROWS=["OK"]; document.getElementById("t").innerHTML = ROWS.join("");</script>\n');
  await fs.writeFile(path.join(demoRepo, 'infra/Dockerfile'), 'FROM node:22-alpine\nUSER node\nWORKDIR /srv\nCOPY package.json ./\nCMD ["node", "src/session.js"]\n');
  await fs.writeFile(path.join(demoRepo, 'package.json'), JSON.stringify({
    name: 'aegis-payments',
    version: '1.4.0',
    dependencies: { pg: '8.13.1', express: '4.21.2' }
  }, null, 2));

  const highEnt = Buffer.alloc(2048);
  for (let i = 0; i < highEnt.length; i++) highEnt[i] = (i * 97 + 31) & 0xff;
  await fs.writeFile(path.join(demoRepo, 'captures/egress.pcap'), Buffer.concat([Buffer.from([0xd4, 0xc3, 0xb2, 0xa1]), highEnt.subarray(0, 1200)]));
  await fs.writeFile(path.join(demoRepo, 'bin/enclave-helper'), highEnt);

  const realDemoRepo = await fs.realpath(demoRepo);
  const realParent = path.dirname(realDemoRepo);

  // Pre-seed Scope (2 authorized hosts so 9-CLI Convergence connects Nmap/Nuclei/TShark!)
  await fs.writeFile(path.join(dataDir, 'scope.json'), JSON.stringify({
    targets: ['api.aegis.example.com', '*.staging.aegis.example.com'],
    allowOsv: true,
    redactContext: true
  }, null, 2));

  // Pre-seed 1 suppressed false-positive finding on visuals/console.html so Attack Reachability displays a severed FP lane too!
  const store = createFindingsStore(path.join(dataDir, 'findings'));
  const fpRec = await store.record(realDemoRepo, {
    title: 'Static UI DOM Sink in console.html',
    severity: 'medium',
    category: 'appsec',
    cwe: 'CWE-79',
    location: 'visuals/console.html:1',
    evidence: 'document.getElementById("t").innerHTML = ROWS.join("")',
    remediation: 'Static constant array only; no external input.'
  });
  await store.update(realDemoRepo, fpRec.finding.id, { status: 'false-positive' });

  const server = createServer((req, res) => {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      const payload = JSON.parse(body);
      const latestUser = payload.messages.findLastIndex(m => m.role === 'user');
      const latestPrompt = String(payload.messages[latestUser]?.content || '');
      const toolResults = payload.messages.slice(latestUser + 1).filter(m => m.role === 'tool');
      let toolCalls = null;
      let finalText = '';

      if (/shirudo/i.test(latestPrompt)) {
        if (toolResults.length === 0) {
          toolCalls = [call('write_file', {
            path: 'shirudo-shields/Beefile',
            content: [
              '[package]',
              'name = "webhook-sqli-shield"',
              'description = "Temporary eBPF shield guarding verifyCharge"',
              '',
              '[[upatches]]',
              'source = "verify_charge_guard.bpf.c"',
              'type = "bpf"',
              '',
              '[upatches.tree]',
              'id = "webhook-sqli-shield"',
              '',
              '[upatches.tree.selector.labels]',
              'service = ["aegis-payments"]',
              ''
            ].join('\n')
          }, 0)];
        } else if (toolResults.length === 1) {
          toolCalls = [call('write_file', {
            path: 'shirudo-shields/verify_charge_guard.bpf.c',
            content: [
              'char LICENSE[] SEC("license") = "Dual BSD/GPL";',
              '',
              'SEC("lsm/socket_connect")',
              'int guard_verify_charge(void *ctx) {',
              '  unsigned int pid = bpf_get_current_pid_tgid() >> 32;',
              '  return pid ? 0 : 0;',
              '}',
              ''
            ].join('\n')
          }, 0)];
        } else if (toolResults.length === 2) {
          toolCalls = [call('audit_shirudo_upatch', { path: 'shirudo-shields' }, 0)];
        } else {
          finalText = [
            '### Shirudo Draft Shield — `webhook-sqli-shield`',
            '',
            '- `shirudo-shields/Beefile` + `verify_charge_guard.bpf.c` drafted behind Marlowe\'s one-shot approval gate.',
            '- **Audit Verdict:** `HOLDS UP` (`SEC("license")` Dual BSD/GPL · explicit label selector · `audit_shirudo_upatch` verified).'
          ].join('\n');
        }
      } else if (toolResults.length === 0) {
        toolCalls = [
          call('scan_secrets', { path: '.' }, 0),
          call('read_file', { path: 'src/ledger.js' }, 1)
        ];
      } else if (toolResults.length === 2) {
        toolCalls = [call('record_findings', {
          findings: [
            {
              title: 'Hardcoded Webhook Token in verifyCharge',
              severity: 'critical',
              category: 'secrets',
              cwe: 'CWE-798',
              cvss: 9.1,
              location: 'src/webhook.js:1',
              evidence: 'Masked token assignment in src/webhook.js:1',
              remediation: 'Move WEBHOOK_TOKEN to OS keychain / secret manager and rotate token.'
            },
            {
              title: 'Reachable SQL Injection via req.body.chargeId',
              severity: 'high',
              category: 'appsec',
              cwe: 'CWE-89',
              cvss: 8.8,
              location: 'src/webhook.js:5',
              evidence: 'db.query(`SELECT * FROM charges WHERE id = ${chargeId}`)',
              remediation: 'Bind chargeId using parameterized placeholder ($1).'
            },
            {
              title: 'Unparameterized SQL Query in fetchAccount',
              severity: 'high',
              category: 'appsec',
              cwe: 'CWE-89',
              cvss: 8.4,
              location: 'src/ledger.js:2',
              evidence: 'db.query(`SELECT id, balance FROM accounts WHERE id = ${accountId}`)',
              remediation: 'Parameterize accountId with $1.'
            }
          ]
        }, 0)];
      } else if (toolResults.length === 3) {
        // Propose replacing src/ledger.js -> triggers host-enforced Line-Diff Approval Gate!
        toolCalls = [call('write_file', {
          path: 'src/ledger.js',
          content: [
            'export async function fetchAccount(db, accountId) {',
            '  return db.query("SELECT id, balance FROM accounts WHERE id = $1", [accountId]);',
            '}',
            ''
          ].join('\n')
        }, 0)];
      } else {
        finalText = [
          '### Triage Summary — `aegis-payments`',
          '',
          '| Asset | Verdict | Detail |',
          '| :--- | :--- | :--- |',
          '| `src/ledger.js` | **Mitigated** | Parameterized `$1` fix approved & backup saved |',
          '| `src/webhook.js` | **2 Open** | `CWE-798` masked secret + `CWE-89` reachable `req.body` SQLi |',
          '| `visuals/console.html` | **False Positive** | Static constant array — severed (`0` blast radius) |',
          '',
          'Open **DNA**, **10-CLI Convergence**, or **Attack Reachability** (or click **Draft Shield**) to inspect multi-engine posture.'
        ].join('\n');
      }

      res.writeHead(200, { 'Content-Type': 'text/event-stream' });
      if (toolCalls) {
        res.end('data: ' + JSON.stringify({ choices: [{ delta: { tool_calls: toolCalls } }] }) + '\n\ndata: {"choices":[{"delta":{},"finish_reason":"tool_calls"}]}\n\ndata: [DONE]\n\n');
        return;
      }
      const chunks = finalText.match(/[\s\S]{1,26}/g) || [finalText];
      let idx = 0;
      const timer = setInterval(() => {
        if (idx < chunks.length) {
          res.write('data: ' + JSON.stringify({ choices: [{ delta: { content: chunks[idx++] } }] }) + '\n\n');
        } else {
          clearInterval(timer);
          res.end('data: {"choices":[{"delta":{},"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n');
        }
      }, 28);
    });
  });

  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const endpoint = `http://127.0.0.1:${server.address().port}/v1`;

  await fs.writeFile(path.join(dataDir, 'settings.json'), JSON.stringify({
    baseUrl: endpoint,
    model: 'qwen3.8:27b'
  }, null, 2));

  const env = { ...process.env, BENJAMIN_TEST_DATA: dataDir };
  delete env.ELECTRON_RUN_AS_NODE;

  const app = await electron.launch({ args: [APP_ROOT], env });
  const page = await app.firstWindow();
  await applicationSize(app, 1440, 900);
  await page.evaluate(() => document.fonts.ready);
  await page.waitForSelector('#shell-status');
  await sleep(600);

  await page.locator('.terminal-host:not(.inactive) .xterm-helper-textarea').focus();
  await page.keyboard.type(`cd '${realParent}' && clear`);
  await page.keyboard.press('Enter');
  await sleep(500);

  // Poster frame (clean shell + editorial welcome)
  const posterPath = path.join(ASSETS_DIR, 'marlowe-app-poster.png');
  await page.screenshot({ path: posterPath, scale: 'css' });

  const mp4Path = path.join(ASSETS_DIR, 'marlowe-app-demo.mp4');
  const rec = await startMp4Recorder(page, mp4Path, { fps: 30, maxWidth: 2880, maxHeight: 1800 });
  const chapterTimes = [0];

  try {
    // CHAPTER 1: Real zsh + Taint-Verified AppSec Audit
    await setChapterBanner(page, '01 / 06', 'Real zsh shell + taint-verified AppSec Audit');
    await sleep(500);
    await typeHuman(page, 'cd aegis-payments && ls', 30);
    await page.keyboard.press('Enter');
    await sleep(950);

    await page.getByRole('button', { name: 'Agent', exact: true }).click();
    await sleep(300);
    await page.locator('#playbook-select').selectOption('appsec');
    await sleep(250);
    await page.locator('#prompt').click();
    await typeHuman(page, 'Audit aegis-payments for secrets & reachable SQLi, and remediate ledger.js.', 16);
    await sleep(250);
    await page.locator('#send-button').click();

    // CHAPTER 2: Host-Enforced Line-Diff Approval Gate + Formatted Markdown Report
    const waitingCard = page.locator('.action-card[data-status="awaiting-approval"]').last();
    await waitingCard.waitFor({ state: 'visible', timeout: 8000 });
    chapterTimes.push(Math.floor(rec.elapsedSeconds()));
    await setChapterBanner(page, '02 / 06', 'Host-enforced line-diff gate · One-shot Approve once');
    await sleep(2300);
    await waitingCard.getByRole('button', { name: 'Approve once', exact: true }).click();
    await page.locator('#stop-button').waitFor({ state: 'hidden', timeout: 8000 });
    await sleep(2400);

    // CHAPTER 3: Codebase DNA (Shannon Byte Entropy × 10 Security CLIs)
    chapterTimes.push(Math.floor(rec.elapsedSeconds()));
    await setChapterBanner(page, '03 / 06', 'Codebase DNA · Shannon byte entropy (0–8 b/B) × 10 CLIs');
    await page.locator('#dna-button').click();
    await page.locator('#dna-svg .dna-dot-node').first().waitFor({ state: 'visible', timeout: 5000 });
    await sleep(1800);
    // Click high-entropy binary dot on DNA map to showcase live inspector transition!
    await page.locator('[data-dna-filter="artifacts"]').click();
    await sleep(1200);
    await page.locator('[data-dna-filter="all"]').click();
    await sleep(900);

    // CHAPTER 4: 10-CLI Security Convergence (Main Stage Tab)
    chapterTimes.push(Math.floor(rec.elapsedSeconds()));
    await setChapterBanner(page, '04 / 06', '10-CLI Convergence · Semgrep, Trivy, Gitleaks, Nmap, Radare2 & Shirudo');
    await page.locator('#convergence-tab').click();
    await page.locator('#convergence-stage .stage-svg-node').first().waitFor({ state: 'visible', timeout: 5000 });
    await sleep(1700);
    await page.locator('#convergence-stage .stage-svg-node').first().click();
    await sleep(1400);
    await page.locator('#convergence-stage .stage-svg-node').first().click();
    await sleep(800);

    // CHAPTER 5: Attack Surface Reachability (⌘J) + 1-Click Draft Shield → Shirudo Upatch Gate
    chapterTimes.push(Math.floor(rec.elapsedSeconds()));
    await setChapterBanner(page, '05 / 06', 'Attack Reachability · Cross-file taint & 1-click Draft Shield (⌘J)');
    await page.locator('#reachability-tab').click();
    await page.locator('#reachability-stage .stage-svg-node').first().waitFor({ state: 'visible', timeout: 5000 });
    await sleep(1600);
    await page.locator('#reachability-stage .stage-svg-node').first().click();
    await sleep(1000);
    await page.locator('#toggle-drawer').click(); // Expand graph to 100% full window width!
    await sleep(1700);
    await page.locator('#toggle-drawer').click(); // Restore split pane
    await sleep(500);
    const draftShieldBtn = page.getByRole('button', { name: 'Draft Shield', exact: true });
    await draftShieldBtn.waitFor({ state: 'visible', timeout: 4000 });
    await draftShieldBtn.click();
    await sleep(700);
    await page.locator('#send-button').click();
    const shieldGate1 = page.locator('.action-card[data-status="awaiting-approval"]').last();
    await shieldGate1.waitFor({ state: 'visible', timeout: 8000 });
    await sleep(1500);
    await shieldGate1.getByRole('button', { name: 'Approve once', exact: true }).click();
    const shieldGate2 = page.locator('.action-card[data-status="awaiting-approval"]').last();
    await shieldGate2.waitFor({ state: 'visible', timeout: 8000 });
    await sleep(1300);
    await shieldGate2.getByRole('button', { name: 'Approve once', exact: true }).click();
    await page.locator('#stop-button').waitFor({ state: 'hidden', timeout: 8000 });
    await sleep(1500);

    // CHAPTER 6: Dynamic Local + Frontier Model Radar & Inline Secret Masking
    chapterTimes.push(Math.floor(rec.elapsedSeconds()));
    await setChapterBanner(page, '06 / 06', 'Live Ollama + Claude/Gemini/OpenAI Radar & Local Secret Masking');
    await page.getByRole('button', { name: 'Settings', exact: true }).click();
    await page.locator('#local-radar-status').waitFor({ state: 'visible', timeout: 4000 });
    await sleep(700);
    await page.locator('#provider-presets .preset-pill', { hasText: 'Ollama' }).click();
    await sleep(1900);
    await page.locator('#provider-presets .preset-pill', { hasText: 'Claude' }).click();
    await sleep(1300);
    await page.getByRole('button', { name: 'Close settings', exact: true }).click();
    await sleep(450);

    // Switch back to zsh · 1 and trigger failed command secret masking!
    await page.getByRole('tab', { name: /zsh/ }).first().click();
    await page.locator('.terminal-host:not(.inactive) .xterm-helper-textarea').focus();
    const demoSk = 'sk-proj-' + 'DemoRedactionKey9876543210abcdef';
    await typeHuman(page, `printf 'API_KEY=${demoSk}\\n'; (exit 22)`, 18);
    await page.keyboard.press('Enter');
    await page.locator('#failure-hud').waitFor({ state: 'visible', timeout: 5000 });
    await sleep(1200);
    await page.locator('#failure-diagnose').click();
    await sleep(1900);
    await setChapterBanner(page, '', '');
  } finally {
    await rec.stop();
    await app.close();
    await new Promise(r => server.close(r));
    await fs.rm(dataDir, { recursive: true, force: true });
  }
  console.log('   Saved:', mp4Path, 'Chapters:', chapterTimes);
  return chapterTimes;
}

async function syncWebsiteChapterTimes(chapterTimes) {
  if (!Array.isArray(chapterTimes) || chapterTimes.length !== 6) return;
  let html = await fs.readFile(MARLOWE_HTML, 'utf8');
  let idx = 0;
  html = html.replace(/(class="mw-chap-btn(?:\s+is-active)?"\s+data-seek=")(\d+(?:\.\d+)?)(")/g, (full, pre, _old, post) => {
    const val = chapterTimes[idx++] ?? 0;
    return `${pre}${val}${post}`;
  });
  await fs.writeFile(MARLOWE_HTML, html, 'utf8');
  console.log('   Synced exact chapter timestamps into marlowe.html:', chapterTimes);
}

async function recordWebsiteReel() {
  console.log('2/2 Recording upgraded Zero Theory Labs → Marlowe website launch reel...');
  const browser = await chromium.launch({ channel: 'chrome', headless: true });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1 });
  const page = await context.newPage();

  const indexUrl = pathToFileURL(path.join(WEB_DIR, 'index.html')).href;
  await page.goto(indexUrl, { waitUntil: 'load' });
  await page.evaluate(() => document.fonts.ready);
  await sleep(500);

  const mp4Path = path.join(ASSETS_DIR, 'marlowe-website-reel.mp4');
  const rec = await startMp4Recorder(page, mp4Path, { fps: 30, maxWidth: 1440, maxHeight: 900 });

  try {
    await sleep(1100);
    const marloweSectionY = await page.evaluate(() => {
      const el = document.querySelector('#marlowe') || document.querySelector('a[href="marlowe.html"]');
      return el ? Math.max(0, el.getBoundingClientRect().top + window.scrollY - 80) : 900;
    });
    await smoothScrollTo(page, marloweSectionY, 1200);
    await sleep(1300);

    await Promise.all([
      page.waitForNavigation({ waitUntil: 'load' }),
      page.locator('a[href="marlowe.html"]').first().click()
    ]);
    await page.evaluate(() => document.fonts.ready);
    await sleep(2200);

    // #approval interactive card
    const approvalY = await page.evaluate(() => document.getElementById('approval').getBoundingClientRect().top + window.scrollY - 60);
    await smoothScrollTo(page, approvalY, 1000);
    await sleep(1600);
    await page.locator('#demo-approve').click();
    await sleep(1100);

    // #dna 3-mode interactive security maps!
    const dnaY = await page.evaluate(() => document.getElementById('dna').getBoundingClientRect().top + window.scrollY - 50);
    await smoothScrollTo(page, dnaY, 1050);
    await sleep(1400);
    await page.locator('[data-viz-mode="convergence"]').click();
    await sleep(1400);
    await page.locator('[data-viz-mode="reachability"]').click();
    await sleep(1400);

    // #models local + frontier command center preview
    const modelsY = await page.evaluate(() => document.getElementById('models').getBoundingClientRect().top + window.scrollY - 50);
    await smoothScrollTo(page, modelsY, 1050);
    await sleep(1200);
    await page.locator('[data-prov="claude"]').click();
    await sleep(1100);
    await page.locator('[data-prov="gemini"]').click();
    await sleep(1000);

    // #platforms embedded live desktop build + interactive chapter seek bar
    const platformsY = await page.evaluate(() => document.getElementById('platforms').getBoundingClientRect().top + window.scrollY - 35);
    await smoothScrollTo(page, platformsY, 1100);
    await sleep(1600);
    await page.locator('#mw-video-chapters .mw-chap-btn').nth(3).click(); // Jump video to 04 · 9-CLI Convergence!
    await sleep(1900);

    // #access CTA
    const accessY = await page.evaluate(() => document.getElementById('access').getBoundingClientRect().top + window.scrollY - 80);
    await smoothScrollTo(page, accessY, 950);
    await sleep(1400);
  } finally {
    await rec.stop();
    await context.close();
    await browser.close();
  }
  console.log('   Saved:', mp4Path);
}

(async () => {
  await fs.mkdir(ASSETS_DIR, { recursive: true });
  const chapterTimes = await recordAppDemo();
  await syncWebsiteChapterTimes(chapterTimes);
  await recordWebsiteReel();
  console.log('All videos recorded and synced successfully.');
})().catch(err => {
  console.error(err);
  process.exit(1);
});
