const { test, expect, _electron: electron } = require('@playwright/test');
const { createServer } = require('node:http');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');

let application, page, server, dataDir, root, endpoint, requests = [];

function call(name, args, index) {
  return { index, id: `cyber_call_${index}`, type: 'function', function: { name, arguments: JSON.stringify(args) } };
}

test.beforeAll(async () => {
  dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'benjamin-cyber-e2e-'));
  root = path.join(dataDir, 'target-app');
  await fs.mkdir(path.join(root, 'src'), { recursive: true });
  await fs.mkdir(path.join(root, 'infra'), { recursive: true });
  await fs.mkdir(path.join(root, 'artifacts'), { recursive: true });
  const fakePat = 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8';
  await fs.writeFile(path.join(root, 'src/db.js'), [
    `const SYNC_TOKEN = "${fakePat}";`,
    'export function findUser(db, userId) {',
    '  return db.query(`SELECT * FROM users WHERE id = ${userId}`);',
    '}'
  ].join('\n'));
  await fs.writeFile(path.join(root, 'src/session.js'), 'export function verifySession(cookie, hmac) {\n  if (!cookie || typeof cookie !== "string") return null;\n  return hmac.verify(cookie);\n}\n');
  await fs.writeFile(path.join(root, 'src/routes.js'), 'export async function handleHealth(req, res) {\n  res.writeHead(200, { "content-type": "application/json" });\n  res.end(JSON.stringify({ ok: true }));\n}\n');
  await fs.writeFile(path.join(root, 'package.json'), JSON.stringify({ name: 'target-app', version: '0.4.0', private: true, dependencies: { pg: '^8.13.0' } }, null, 2));
  await fs.writeFile(path.join(root, 'infra/Dockerfile'), 'FROM node:22-alpine\nUSER node\nWORKDIR /srv/app\nCOPY package.json ./\nCMD ["node", "src/routes.js"]\n');
  const packed = Buffer.alloc(2048);
  for (let i = 0; i < packed.length; i++) packed[i] = (i * 97 + 31) & 0xff;
  await fs.writeFile(path.join(root, 'artifacts/capture.pcap'), Buffer.concat([Buffer.from([0xd4, 0xc3, 0xb2, 0xa1]), packed.subarray(0, 1200)]));
  await fs.writeFile(path.join(root, 'artifacts/loader.bin'), packed);

  server = createServer((req, res) => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      const payload = JSON.parse(body);
      requests.push(payload);
      const latestUser = payload.messages.findLastIndex(m => m.role === 'user');
      const results = payload.messages.slice(latestUser + 1).filter(m => m.role === 'tool');
      let calls = null;
      if (results.length === 0) {
        calls = [
          call('scan_secrets', { path: '.' }, 0),
          call('audit_code_patterns', { path: '.' }, 1)
        ];
      } else if (results.length === 2) {
        calls = [
          call('record_finding', {
            title: 'Hardcoded GitHub Personal Access Token',
            severity: 'critical',
            category: 'secrets',
            cwe: 'CWE-798',
            cvss: 9.1,
            location: 'src/db.js:1',
            evidence: 'Masked token assignment in src/db.js:1',
            remediation: 'Move SYNC_TOKEN to OS secret storage or environment injection and rotate the token.'
          }, 0),
          call('record_finding', {
            title: 'SQL Injection in findUser query',
            severity: 'high',
            category: 'appsec',
            cwe: 'CWE-89',
            cvss: 8.6,
            location: 'src/db.js:3',
            evidence: 'db.query(`SELECT * FROM users WHERE id = ${userId}`)',
            remediation: 'Use parameterized placeholders ($1 / ?) instead of string interpolation.'
          }, 1)
        ];
      }
      res.writeHead(200, { 'Content-Type': 'text/event-stream' });
      if (calls) {
        res.end('data: ' + JSON.stringify({ choices: [{ delta: { tool_calls: calls } }] }) + '\n\ndata: {"choices":[{"delta":{},"finish_reason":"tool_calls"}]}\n\ndata: [DONE]\n\n');
      } else {
        res.end('data: ' + JSON.stringify({ choices: [{ delta: { content: 'Completed AppSec audit: recorded 1 critical secret exposure and 1 high-severity SQL injection finding.' }, finish_reason: 'stop' }] }) + '\n\ndata: [DONE]\n\n');
      }
    });
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  endpoint = `http://127.0.0.1:${server.address().port}/v1`;
  application = await electron.launch({
    ...(process.env.BENJAMIN_EXECUTABLE ? { executablePath: process.env.BENJAMIN_EXECUTABLE, args: [] } : { args: ['.'] }),
    env: { ...process.env, BENJAMIN_TEST_DATA: dataDir }
  });
  page = await application.firstWindow();
});

test.afterAll(async () => {
  await application?.close();
  await new Promise(resolve => server?.close(resolve));
  if (dataDir) await fs.rm(dataDir, { recursive: true, force: true });
});

test('cybersecurity scope gate, toolchain doctor, appsec playbook, secret masking, findings ledger and SARIF export', async () => {
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  await expect(page.locator('#shell-status')).toContainText('interactive');

  // Configure local test model (and verify dynamic provider presets + live local radar)
  await page.getByRole('button', { name: 'Settings', exact: true }).click();
  await expect(page.locator('#provider-presets .preset-pill').first()).toBeVisible();
  await expect(page.locator('#local-radar-status')).not.toHaveText('Scanning local ports…');
  await page.locator('#provider-presets .preset-pill', { hasText: 'Ollama' }).click();
  await page.screenshot({ path: 'test-results/marlowe-model-connect.png', scale: 'css' });
  await page.locator('#base-url').fill(endpoint);
  await page.locator('#model-id').fill('cyber-sec-model');
  await page.getByRole('button', { name: 'Save connection' }).click();

  // Switch right pane inline to Scope & Toolchain Doctor tab
  await page.locator('#scope-button').click();
  await expect(page.locator('#scope-dialog')).toBeVisible();
  await expect(page.locator('#toolchain-summary')).toContainText('local security CLIs ready');
  await page.locator('#scope-target-input').fill('api.example.com');
  await page.locator('#add-scope-target').click();
  await page.locator('#scope-target-input').fill('*.staging.example.com');
  await page.locator('#add-scope-target').click();
  await expect(page.locator('.scope-chip')).toHaveCount(2);
  await page.screenshot({ path: 'test-results/benjamin-scope-doctor.png', scale: 'css' });
  await page.locator('#save-scope-button').click();
  await expect(page.locator('#scope-count-badge')).toHaveText('2');
  await page.locator('#assistant-tab').click();

  // cd into project in zsh: clicking Agent adopts shell cwd without opening Finder or spawning extra tabs
  await application.evaluate(({ dialog }) => {
    dialog.showOpenDialog = async () => { throw new Error('Finder must not open when terminal cwd is already a project folder'); };
  });
  const realRoot = await fs.realpath(root);
  await page.locator('.terminal-host:not(.inactive) .xterm-helper-textarea').focus();
  await page.keyboard.type(`cd '${realRoot.replaceAll("'", "'\"'\"'")}'`);
  await page.keyboard.press('Enter');
  await expect(page.locator('#shell-path')).toHaveText(realRoot);

  await page.getByRole('button', { name: 'Agent', exact: true }).click();
  await expect(page.locator('#terminal-count')).toHaveText('2');
  await expect(page.locator('#folder-name')).toHaveText('target-app');
  await expect(page.locator('#playbook-select')).toBeVisible();
  expect(JSON.parse(await fs.readFile(path.join(dataDir, 'workspace.json'), 'utf8')).folder).toBe(realRoot);
  await page.locator('#playbook-select').selectOption('appsec');

  // Run AppSec audit
  await page.locator('#prompt').fill('Audit this project for secrets and SQL injection');
  await page.getByRole('button', { name: 'Send message', exact: true }).click();
  await expect(page.locator('#stop-button')).toBeHidden();
  await expect(page.locator('.message.assistant').last()).toContainText('Completed AppSec audit');

  // Verify raw GitHub token was never sent to the model or rendered in the UI
  expect(JSON.stringify(requests)).not.toContain('A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8');
  expect(JSON.stringify(requests[0].system || requests[0].messages)).toContain('Application Security & Supply-Chain Auditor');
  expect(JSON.stringify(requests[0].messages)).toContain('api.example.com');

  // Verify live Findings badge updated to 2 and inspect inline Findings tab
  await expect(page.locator('#findings-badge')).toBeVisible();
  await expect(page.locator('#findings-badge')).toHaveText('2');
  await page.locator('#findings-button').click();
  await expect(page.locator('#findings-dialog')).toBeVisible();
  await expect(page.locator('.finding-card')).toHaveCount(2);
  await page.locator('.finding-details summary').first().click();
  await page.screenshot({ path: 'test-results/benjamin-findings.png', scale: 'css' });

  // Export SARIF report and verify valid SARIF v2.1.0 on disk
  const sarifPath = path.join(dataDir, 'exported-audit.sarif.json');
  await application.evaluate(({ dialog }, outPath) => {
    dialog.showSaveDialog = async () => ({ canceled: false, filePath: outPath });
  }, sarifPath);
  await page.locator('#export-sarif').click();
  await expect.poll(async () => {
    try { return JSON.parse(await fs.readFile(sarifPath, 'utf8')).version; } catch { return ''; }
  }).toBe('2.1.0');
  const sarif = JSON.parse(await fs.readFile(sarifPath, 'utf8'));
  expect(sarif.runs[0].results.length).toBe(2);

  // Inspect Codebase DNA dot-matrix map (Shannon byte entropy × 10-CLI security posture)
  await page.locator('#dna-button').click();
  await expect(page.locator('#dna-dialog')).toBeVisible();
  await expect(page.locator('#dna-svg .dna-dot-node')).toHaveCount(7);
  await expect(page.locator('#dna-inspector')).toContainText('src/db.js');
  await expect(page.locator('#dna-inspector')).toContainText('CRITICAL');
  await page.screenshot({ path: 'test-results/marlowe-dna.png', scale: 'css' });

  // Inspect 10-CLI Convergence & Attack Reachability tabs alongside Marlowe in the main stage
  await page.locator('#convergence-tab').click();
  await expect(page.locator('#convergence-stage')).toBeVisible();
  await expect(page.locator('#convergence-stage button', { hasText: 'Rescan' })).toBeEnabled();
  await expect(page.locator('#convergence-stage .stage-svg-node').first()).toBeVisible();
  await expect(page.locator('#convergence-stage')).toContainText('10-CLI Security Convergence');
  await page.screenshot({ path: 'test-results/marlowe-convergence.png', scale: 'css' });

  await page.locator('#reachability-tab').click();
  await expect(page.locator('#reachability-stage')).toBeVisible();
  await expect(page.locator('#reachability-stage button', { hasText: 'Rescan' })).toBeEnabled();
  await expect(page.locator('#reachability-stage .stage-svg-node').first()).toBeVisible();
  await expect(page.locator('#reachability-stage')).toContainText('Attack Surface Reachability');
  await page.screenshot({ path: 'test-results/marlowe-reachability.png', scale: 'css' });

  await page.locator('#findings-button').click();

  // Test Draft Fix handoff switches cleanly back to Assistant tab
  await page.locator('.finding-card').filter({ hasText: 'SQL Injection' }).getByRole('button', { name: 'Draft Fix' }).click();
  await expect(page.locator('#findings-dialog')).toBeHidden();
  await expect(page.locator('#assistant-view')).toBeVisible();
  await expect(page.locator('#prompt')).toHaveValue(/Remediate finding \[HIGH\] "SQL Injection in findUser query" \(CWE-89\) at src\/db\.js:3/);

  // Test unified ⌘J drawer button and inline OSC-777 failed-command secret masking HUD
  await page.getByRole('tab', { name: /zsh/ }).first().click();
  await page.locator('#toggle-drawer').click();
  await expect(page.locator('#chat-pane')).toBeHidden();

  const fakeSk = 'sk-proj-' + 'SecretKeyForRedactionTest1234567890';
  await page.locator('.terminal-host:not(.inactive) .xterm-helper-textarea').focus();
  await page.keyboard.type(`printf 'OPENAI_KEY=${fakeSk}\\n'; (exit 4)`);
  await page.keyboard.press('Enter');
  await expect(page.locator('#failure-hud')).toBeVisible();
  await expect(page.locator('#failure-hud-title')).toContainText('EXIT 4');
  await expect(page.locator('#failure-hud-secrets')).toHaveText('2 secrets in output');
  await expect(page.locator('#failure-diagnose')).toHaveText('Mask Secret & Help Fix');
  await page.screenshot({ path: 'test-results/benjamin-shell-fullwidth.png', scale: 'css' });

  // Clicking Mask Secret & Help Fix auto-opens the Benjamin drawer and masks the secret in review
  await page.locator('#failure-diagnose').click();
  await expect(page.locator('#chat-pane')).toBeVisible();
  await expect(page.locator('#context-dialog')).toBeVisible();
  await expect(page.locator('#context-editor')).toHaveValue(/\[REDACTED\]/);
  await expect(page.locator('#context-editor')).not.toHaveValue(/SecretKeyForRedactionTest1234567890/);
  await page.getByRole('button', { name: 'Close preview', exact: true }).click();

  expect(errors).toEqual([]);
});
