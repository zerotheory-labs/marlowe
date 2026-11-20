const { test, expect, _electron: electron } = require('@playwright/test');
const { createServer } = require('node:http');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { DEFAULT_PATH } = require('../electron/toolchain.cjs');
let application, page, server, dataDir, root, endpoint;
function call(name, args, index) { return { index, id: `call_${index}`, type: 'function', function: { name, arguments: JSON.stringify(args) } }; }
test.beforeAll(async () => {
  dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'benjamin-agent-ui-'));
  root = path.join(dataDir, 'project'); await fs.mkdir(root);
  await fs.writeFile(path.join(root, 'note.txt'), 'hello');
  server = createServer((req, res) => {
    let body = ''; req.on('data', chunk => body += chunk); req.on('end', () => {
      const payload = JSON.parse(body);
      const prompt = payload.messages.filter(m => m.role === 'user').at(-1).content;
      const latestUser = payload.messages.findLastIndex(m => m.role === 'user');
      const results = payload.messages.slice(latestUser + 1).filter(m => m.role === 'tool');
      if (prompt === 'Replace the note and run the command') {
        if (!payload.messages.slice(0, latestUser).some(m => m.role === 'tool' && m.content.includes('denied'))) throw new Error('Prior real tool results were lost');
      }
      let calls;
      const phantom = prompt === 'Create and edit, then propose deleting the note' && results.length === 0 && !payload.messages.some(m => m.role === 'system' && m.content.startsWith('No approval is pending.'));
      if (phantom) {
        res.writeHead(200, { 'Content-Type': 'text/event-stream' });
        res.end('data: ' + JSON.stringify({ choices: [{ delta: { content: 'I requested approval. Please approve the deletion. Agent activity: awaiting user approval.' }, finish_reason: 'stop' }] }) + '\n\ndata: [DONE]\n\n');
        return;
      }
      if (prompt === 'Create and edit, then propose deleting the note' && results.length === 0) calls = [
        call('list_files', { path: '.' }, 0), call('read_file', { path: 'note.txt' }, 1),
        call('find_files', { pattern: '*.txt', path: '.' }, 2), call('search_text', { query: 'HELLO', path: '.' }, 3),
        call('edit_file', { path: 'note.txt', old_text: 'hello', new_text: 'hello world' }, 4),
        call('write_file', { path: 'created.txt', content: 'created autonomously' }, 5),
        call('run_command', { command: 'pwd', cwd: '.' }, 6),
        call('delete_file', { path: 'note.txt' }, 7)
      ];
      else if (prompt === 'Replace the note and run the command' && results.length === 0) calls = [
        call('write_file', { path: 'note.txt', content: 'approved replacement' }, 0),
        call('run_command', { command: 'printf "shell-ok %s" "$PATH" > agent-command.txt', cwd: '.' }, 1)
      ];
      else if (prompt === 'Run a slow command' && results.length === 0) calls = [call('run_command', { command: 'printf started; sleep 20; printf bad > should-not-exist.txt', cwd: '.', timeout_seconds: 120 }, 0)];
      else if (prompt === 'Propose another overwrite' && results.length === 0) calls = [call('write_file', { path: 'note.txt', content: 'must not happen' }, 0)];
      res.writeHead(200, { 'Content-Type': 'text/event-stream' });
      if (calls) res.end('data: ' + JSON.stringify({ choices: [{ delta: { tool_calls: calls } }] }) + '\n\ndata: {"choices":[{"delta":{},"finish_reason":"tool_calls"}]}\n\ndata: [DONE]\n\n');
      else res.end('data: ' + JSON.stringify({ choices: [{ delta: { content: 'Finished with the reported tool results.' }, finish_reason: 'stop' }] }) + '\n\ndata: [DONE]\n\n');
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve)); endpoint = `http://127.0.0.1:${server.address().port}/v1`;
  application = await electron.launch({ ...(process.env.BENJAMIN_EXECUTABLE ? { executablePath: process.env.BENJAMIN_EXECUTABLE, args: [] } : { args: ['.'] }), env: { ...process.env, BENJAMIN_TEST_DATA: dataDir } });
  page = await application.firstWindow();
});
test.afterAll(async () => { await application?.close(); await new Promise(resolve => server.close(resolve)); await fs.rm(dataDir, { recursive: true, force: true }); });
async function ask(text) { await page.locator('#prompt').fill(text); await page.getByRole('button', { name: 'Send message', exact: true }).click(); }
const waiting = () => page.locator('.action-card[data-status="awaiting-approval"]').last();
test('agent creates/edits files, pauses for destructive actions, restores and cancels safely', async () => {
  const errors = []; page.on('pageerror', e => errors.push(e.message));
  await expect(page.locator('#shell-status')).toContainText('interactive');
  await page.getByRole('button', { name: 'Settings', exact: true }).click();
  await page.locator('#base-url').fill(endpoint); await page.locator('#model-id').fill('tool-test');
  await page.getByRole('button', { name: 'Save connection' }).click();
  await application.evaluate(({ dialog }, root) => { dialog.showOpenDialog = async () => ({ canceled: false, filePaths: [root] }); }, root);
  await page.getByRole('button', { name: 'Agent', exact: true }).click();
  await expect(page.locator('#agent-mode')).toHaveAttribute('aria-pressed', 'true');
  await page.getByRole('tab', { name: 'Marlowe', exact: true }).click();
  await page.locator('#prompt').fill('Preserve this separate draft');
  await page.locator('[data-session="marlowe"] .xterm-helper-textarea').focus();
  await page.keyboard.type('Create and edit, then propose deleting the note');
  await page.keyboard.press('Enter');
  await expect(page.locator('#prompt')).toHaveValue('Preserve this separate draft');
  await expect(waiting()).toContainText('Delete this file');
  await expect(page.locator('[data-session="marlowe"] .xterm-rows')).toContainText('awaiting-approval');
  await expect(page.locator('#messages')).not.toContainText('I requested approval.');
  expect(await fs.readFile(path.join(root, 'note.txt'), 'utf8')).toBe('hello world');
  expect(await fs.readFile(path.join(root, 'created.txt'), 'utf8')).toBe('created autonomously');
  await expect(page.locator('.action-card').filter({ hasText: 'run command' }).first()).toContainText('completed');
  await expect(page.locator('.action-card').filter({ hasText: 'find files' }).first().locator('pre')).toContainText('Found 1 file.\nnote.txt');
  await expect(page.locator('.action-card').filter({ hasText: 'search text' }).first().locator('pre')).toContainText('note.txt:1: hello');
  await expect(waiting().locator('.diff-line[data-kind="removed"]')).toHaveText('− hello world');
  await expect(waiting().locator('.action-title')).toContainText('+0 −1');
  await expect(page.locator('[data-session="marlowe"] .xterm-rows')).toContainText('(+0 −1)');
  await expect(page.locator('.action-card').filter({ hasText: 'edit file' }).first().locator('.diff-line')).toHaveText(['− hello', 'No newline at end of file', '+ hello world', 'No newline at end of file']);
  await page.screenshot({ path: 'test-results/benjamin-agent-approval.png', scale: 'css' });
  await waiting().getByRole('button', { name: 'Deny', exact: true }).click();
  await expect(page.locator('#stop-button')).toBeHidden();
  expect(await fs.readFile(path.join(root, 'note.txt'), 'utf8')).toBe('hello world');
  await page.reload();
  await page.getByRole('button', { name: 'Agent', exact: true }).click();
  await ask('Replace the note and run the command');
  await expect(waiting()).toContainText('approved replacement');
  await expect(waiting().locator('.diff-hunk')).toHaveText('@@ -1,1 +1,1 @@');
  await expect(waiting().locator('.diff-line[data-kind="added"]')).toHaveText('+ approved replacement');
  await expect(waiting().locator('pre')).toBeHidden();
  await waiting().screenshot({ path: 'test-results/benjamin-diff-card.png' });
  await page.locator('#theme-toggle').click();
  await waiting().screenshot({ path: 'test-results/benjamin-diff-card-dark.png' });
  await page.locator('#theme-toggle').click();
  await waiting().getByRole('button', { name: 'Show full file' }).click();
  await expect(waiting().locator('pre')).toContainText('--- Before: note.txt\nhello world');
  await expect(waiting().locator('.diff')).toBeHidden();
  await waiting().getByRole('button', { name: 'Show changes' }).click();
  await expect(waiting().locator('.diff')).toBeVisible();
  expect(await fs.readFile(path.join(root, 'note.txt'), 'utf8')).toBe('hello world');
  await waiting().getByRole('button', { name: 'Approve once' }).click();
  await expect(waiting()).toContainText('printf "shell-ok');
  await expect(fs.access(path.join(root, 'agent-command.txt'))).rejects.toThrow();
  await waiting().getByRole('button', { name: 'Approve once' }).click();
  await expect(page.locator('#stop-button')).toBeHidden();
  expect(await fs.readFile(path.join(root, 'note.txt'), 'utf8')).toBe('approved replacement');
  const commandOutput = await fs.readFile(path.join(root, 'agent-command.txt'), 'utf8');
  expect(commandOutput).toMatch(/^shell-ok \//);
  await page.getByRole('button', { name: 'Undo file change' }).last().click();
  await expect.poll(() => fs.readFile(path.join(root, 'note.txt'), 'utf8')).toBe('hello world');
  await expect(page.locator('[data-session="marlowe"] .xterm-rows')).toContainText('[undo completed]');
  await page.screenshot({ path: 'test-results/benjamin-connected-terminal.png', scale: 'css' });
  await ask('Run a slow command');
  await expect(waiting()).toContainText('sleep 20');
  await expect(waiting()).toContainText('Time limit: 2 minutes');
  await waiting().getByRole('button', { name: 'Approve once' }).click();
  await expect(page.locator('.action-card').last().locator('pre')).toContainText('started');
  await expect(page.locator('[data-session="marlowe"] .xterm-rows')).toContainText('started');
  await expect(page.locator('.action-card').last().locator('.action-status')).toHaveText(/running · \d+s/);
  await page.locator('#stop-button').click();
  await expect(page.locator('#stop-button')).toBeHidden();
  await expect(fs.access(path.join(root, 'should-not-exist.txt'))).rejects.toThrow();
  await ask('Propose another overwrite');
  await expect(waiting()).toContainText('must not happen');
  await page.locator('#stop-button').click();
  await expect(page.locator('#stop-button')).toBeHidden();
  expect(await fs.readFile(path.join(root, 'note.txt'), 'utf8')).toBe('hello world');
  await expect(page.getByRole('button', { name: 'Approve once' })).toHaveCount(0);
  const logs = (await fs.readdir(path.join(dataDir, 'agent-runs'))).filter(file => file.endsWith('.jsonl'));
  expect(logs.length).toBe(4);
  // The command saw exactly the PATH the host recorded for its run, without workspace or relative entries.
  const recorded = (await Promise.all(logs.map(file => fs.readFile(path.join(dataDir, 'agent-runs', file), 'utf8')))).map(log => JSON.parse(log.split('\n')[0]).commandPath);
  const commandPath = commandOutput.slice('shell-ok '.length);
  expect(recorded.every(value => value === recorded[0])).toBe(true);
  expect(recorded[0] === 'default' ? DEFAULT_PATH : recorded[0]).toBe(commandPath);
  expect(commandPath.split(':').every(entry => path.isAbsolute(entry) && !entry.startsWith(root))).toBe(true);
  expect((await Promise.all(logs.map(file => fs.readFile(path.join(dataDir, 'agent-runs', file), 'utf8')))).join('')).toContain('"status":"denied"');
  await page.getByRole('button', { name: 'Agent reliability', exact: true }).click();
  await expect(page.locator('#reliability-dialog')).toBeVisible();
  await expect(page.locator('.reliability-run')).toHaveCount(4);
  await expect(page.locator('.reliability-metric').filter({ hasText: 'Unsupported claims detected' }).locator('strong')).toHaveText('1');
  await expect(page.locator('.reliability-metric').filter({ hasText: 'Undo outcomes' }).locator('strong')).toHaveText('1');
  await page.locator('#reliability-model').selectOption('tool-test');
  await expect(page.locator('.reliability-run')).toHaveCount(4);
  await page.getByRole('button', { name: 'Run checks', exact: true }).click();
  await expect(page.locator('.reliability-check-result[data-passed="true"]')).toHaveCount(10);
  await page.locator('#reliability-dialog').evaluate(node => node.scrollTop = 0);
  await page.screenshot({ path: 'test-results/benjamin-reliability.png', scale: 'css' });
  await page.getByRole('button', { name: 'Close reliability', exact: true }).click();
  await page.locator('#theme-toggle').click();
  await page.getByRole('button', { name: 'Agent reliability', exact: true }).click();
  await expect(page.locator('.reliability-check-result[data-passed="true"]')).toHaveCount(10);
  await page.locator('#reliability-dialog').evaluate(node => node.scrollTop = 0);
  await page.screenshot({ path: 'test-results/benjamin-reliability-dark.png', scale: 'css' });
  await page.getByRole('button', { name: 'Close reliability', exact: true }).click();
  expect(errors).toEqual([]);
});
