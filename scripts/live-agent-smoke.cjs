// Runs the production agent engine against the user's saved local connection.
// Every approval is explicit stdin input; nothing is auto-approved.
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const readline = require('node:readline');
const { randomUUID } = require('node:crypto');
const { runAgent, ApprovalGate } = require('../electron/agent.cjs');
const { restoreBackup } = require('../electron/agent-tools.cjs');
(async () => {
  const settings = JSON.parse(await fs.readFile(path.join(os.homedir(), 'Library/Application Support/Benjamin/settings.json'), 'utf8'));
  if (settings.baseUrl !== 'http://127.0.0.1:11434/v1') throw new Error('This smoke test only uses the local Ollama endpoint.');
  const root = await fs.realpath(path.resolve('examples/agent-playground'));
  const logs = path.resolve('.live-agent'); await fs.mkdir(logs, { recursive: true });
  const backupDir = path.join(logs, 'backups');
  if (process.argv[2] === 'restore') { console.log(JSON.stringify(await restoreBackup(backupDir, process.argv[3]))); return; }
  const prompt = process.argv[2] === 'delete' ? 'Read obsolete-note.txt, then use delete_file to delete exactly obsolete-note.txt. Do not modify any other file. If deletion is denied, stop and acknowledge the denial; do not retry.' : 'Read greeting.cjs and greeting.test.cjs. Update greet so an omitted name returns "Hello, friend!" while greet("Ada") still returns "Hello, Ada!". Add a missing-name test to greeting.test.cjs. Use edit_file for focused edits. If module.exports is duplicated, remove the duplicate so it appears exactly once. Run exactly `node --test greeting.test.cjs` with run_command to verify. Do not delete files, install packages, or change other files.';
  const controller = new AbortController(), gate = new ApprovalGate(), id = randomUUID();
  let pending;
  const input = readline.createInterface({ input: process.stdin, output: process.stdout });
  input.on('line', line => {
    if (line.trim() === 'stop') controller.abort(new Error('Stopped by user'));
    else if (pending && ['approve', 'deny'].includes(line.trim())) {
      gate.decide(id, pending, line.trim() === 'approve'); pending = null;
    }
  });
  const timer = setTimeout(() => controller.abort(new Error('Live test timed out after ten minutes')), 600000);
  const logfile = path.join(logs, `${id}.jsonl`);
  console.log(JSON.stringify({ phase: 'start', id, root, model: settings.model, logfile }));
  try {
    const result = await runAgent({ id, root, settings, fetchImpl: async (url, init) => {
        await fs.writeFile(path.join(logs, 'last-request.json'), init.body, { mode: 0o600 });
        const response = await fetch(url, init);
        if (!response.ok) console.log('LOCAL_SERVER_ERROR', (await response.clone().text()).slice(0, 2000));
        return response;
      }, apiKey: '', messages: [{ role: 'user', content: prompt }], context: '', signal: controller.signal, backupDir,
      onToken: token => process.stdout.write(token),
      onEvent: event => { if (event.status !== 'output') console.log('\n' + JSON.stringify(event)); },
      audit: event => fs.appendFile(logfile, JSON.stringify({ time: new Date().toISOString(), ...event }) + '\n', { mode: 0o600 }),
      approve: action => gate.wait(action, controller.signal, event => { pending = event.approvalId; console.log('\nAPPROVAL_REQUIRED ' + JSON.stringify(event)); })
    });
    console.log('\nRUN_COMPLETE ' + JSON.stringify(result));
  } finally { clearTimeout(timer); input.close(); }
})().catch(error => { console.error('RUN_FAILED', error.message); process.exitCode = 1; });
