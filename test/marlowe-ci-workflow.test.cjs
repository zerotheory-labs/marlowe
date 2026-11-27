const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFile } = require('node:fs/promises');
const path = require('node:path');

test('the Desktop guard workflow pins Marlowe CI to the per-commit scanner', async () => {
  const workflow = await readFile(path.join(__dirname, '../.github/workflows/marlowe-ci.yml'), 'utf8');
  const steps = workflow.split(/^[ \t]*-[ \t]+/m);
  const guard = steps.find(step => /^[ \t]*id:[ \t]+['"]?marlowe['"]?[ \t]*(?:#.*)?$/m.test(step));
  assert.ok(guard, 'Expected the Marlowe guard step in the Desktop workflow');

  const uses = /^[ \t]*uses:[ \t]+['"]?([^\s'"]+)/m.exec(guard);
  assert.equal(uses?.[1], 'zerotheory-labs/marlowe-ci@ddf709be1d80c8206f837a77cd464f6bb16322d0');
});
