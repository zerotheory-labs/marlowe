const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFile } = require('node:fs/promises');
const path = require('node:path');

test('the Desktop guard workflow pins Marlowe CI v0.7.2 by its full commit SHA', async () => {
  const workflow = await readFile(path.join(__dirname, '../.github/workflows/marlowe-ci.yml'), 'utf8');
  const steps = workflow.split(/^[ \t]*-[ \t]+/m);
  const guard = steps.find(step => /^[ \t]*id:[ \t]+['"]?marlowe['"]?[ \t]*(?:#.*)?$/m.test(step));
  assert.ok(guard, 'Expected the Marlowe guard step in the Desktop workflow');

  const uses = /^[ \t]*uses:[ \t]+['"]?([^\s'"]+)/m.exec(guard);
  assert.equal(uses?.[1], 'zerotheory-labs/marlowe-ci@f789227964550dc3191765ac5e59309654023f65');
});
