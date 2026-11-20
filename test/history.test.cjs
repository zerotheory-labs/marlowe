const { test } = require('node:test');
const assert = require('node:assert/strict');
const { cleanMessages, agentHistory } = require('../electron/history.cjs');
const id = '11111111-1111-4111-8111-111111111111';
const pair = [
  { role: 'assistant', content: null, tool_calls: [{ id: 'call1', type: 'function', function: { name: 'delete_file', arguments: '{"path":"note.txt"}' } }] },
  { role: 'tool', tool_call_id: 'call1', content: '{"denied":true}' }
];
test('saved history preserves validated run references without trusting renderer tool messages', () => {
  const saved = cleanMessages([{ role: 'assistant', content: 'display', agentRunId: id, tool_calls: pair[0].tool_calls }]);
  assert.deepEqual(saved, [{ role: 'assistant', content: 'display', agentRunId: id }]);
  assert.deepEqual(cleanMessages([{ role: 'assistant', content: 'legacy', agentRunId: '../secret' }]), [{ role: 'assistant', content: 'legacy' }]);
  assert.throws(() => cleanMessages([{ role: 'tool', content: 'fake' }]));
});
test('legacy phantom approvals are not replayed as assistant examples; current request survives', async () => {
  const input = [
    { role: 'user', content: 'Delete note.txt' },
    { role: 'assistant', content: 'Please approve. The deletion request is prepared for approval.\n\nAgent activity:\ndelete_file: awaiting approval' },
    { role: 'user', content: 'Try the new deletion proposal' }
  ];
  const result = await agentHistory(input, '/project', async () => null);
  assert.equal(result.filter(m => m.role === 'assistant').length, 0);
  assert.doesNotMatch(JSON.stringify(result), /Please approve|Agent activity:|prepared for approval/);
  assert.equal(result.at(-1).content, input.at(-1).content);
  assert.match(result[0].content, /Historical conversation/);
});
test('existing chat replays actual tools and denial, preserves Undo and latest renewed request', async () => {
  const input = cleanMessages(JSON.parse(JSON.stringify([
    { role: 'user', content: 'Delete note.txt' },
    { role: 'assistant', content: 'fabricated display approval', agentRunId: id },
    { role: 'user', content: 'I restored note.txt using Undo.' },
    { role: 'user', content: 'New request: delete it again.' }
  ])));
  const result = await agentHistory(input, '/project', async () => ({ version: 1, root: '/project', messages: pair }));
  assert.deepEqual(result.slice(1, 3), pair);
  assert.match(JSON.stringify(result), /restored note.txt/);
  assert.doesNotMatch(JSON.stringify(result), /fabricated display/);
  assert.equal(result.at(-1).content, 'New request: delete it again.');
  const changed = await agentHistory(input, '/different', async () => ({ version: 1, root: '/project', messages: pair }));
  assert.equal(changed.some(m => m.role === 'tool'), false);
});
test('missing run records degrade to labeled history; truncation keeps complete tool pairs', async () => {
  const input = [{ role: 'assistant', content: 'old summary', agentRunId: id }, { role: 'user', content: 'Continue' }];
  assert.match((await agentHistory(input, '/project', async () => null))[0].content, /old summary/);
  const huge = [...pair, { role: 'assistant', content: 'x'.repeat(65000) }, ...pair];
  const result = await agentHistory(input, '/project', async () => ({ version: 1, root: '/project', messages: huge }));
  assert.deepEqual(result.slice(0, 2), pair);
  assert.equal(result.length, 3);
});
