const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { lineDiff } = require('../electron/diff.cjs');
const { prepareTool } = require('../electron/agent-tools.cjs');
const { runAgent } = require('../electron/agent.cjs');
const split = text => (text || '').match(/[^\n]*\n|[^\n]+$/g) || [];
const text = hunk => hunk.lines.map(line => line.type + line.text);
// Every hunk must describe exactly the lines it names on both sides, and what lies outside the hunks must be unchanged.
function verify(before, after) {
  const diff = lineDiff(before, after), a = split(before), b = split(after);
  let oldAt = 0, newAt = 0, added = 0, removed = 0;
  for (const hunk of diff.hunks) {
    const oldStart = hunk.oldLines ? hunk.oldStart - 1 : hunk.oldStart, newStart = hunk.newLines ? hunk.newStart - 1 : hunk.newStart;
    assert.deepEqual(a.slice(oldAt, oldStart), b.slice(newAt, newStart));
    const lines = hunk.lines.filter(line => line.type !== '\\'), strip = line => line.replace(/\n$/, '');
    assert.deepEqual(lines.filter(line => line.type !== '+').map(line => line.text), a.slice(oldStart, oldStart + hunk.oldLines).map(strip));
    assert.deepEqual(lines.filter(line => line.type !== '-').map(line => line.text), b.slice(newStart, newStart + hunk.newLines).map(strip));
    assert.ok(lines.some(line => line.type !== ' '));
    added += lines.filter(line => line.type === '+').length; removed += lines.filter(line => line.type === '-').length;
    oldAt = oldStart + hunk.oldLines; newAt = newStart + hunk.newLines;
  }
  assert.deepEqual(a.slice(oldAt), b.slice(newAt));
  assert.equal(diff.added, added); assert.equal(diff.removed, removed); assert.equal(a.length - removed + added, b.length);
  return diff;
}
const numbered = (count, change = {}) => Array.from({ length: count }, (_, i) => change[i + 1] ?? `line ${i + 1}`).join('\n') + '\n';

test('line diff shows a small change with three lines of context', () => {
  const diff = verify(numbered(20), numbered(20, { 10: 'line ten' }));
  assert.equal(diff.added, 1); assert.equal(diff.removed, 1); assert.equal(diff.hunks.length, 1);
  assert.deepEqual({ ...diff.hunks[0], lines: undefined }, { oldStart: 7, oldLines: 7, newStart: 7, newLines: 7, lines: undefined });
  assert.deepEqual(text(diff.hunks[0]), [' line 7', ' line 8', ' line 9', '-line 10', '+line ten', ' line 11', ' line 12', ' line 13']);
});
test('line diff separates distant changes, merges close ones and keeps removals before additions', () => {
  assert.equal(verify(numbered(40), numbered(40, { 5: 'five', 30: 'thirty' })).hunks.length, 2);
  assert.equal(verify(numbered(40), numbered(40, { 5: 'five', 12: 'twelve' })).hunks.length, 1);
  assert.equal(verify(numbered(40), numbered(40, { 5: 'five', 13: 'thirteen' })).hunks.length, 2);
  assert.deepEqual(text(verify('a\nb\nc\nd\n', 'a\nx\ny\nd\n').hunks[0]), [' a', '-b', '-c', '+x', '+y', ' d']);
  const inserted = verify('a\nb\n', 'a\nnew\nb\n');
  assert.equal(inserted.added, 1); assert.equal(inserted.removed, 0); assert.deepEqual(text(inserted.hunks[0]), [' a', '+new', ' b']);
});
test('line diff handles new, deleted, empty, unchanged and unterminated files', () => {
  const created = verify(null, 'one\ntwo\n');
  assert.deepEqual({ ...created.hunks[0], lines: text(created.hunks[0]) }, { oldStart: 0, oldLines: 0, newStart: 1, newLines: 2, lines: ['+one', '+two'] });
  const deleted = verify('one\ntwo\n', null);
  assert.deepEqual({ ...deleted.hunks[0], lines: text(deleted.hunks[0]) }, { oldStart: 1, oldLines: 2, newStart: 0, newLines: 0, lines: ['-one', '-two'] });
  assert.deepEqual(verify('same\n', 'same\n'), { added: 0, removed: 0, hunks: [] });
  assert.deepEqual(verify('', ''), { added: 0, removed: 0, hunks: [] });
  assert.deepEqual(text(verify('end', 'end\n').hunks[0]), ['-end', '\\No newline at end of file', '+end']);
  assert.deepEqual(text(verify('a\r\nb\n', 'a\nb\n').hunks[0]), ['-a\r', '+a', ' b']);
});
test('line diff stays exact on random edits', () => {
  let seed = 7; const random = max => (seed = (seed * 1103515245 + 12345) % 2147483648) % max;
  for (let round = 0; round < 300; round++) {
    const lines = Array.from({ length: random(40) }, () => `v${random(6)}`), edited = [...lines];
    for (let edits = random(6); edits > 0; edits--) {
      const at = random(edited.length + 1), kind = random(3);
      if (kind === 0) edited.splice(at, 0, `v${random(6)}`); else if (kind === 1) edited.splice(at, 1); else if (at < edited.length) edited[at] = `v${random(9)}`;
    }
    verify(lines.join('\n') + (random(2) ? '\n' : ''), edited.join('\n') + (random(2) ? '\n' : ''));
  }
});
test('line diff bounds its work and output on large or hostile input', () => {
  const big = Array.from({ length: 6000 }, (_, i) => `old ${i}`).join('\n') + '\n', other = Array.from({ length: 6000 }, (_, i) => `new ${i}`).join('\n') + '\n';
  const started = Date.now(), replaced = lineDiff(big, other);
  assert.ok(Date.now() - started < 2000); assert.equal(replaced.added, 6000); assert.equal(replaced.removed, 6000); assert.equal(replaced.truncated, true);
  assert.equal(replaced.hunks.flatMap(hunk => hunk.lines).length, 1500); assert.equal(replaced.hunks[0].oldLines, 1500);
  // A change in the middle of a large file is still found exactly.
  const middle = verify(numbered(9000), numbered(9000, { 4500: 'changed' }));
  assert.equal(middle.added, 1); assert.equal(middle.hunks[0].oldStart, 4497);
  const aligned = verify(numbered(1500, { 1: 'first' }), numbered(1500, { 1500: 'last' }));
  assert.equal(aligned.added, 2); assert.equal(aligned.hunks.length, 2);
  const long = lineDiff('short\n', 'x'.repeat(5000) + '\n').hunks[0].lines[1].text;
  assert.ok(long.length < 450); assert.match(long, /long line shortened/);
});
test('file plans carry the diff to the review card and the audit log once', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'benjamin-diff-')), root = path.join(dir, 'workspace');
  try {
    await fs.mkdir(root); await fs.writeFile(path.join(root, 'note.txt'), 'one\ntwo\nthree\n');
    const edit = await prepareTool(root, 'edit_file', { path: 'note.txt', old_text: 'two', new_text: 'TWO' });
    assert.deepEqual(text(edit.diff.hunks[0]), [' one', '-two', '+TWO', ' three']);
    assert.equal((await prepareTool(root, 'write_file', { path: 'new.txt', content: 'a\nb\n' })).diff.added, 2);
    assert.equal((await prepareTool(root, 'delete_file', { path: 'note.txt' })).diff.removed, 3);
    assert.equal((await prepareTool(root, 'read_file', { path: 'note.txt' })).diff, undefined);
    let step = 0; const events = [], audited = [], asked = [];
    await runAgent({ id: 'diff', root, backupDir: path.join(dir, 'backups'), signal: new AbortController().signal, settings: { baseUrl: 'https://example.invalid/v1', model: 'test' }, messages: [{ role: 'user', content: 'Rewrite the note' }], context: '', apiKey: '', onToken() {}, onEvent: event => events.push(event), audit: async event => audited.push(event), approve: async action => { asked.push(action); return true; }, fetchImpl: async () => {
      const reply = step++ ? { content: 'Done.' } : { tool_calls: [{ index: 0, id: 'call_1', type: 'function', function: { name: 'write_file', arguments: JSON.stringify({ path: 'note.txt', content: 'one\nthree\nfour\n' }) } }] };
      return new Response(`data: ${JSON.stringify({ choices: [{ delta: reply, finish_reason: step === 1 ? 'tool_calls' : 'stop' }] })}\n\ndata: [DONE]\n`);
    } });
    assert.deepEqual([asked[0].diff.added, asked[0].diff.removed], [1, 1]);
    assert.deepEqual(text(events.find(event => event.status === 'planned').diff.hunks[0]), [' one', '-two', ' three', '+four']);
    assert.equal(audited.filter(event => event.diff).length, 1);
    assert.equal(await fs.readFile(path.join(root, 'note.txt'), 'utf8'), 'one\nthree\nfour\n');
  } finally { await fs.rm(dir, { recursive: true, force: true }); }
});
