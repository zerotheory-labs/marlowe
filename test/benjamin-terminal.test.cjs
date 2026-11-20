const { test } = require('node:test');
const assert = require('node:assert/strict');
test('conversation input never executes pasted newlines; model controls cannot reach the terminal', async () => {
  const { terminalText, conversationTerminal } = await import('../src/benjamin-terminal.mjs');
  assert.equal(terminalText('\x1b]52;c;secret\x07\x1b[31mhello\x1b[0m\nworld'), 'hello\r\nworld');
  const writes = [], sends = []; let input, stopped = 0;
  const view = conversationTerminal({ cols: 80, write: s => writes.push(s), onData: fn => input = fn, onResize() {} }, { send: s => sends.push(s), stop: () => stopped++, getMode: () => 'agent' });
  input('create files\nrm something\r'); assert.deepEqual(sends, []);
  input('\r'); assert.deepEqual(sends, ['create files rm something']);
  view.begin(sends[0]); input('unwanted'); input('\r'); assert.equal(sends.length, 1);
  view.token('partial output'); view.line('[completed]');
  assert.ok(!writes.at(-1).includes('\x1b[2K')); // Never erase an unterminated output line.
  input('\x03'); assert.equal(stopped, 1);
  view.end(); input('next'); input('\r'); assert.equal(sends[1], 'next');
});

test('reply formatting stays compact, handles streamed Markdown, and strips model escapes', async () => {
  const { conversationTerminal } = await import('../src/benjamin-terminal.mjs');
  const writes = [];
  const view = conversationTerminal({ cols: 80, write: s => writes.push(s), onData() {}, onResize() {} }, { send() {}, stop() {}, getMode: () => 'agent' });
  view.begin('test'); writes.length = 0;
  view.line('Running', 'info'); view.line('Done', 'success');
  assert.equal(writes.join(''), '\x1b[36mRunning\x1b[0m\r\n\x1b[32mDone\x1b[0m\r\n');
  writes.length = 0;
  view.reply('## Result\n**Cre'); view.reply('ated** `hello.txt`\n\x1b]52;c;secret\x07Safe'); view.flushReply();
  const output = writes.join('');
  assert.ok(output.includes('\x1b[35mResult'));
  assert.ok(output.includes('\x1b[1mCreated\x1b[22m'));
  assert.ok(output.includes('\x1b[36mhello.txt'));
  assert.ok(!output.includes('secret'));
  assert.ok(output.endsWith('Safe\r\n'));
});
