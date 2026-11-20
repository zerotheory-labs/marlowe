const { test } = require('node:test');
const assert = require('node:assert/strict');
const { TerminalContext } = require('../electron/terminal-context.cjs');
const hex = value => Buffer.from(value).toString('hex');
const mark = (...parts) => '\x1b]777;Benjamin;token;' + parts.join(';') + '\x07';
test('fragmented markers capture exact command output, cwd and original failure status', () => {
  const tracker = new TerminalContext('token', '/start', true); let screen = '';
  const data = 'prompt' + mark('P', '0', hex('/start')) + 'echoed command' + mark('S', hex('/start'), hex('cd "a b"; printf hello; false')) + '\x1b[31mhello\x1b[0m\r\n' + mark('P', '1', hex('/start/a b')) + 'next prompt';
  for (const char of data) tracker.push(char, chunk => screen += chunk);
  assert.equal(screen, 'promptechoed command\x1b[31mhello\x1b[0m\r\nnext prompt');
  assert.equal(tracker.state().cwd, '/start/a b'); assert.equal(tracker.state().last.exitCode, 1);
  const snapshot = tracker.snapshot('last'); assert.match(snapshot.text, /Exit 1/); assert.match(snapshot.text, /hello/);
  assert.doesNotMatch(snapshot.text, /next prompt|echoed command|\x1b/);
  assert.equal(snapshot.cwd, '/start');
});
test('running commands, separate tabs, interrupted commands and unsupported shells do not fabricate completion', () => {
  const a = new TerminalContext('token', '/a', true), b = new TerminalContext('other', '/b', true);
  a.push(mark('S', hex('/a'), hex('sleep 30')), () => {});
  assert.equal(a.state().running, true); assert.throws(() => a.snapshot('last'));
  assert.equal(b.state().running, false); assert.equal(b.state().cwd, '/b');
  a.exit(() => {}); assert.equal(a.state().last.interrupted, true); assert.match(a.snapshot('last').text, /exit status unknown/);
  const fallback = new TerminalContext('unused', '/x'); assert.throws(() => fallback.snapshot('last'));
  assert.match(fallback.snapshot('selection', 'selected only').text, /selected only/);
  assert.equal(fallback.snapshot('selection', 'text').cwd, null);
});
test('token mismatch cannot create command events; snapshots are bounded and retain last failure', () => {
  const t = new TerminalContext('token', '/a', true);
  t.push(mark('P', '0', hex('/a')).replace('token','wrong'), () => {}); assert.equal(t.ready, false);
  t.push(mark('S', hex('/a'), hex('false')) + 'x'.repeat(70000) + mark('P', '2', hex('/a')), () => {});
  t.push(mark('S', hex('/a'), hex('true')) + 'ok' + mark('P', '0', hex('/a')), () => {});
  assert.match(t.snapshot('failure').text, /Exit 2/); assert.ok(t.snapshot('failure').text.length <= 16000);
  assert.match(t.snapshot('last').text, /Exit 0/);
  t.push(mark('S', 'nothex', hex('invalid')), () => {}); assert.equal(t.state().running, false);
});
