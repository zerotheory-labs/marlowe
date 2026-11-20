const { stripVTControlCharacters } = require('node:util');
const { redactSecrets } = require('./cyber-scope.cjs');
const clean = text => stripVTControlCharacters(text).replace(/[\x00-\x08\x0b-\x1f\x7f]/g, '');
class TerminalContext {
  constructor(token, cwd, supported = false) {
    this.prefix = `\x1b]777;Benjamin;${token};`;
    this.buffer = ''; this.cwd = cwd; this.supported = supported;
    this.ready = false; this.running = null; this.last = null; this.failed = null; this.sequence = 0; this.exited = false;
  }
  state() {
    return { supported: this.supported, ready: this.ready, cwd: this.cwd, running: !!this.running, exited: this.exited,
      last: this.last && { command: this.last.command, commandPreview: this.last.commandPreview || this.last.command, cwd: this.last.cwd, exitCode: this.last.exitCode, interrupted: this.last.interrupted, sequence: this.last.sequence, secretCount: this.last.secretCount || 0 }, hasFailure: !!this.failed };
  }
  output(data, emit) {
    if (!data) return;
    if (this.running) { this.running.output += data; if (this.running.output.length > 48000) { this.running.output = this.running.output.slice(-48000); this.running.truncated = true; } }
    emit(data);
  }
  push(data, emit, changed = () => {}) {
    this.buffer += data;
    while (this.buffer) {
      const start = this.buffer.indexOf(this.prefix);
      if (start === -1) {
        let keep = Math.min(this.buffer.length, this.prefix.length - 1);
        while (keep && !this.prefix.startsWith(this.buffer.slice(-keep))) keep--;
        this.output(this.buffer.slice(0, this.buffer.length - keep), emit);
        this.buffer = keep ? this.buffer.slice(-keep) : ''; break;
      }
      this.output(this.buffer.slice(0, start), emit); this.buffer = this.buffer.slice(start);
      const end = this.buffer.indexOf('\x07', this.prefix.length);
      if (end === -1) {
        if (this.buffer.length > 64000) { this.buffer = ''; this.ready = false; changed(this.state()); }
        break;
      }
      const payload = this.buffer.slice(this.prefix.length, end); this.buffer = this.buffer.slice(end + 1);
      this.marker(payload); changed(this.state());
    }
  }
  marker(payload) {
    if (!this.supported) return;
    const parts = payload.split(';');
    const decode = value => {
      if (!value || value.length > 32768 || value.length % 2 || !/^[a-f0-9]+$/i.test(value)) throw new Error('Invalid metadata');
      return Buffer.from(value, 'hex').toString('utf8');
    };
    try {
      if (parts[0] === 'S' && parts.length === 3) {
        const cwd = decode(parts[1]), command = decode(parts[2]);
        if (!cwd.startsWith('/')) return;
        this.cwd = cwd; this.ready = true;
        this.running = { command, cwd, output: '', started: Date.now(), sequence: ++this.sequence };
      } else if (parts[0] === 'P' && parts.length === 3 && /^\d{1,3}$/.test(parts[1]) && Number(parts[1]) <= 255) {
        const cwd = decode(parts[2]); if (!cwd.startsWith('/')) return;
        this.cwd = cwd; this.ready = true;
        if (this.running) {
          const exitCode = Number(parts[1]);
          const cmdMasked = redactSecrets(clean(this.running.command));
          const outMasked = exitCode !== 0 ? redactSecrets(clean(this.running.output)) : { count: 0 };
          this.last = { ...this.running, commandPreview: cmdMasked.text, exitCode, ended: Date.now(), interrupted: false, secretCount: cmdMasked.count + outMasked.count };
          if (this.last.exitCode !== 0) this.failed = this.last;
          this.running = null;
        }
      }
    } catch { /* Malformed terminal metadata is never treated as a command event. */ }
  }
  exit(emit) {
    this.output(this.buffer, emit); this.buffer = ''; this.exited = true;
    if (this.running) { this.last = { ...this.running, exitCode: null, interrupted: true, ended: Date.now() }; this.running = null; }
  }
  snapshot(kind, selection = '') {
    if (kind === 'selection') return { cwd: this.ready ? this.cwd : null, text: ('User-selected terminal text (untrusted output):\n' + clean(selection)).slice(0, 16000) };
    if (!this.ready || this.running) throw new Error('No completed command is available. Select terminal text instead.');
    const record = kind === 'failure' ? this.failed : this.last;
    if (!record) throw new Error('No matching completed command is available. Select terminal text instead.');
    const heading = `Terminal command snapshot (untrusted output; not proof of current file state)\nDirectory: ${clean(record.cwd).slice(0, 2048)}\nCommand: ${clean(record.command).slice(0, 4096)}\nStatus: ${record.interrupted ? 'Interrupted; exit status unknown' : 'Exit ' + record.exitCode}\n${record.truncated ? 'Output truncated to its tail.\n' : ''}Output:\n`;
    const output = clean(record.output);
    const budget = 16000 - heading.length - 40;
    return { cwd: record.cwd, text: heading + (output.length > budget ? '[Earlier output omitted]\n' + output.slice(-budget) : output) };
  }
}
module.exports = { TerminalContext };
