// Model/tool text is data, never terminal control sequences or shell input.
export function terminalText(value) {
  return String(value ?? '').replace(/\x1b\][\s\S]*?(?:\x07|\x1b\\)/g, '')
    .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '')
    .replace(/[\x00-\x08\x0b-\x1f\x7f-\x9f]/g, '').replace(/\n/g, '\r\n');
}
export function conversationTerminal(term, { send, stop, getMode }) {
  let draft = '', locked = false, atLineStart = true, replyBuffer = '', inCode = false;
  const tones = { muted: 90, info: 36, success: 32, warning: 33, error: 31, heading: 35 };
  const paint = (text, tone) => tones[tone] ? `\x1b[${tones[tone]}m${text}\x1b[0m` : text;
  const prompt = () => `Marlowe (${getMode()}) › `;
  function redraw() {
    if (locked) return;
    const room = Math.max(1, term.cols - prompt().length - 2);
    const visible = Array.from(draft).slice(-room).join('');
    term.write('\r\x1b[2K\x1b[32m' + prompt() + '\x1b[0m' + visible);
    atLineStart = false;
  }
  function write(text) {
    if (!text) return;
    term.write(text); atLineStart = text.endsWith('\n');
  }
  function line(text, tone) {
    // End a partial output line without erasing it; otherwise add no extra gaps.
    const prefix = locked ? (atLineStart ? '' : '\r\n') : '\r\x1b[2K';
    write(prefix + paint(terminalText(text).replace(/^\r?\n+|(?:\r?\n)+$/g, ''), tone) + '\r\n');
    redraw();
  }
  function replyLine(text) {
    const safe = terminalText(text);
    if (/^\s*```/.test(safe)) {
      inCode = !inCode;
      if (inCode) line(safe.replace(/^\s*```/, '') || 'code', 'muted');
      return;
    }
    if (inCode) { line(text, 'info'); return; }
    const heading = /^#{1,6}\s+/.test(safe);
    const formatted = safe.replace(/^#{1,6}\s+/, '')
      .replace(/\*\*([^*]+)\*\*/g, '\x1b[1m$1\x1b[22m')
      .replace(/`([^`]+)`/g, '\x1b[36m$1\x1b[39m');
    write((atLineStart ? '' : '\r\n') + (heading ? paint(formatted, 'heading') : formatted) + '\r\n');
  }
  function flushReply() { if (replyBuffer) { replyLine(replyBuffer); replyBuffer = ''; } }
  term.onData(data => {
    if (data === '\x03') { if (locked) stop(); else { draft = ''; redraw(); } return; }
    if (locked) return;
    if (data === '\r') {
      const text = draft.trim(); if (!text) return;
      send(text); return;
    }
    if (data === '\x7f' || data === '\b') draft = Array.from(draft).slice(0, -1).join('');
    else if (data === '\x15') draft = '';
    else if (!data.startsWith('\x1b')) draft = (draft + terminalText(data.replace(/\r\n?|\n|\t/g, ' '))).slice(0, 32000);
    redraw();
  });
  term.onResize(redraw);
  return {
    line, redraw,
    begin(text, scopeLabel = '') { draft = ''; replyBuffer = ''; inCode = false; term.write('\r\x1b[2K'); atLineStart = true; locked = true; line(`YOU › ${text}`, 'info'); line(getMode() === 'agent' ? (scopeLabel ? `Agent · ${scopeLabel}` : 'Agent · working in the chosen workspace') : 'Chat · conversation only', 'muted'); },
    end() { flushReply(); locked = false; redraw(); },
    token(text) { write(terminalText(text)); },
    reply(text) { replyBuffer += text; const lines = replyBuffer.split('\n'); replyBuffer = lines.pop(); for (const text of lines) replyLine(text); },
    flushReply,
  };
}
