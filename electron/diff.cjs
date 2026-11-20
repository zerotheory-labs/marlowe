// Line diff for review cards. It runs in the main process on model-supplied
// content, so the comparison table and the returned hunks are both bounded.
const CONTEXT = 3, MAX_CELLS = 4000000, MAX_LINES = 1500, MAX_WIDTH = 400;
const split = text => (text || '').match(/[^\n]*\n|[^\n]+$/g) || [];
// One character per step: ' ' kept, '-' only in a, '+' only in b.
function operations(a, b) {
  let start = 0, endA = a.length, endB = b.length;
  while (start < endA && start < endB && a[start] === b[start]) start++;
  while (endA > start && endB > start && a[endA - 1] === b[endB - 1]) { endA--; endB--; }
  const n = endA - start, m = endB - start, ops = new Array(start).fill(' ');
  if (n && m && n * m <= MAX_CELLS) {
    const ids = new Map(), id = line => { let value = ids.get(line); if (value === undefined) ids.set(line, value = ids.size); return value; };
    const x = a.slice(start, endA).map(id), y = b.slice(start, endB).map(id), width = m + 1, table = new Uint16Array((n + 1) * width);
    for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) table[i * width + j] = x[i] === y[j] ? table[(i + 1) * width + j + 1] + 1 : Math.max(table[(i + 1) * width + j], table[i * width + j + 1]);
    let i = 0, j = 0;
    while (i < n && j < m) {
      if (x[i] === y[j]) { ops.push(' '); i++; j++; }
      else if (table[(i + 1) * width + j] >= table[i * width + j + 1]) { ops.push('-'); i++; }
      else { ops.push('+'); j++; }
    }
    for (; i < n; i++) ops.push('-');
    for (; j < m; j++) ops.push('+');
  } else {
    // One side is empty, or the middle is too large to align line by line:
    // still exact, shown as one replaced block.
    for (let i = 0; i < n; i++) ops.push('-');
    for (let j = 0; j < m; j++) ops.push('+');
  }
  for (let i = endA; i < a.length; i++) ops.push(' ');
  return ops;
}
function lineDiff(before, after) {
  const a = split(before), b = split(after), ops = operations(a, b), rows = [];
  let ai = 0, bi = 0, added = 0, removed = 0;
  for (let index = 0; index < ops.length;) {
    if (ops[index] === ' ') { rows.push({ type: ' ', text: a[ai++] }); bi++; index++; continue; }
    // Show each changed block as its removals followed by its additions.
    const from = ai, to = bi;
    for (; index < ops.length && ops[index] !== ' '; index++) ops[index] === '-' ? ai++ : bi++;
    for (let i = from; i < ai; i++) rows.push({ type: '-', text: a[i] });
    for (let j = to; j < bi; j++) rows.push({ type: '+', text: b[j] });
    removed += ai - from; added += bi - to;
  }
  const hunks = []; let shown = 0, truncated = false, oldLine = 0, newLine = 0, counted = 0;
  for (let index = 0; index < rows.length && !truncated;) {
    if (rows[index].type === ' ') { index++; continue; }
    let end = index;
    for (let next = index; next < rows.length && next <= end + CONTEXT * 2 + 1; next++) if (rows[next].type !== ' ') end = next;
    const start = Math.max(index - CONTEXT, counted), stop = Math.min(end + CONTEXT + 1, rows.length);
    for (; counted < start; counted++) { oldLine++; newLine++; }
    const hunk = { oldStart: oldLine, oldLines: 0, newStart: newLine, newLines: 0, lines: [] };
    for (; counted < stop; counted++) {
      if (shown >= MAX_LINES) { truncated = true; break; }
      const { type, text } = rows[counted];
      if (type !== '+') { oldLine++; hunk.oldLines++; }
      if (type !== '-') { newLine++; hunk.newLines++; }
      const content = text.endsWith('\n') ? text.slice(0, -1) : text;
      hunk.lines.push({ type, text: content.length > MAX_WIDTH ? content.slice(0, MAX_WIDTH) + ' … (long line shortened)' : content }); shown++;
      if (!text.endsWith('\n')) hunk.lines.push({ type: '\\', text: 'No newline at end of file' });
    }
    // Like unified diff: a side with lines starts at its first line, an empty side names the line before.
    if (hunk.oldLines) hunk.oldStart++;
    if (hunk.newLines) hunk.newStart++;
    if (hunk.lines.length) hunks.push(hunk);
    index = stop;
  }
  return { added, removed, hunks, ...(truncated ? { truncated: true } : {}) };
}
module.exports = { lineDiff };
