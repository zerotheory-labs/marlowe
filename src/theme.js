const icons = {
  moon: '<path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M2 12h2m16 0h2M5 5l2 2m10 10 2 2M5 19l2-2M17 7l2-2"/>',
  terminal: '<path d="m5 6 5 6-5 6m8 0h6"/>',
  settings: '<path d="m9 4 1-2h4l1 2 2 1 2-.2 2 3.4-1 1.8v2l1 1.8-2 3.4-2-.2-2 1-1 2h-4l-1-2-2-1-2 .2-2-3.4 1-1.8v-2L3 8.2l2-3.4L7 5z" transform="translate(0 1)"/><circle cx="12" cy="12" r="3"/>',
  chart: '<path d="M4 20V11h4v9m2 0V4h4v16m2 0V8h4v12M3 20h18"/>',
  folder: '<path d="M3 7V5h6l2 2h10v12H3z"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  clear: '<path d="M4 10a8 8 0 1 1 1 7M4 4v6h6"/>',
  compose: '<path d="m14 5 5 5M4 20l5-1L21 7a2.1 2.1 0 0 0-4-4L5 15z"/>',
  drawer: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M14.5 4v16"/>',
  arrow: '<path d="M12 19V5m-6 6 6-6 6 6"/>',
  chevron: '<path d="m8 10 4 4 4-4"/>'
};

function icon(name) { return `<svg class="ui-icon" viewBox="0 0 24 24" aria-hidden="true">${icons[name]}</svg>`; }

export function terminalTheme() {
  const dark = document.documentElement.dataset.theme !== 'light';
  return dark ? {
    background: '#151412', foreground: '#d2cec5', cursor: '#3ddc97', selectionBackground: '#3ddc9736',
    black: '#211f1c', red: '#f26d5b', green: '#3ddc97', yellow: '#f2c14e', blue: '#7eafff', magenta: '#d49eff', cyan: '#5ce1e6', white: '#d2cec5',
    brightBlack: '#a39f96', brightRed: '#ff9586', brightGreen: '#6eedb3', brightYellow: '#f7d47c', brightBlue: '#a8c8ff', brightMagenta: '#e5c4ff', brightCyan: '#8eedf0', brightWhite: '#f2efe8'
  } : {
    background: '#eae6dc', foreground: '#131210', cursor: '#176b45', selectionBackground: '#176b4528',
    black: '#131210', red: '#b82f20', green: '#176b45', yellow: '#7a5000', blue: '#1f56b5', magenta: '#6e2d78', cyan: '#145f6c', white: '#6b665e',
    brightBlack: '#6b665e', brightRed: '#d13a2a', brightGreen: '#1e8556', brightYellow: '#966405', brightBlue: '#296ad8', brightMagenta: '#883a94', brightCyan: '#1a798a', brightWhite: '#383530'
  };
}

export function initializeTheme(onChange) {
  for (const [selector, name] of Object.entries({
    '#reliability-button': 'chart', '#settings-button': 'settings', '.folder-icon': 'folder', '.chevron': 'chevron',
    '#new-terminal': 'plus', '#clear-terminal': 'clear', '#toggle-drawer-icon': 'drawer', '#new-chat': 'compose', '#send-button': 'arrow'
  })) {
    const node = document.querySelector(selector);
    if (node) node.innerHTML = icon(name);
  }
  const toggle = document.getElementById('theme-toggle');
  function apply(theme) {
    document.documentElement.dataset.theme = theme;
    const label = `Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`;
    toggle.innerHTML = icon(theme === 'dark' ? 'sun' : 'moon');
    toggle.setAttribute('aria-label', label); toggle.title = label;
    onChange();
  }
  let theme = 'dark';
  try {
    const saved = localStorage.getItem('marlowe-theme');
    if (saved === 'light' || saved === 'dark') theme = saved;
  } catch { /* Default to Marlowe dark if local storage is unavailable. */ }
  apply(theme);
  toggle.addEventListener('click', () => {
    theme = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
    apply(theme);
    try { localStorage.setItem('marlowe-theme', theme); } catch { /* Switching still works without persistence. */ }
  });
}
