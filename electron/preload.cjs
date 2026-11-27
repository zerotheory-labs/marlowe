const { contextBridge, ipcRenderer } = require('electron');
const invoke = channel => (...args) => ipcRenderer.invoke(channel, ...args);
const listen = channel => callback => {
  const listener = (_event, payload) => callback(payload);
  ipcRenderer.on(channel, listener);
  return () => ipcRenderer.removeListener(channel, listener);
};
contextBridge.exposeInMainWorld('benjamin', {
  reliability: invoke('reliability:read'), runReliabilityChecks: invoke('reliability:check'),
  boot: invoke('app:boot'), chooseFolder: invoke('app:folder'), adoptTerminalCwd: invoke('app:adopt-cwd'),
  getScope: invoke('cyber:scope-get'), saveScope: invoke('cyber:scope-save'),
  scanToolchain: invoke('cyber:toolchain'), scanDna: invoke('cyber:dna'), scanGraphs: invoke('cyber:graphs'), redactText: invoke('cyber:redact'),
  listFindings: invoke('findings:list'), updateFinding: invoke('findings:update'),
  deleteFinding: invoke('findings:delete'), clearFindings: invoke('findings:clear'),
  exportFindings: invoke('findings:export'), onFindingsChanged: listen('findings:changed'), onScansChanged: listen('scans:changed'),
  createTerminal: invoke('terminal:create'), writeTerminal: invoke('terminal:write'),
  resizeTerminal: invoke('terminal:resize'), closeTerminal: invoke('terminal:close'),
  terminalContextMenu: invoke('terminal:context-menu'), terminalState: invoke('terminal:state'),
  failureSnapshot: invoke('terminal:failure-snapshot'),
  onTerminalState: listen('terminal:state'), onTerminalContext: listen('terminal:context-request'),
  onTerminalData: listen('terminal:data'), onTerminalExit: listen('terminal:exit'),
  saveSettings: invoke('settings:save'), scanLocalModels: invoke('settings:radar'),
  discoverModels: invoke('settings:discover'), testConnection: invoke('settings:test'),
  saveHistory: invoke('history:save'),
  onAgentEvent: listen('agent:event'), approveAction: invoke('agent:approve'), restoreFile: invoke('agent:restore'),
  chat: invoke('chat:start'), stopChat: invoke('chat:stop'), onChatToken: listen('chat:token')
});
