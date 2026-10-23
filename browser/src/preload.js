const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('phishshield', {
  scanUrl: (url) => ipcRenderer.invoke('scan-url', url),
  launchSandbox: (url, threatLevel) => ipcRenderer.invoke('launch-sandbox', { url, threatLevel }),
  generateAnalystReport: (scanId) => ipcRenderer.invoke('generate-report', scanId),
  onSecurityUpdate: (callback) => ipcRenderer.on('security-update', (_event, value) => callback(value)),
  onNavigationBlocked: (callback) => ipcRenderer.on('navigation-blocked', (_event, value) => callback(value)),
});
