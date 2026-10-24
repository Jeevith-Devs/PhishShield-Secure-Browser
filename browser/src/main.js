const { app, BrowserWindow, session, ipcMain } = require('electron');
const path = require('path');
const http = require('http');
const fs = require('fs');

const crashLog = path.join(__dirname, 'crash.log');
function log(msg) {
  fs.appendFileSync(crashLog, `[${new Date().toISOString()}] ${msg}\n`);
}

process.on('uncaughtException', (err) => {
  log(`Uncaught exception: ${err.stack || err}`);
});
process.on('unhandledRejection', (reason) => {
  log(`Unhandled rejection: ${reason}`);
});

log('main.js loaded');

// Optimize for Windows desktop display
app.commandLine.appendSwitch('disable-gpu-shader-disk-cache');
app.commandLine.appendSwitch('disable-http-cache');

let mainWindow;
const API_BASE = 'http://127.0.0.1:8000/api/v1';

function postJson(endpoint, data) {
  return new Promise((resolve, reject) => {
    const url = new URL(endpoint);
    const postData = JSON.stringify(data);
    const req = http.request({
      hostname: url.hostname,
      port: url.port || 80,
      path: url.pathname + (url.search || ''),
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData),
      },
    }, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(body));
        } catch (e) {
          resolve({ error: 'Invalid JSON response', body });
        }
      });
    });
    req.on('error', reject);
    req.write(postData);
    req.end();
  });
}

function createWindow() {
  log('createWindow called');
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 920,
    minWidth: 1000,
    minHeight: 700,
    title: 'PhishShield Secure Browser',
    backgroundColor: '#0a0d14',
    icon: path.join(__dirname, 'assets', 'phishshield-icon.png'),
    show: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true,
      webviewTag: true,
    },
  });

  mainWindow.loadFile(path.join(__dirname, 'index.html'));
  mainWindow.setMenuBarVisibility(false);

  mainWindow.show();
  mainWindow.focus();

  mainWindow.on('close', () => {
    log('mainWindow close event fired');
  });

  mainWindow.webContents.on('did-finish-load', () => {
    log('mainWindow webContents did-finish-load');
  });

  mainWindow.webContents.on('did-fail-load', (_e, code, desc) => {
    log(`mainWindow webContents did-fail-load: ${code} - ${desc}`);
  });

  mainWindow.once('ready-to-show', () => {
    log('mainWindow ready-to-show event fired');
    mainWindow.show();
    mainWindow.focus();
  });
}

// ─── IPC Handlers ─────────────────────────────────────────────────────────────

ipcMain.handle('scan-url', async (_event, targetUrl) => {
  try {
    const result = await postJson(`${API_BASE}/scan/url`, {
      url: targetUrl,
      client_type: 'browser',
    });
    return result;
  } catch (err) {
    return {
      error: err.message,
      threat_level: 'UNKNOWN',
      risk_score: 0,
      adaptive_action: 'ALLOW',
      indicators: { reasons: ['Could not connect to PhishShield API'] },
    };
  }
});

ipcMain.handle('launch-sandbox', async (_event, { url, threatLevel }) => {
  try {
    return await postJson(`${API_BASE}/sandbox/launch`, {
      url,
      threat_level: threatLevel || 'HIGH',
      inject_synthetic_data: true,
    });
  } catch (err) {
    return { error: err.message };
  }
});

ipcMain.handle('generate-report', async (_event, scanId) => {
  try {
    return await postJson(`${API_BASE}/analyst/generate`, {
      scan_id: scanId,
      include_sandbox_telemetry: true,
      include_graph_data: true,
    });
  } catch (err) {
    return { error: err.message };
  }
});

app.whenReady().then(() => {
  log('app.whenReady resolved');
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  log('window-all-closed event fired');
  if (process.platform !== 'darwin') app.quit();
});
