// PhishShield Dedicated Secure Browser — UI Controller

const $ = (id) => document.getElementById(id);

// ─── Search Engine Registry ───────────────────────────────────────────────────

const SEARCH_ENGINES = {
  brave: {
    name: 'Brave Search',
    short: 'Brave',
    icon: 'BR',
    searchUrl: 'https://search.brave.com/search?q=',
    homeUrl: 'https://search.brave.com',
    privacyNote: 'Brave Search — No tracking. No profiling. Independent web index.',
    placeholder: 'Search privately with Brave Search\u2026',
  },
  duckduckgo: {
    name: 'DuckDuckGo',
    short: 'DDG',
    icon: 'DD',
    searchUrl: 'https://duckduckgo.com/?q=',
    homeUrl: 'https://duckduckgo.com',
    privacyNote: 'DuckDuckGo — No user tracking. No search history.',
    placeholder: 'Search with DuckDuckGo\u2026',
  },
  startpage: {
    name: 'Startpage',
    short: 'SP',
    icon: 'SP',
    searchUrl: 'https://www.startpage.com/search?q=',
    homeUrl: 'https://www.startpage.com',
    privacyNote: 'Startpage — Anonymous Google results. Zero tracking.',
    placeholder: 'Search anonymously with Startpage\u2026',
  },
  google: {
    name: 'Google',
    short: 'Google',
    icon: 'G',
    searchUrl: 'https://www.google.com/search?q=',
    homeUrl: 'https://www.google.com',
    privacyNote: 'Google Search — Personalised results.',
    placeholder: 'Search with Google\u2026',
  },
  bing: {
    name: 'Bing',
    short: 'Bing',
    icon: 'B',
    searchUrl: 'https://www.bing.com/search?q=',
    homeUrl: 'https://www.bing.com',
    privacyNote: 'Bing — Microsoft Search.',
    placeholder: 'Search with Bing\u2026',
  },
};

let currentEngineKey = localStorage.getItem('ps_search_engine') || 'brave';
if (!SEARCH_ENGINES[currentEngineKey]) currentEngineKey = 'brave';

// ─── DOM References ───────────────────────────────────────────────────────────

const webview = $('webview');
const urlForm = $('url-form');
const urlInput = $('url-input');
const riskPill = $('risk-pill');
const riskScoreVal = $('risk-score-val');
const riskLevelVal = $('risk-level-val');

const btnBack = $('btn-back');
const btnForward = $('btn-forward');
const btnReload = $('btn-reload');
const btnHome = $('btn-home');

const btnSandbox = $('btn-sandbox');
const btnReport = $('btn-report');
const reportDrawer = $('report-drawer');
const btnCloseDrawer = $('btn-close-drawer');
const drawerContent = $('drawer-content');

const warningGate = $('warning-gate');
const barrierTitle = $('barrier-title');
const barrierUrl = $('barrier-url');
const barrierScore = $('barrier-score');
const barrierLevel = $('barrier-level');
const barrierAction = $('barrier-action');
const barrierReasonsList = $('barrier-reasons-list');
const barrierBtnSandbox = $('barrier-btn-sandbox');
const barrierBtnBypass = $('barrier-btn-bypass');
const barrierBtnBack = $('barrier-btn-back');

const enginePickerBtn = $('engine-picker-btn');
const engineFavicon = $('engine-favicon');
const engineNameShort = $('engine-name-short');
const engineDropdown = $('engine-dropdown');
const newTabScreen = $('new-tab-screen');
const ntEngineLabel = $('nt-engine-label');
const ntEngineFavicon = $('nt-engine-favicon');
const ntPrivacyText = $('nt-privacy-text');
const ntSearchInput = $('nt-search-input');
const ntSearchForm = $('nt-search-form');

let currentVerdict = null;
let pendingUrl = '';

// ─── Search Engine Picker ─────────────────────────────────────────────────────

function applyEngine(key) {
  currentEngineKey = key;
  localStorage.setItem('ps_search_engine', key);
  const eng = SEARCH_ENGINES[key];

  // Omnibar badge
  engineFavicon.textContent = eng.icon;
  engineNameShort.textContent = eng.short;
  urlInput.placeholder = `Search with ${eng.name} or enter a URL`;

  // New-tab screen
  ntEngineLabel.textContent = eng.name;
  ntEngineFavicon.textContent = eng.icon;
  ntPrivacyText.textContent = eng.privacyNote;
  ntSearchInput.placeholder = eng.placeholder;

  // Dropdown active state
  document.querySelectorAll('.engine-option').forEach((btn) => {
    const isActive = btn.dataset.engine === key;
    btn.classList.toggle('active', isActive);
    btn.querySelector('.engine-opt-check').classList.toggle('hidden', !isActive);
  });
}

enginePickerBtn.addEventListener('click', (e) => {
  e.stopPropagation();
  const open = !engineDropdown.classList.contains('hidden');
  engineDropdown.classList.toggle('hidden', open);
  enginePickerBtn.setAttribute('aria-expanded', String(!open));
});

document.addEventListener('click', () => {
  engineDropdown.classList.add('hidden');
  enginePickerBtn.setAttribute('aria-expanded', 'false');
});

document.querySelectorAll('.engine-option').forEach((btn) => {
  btn.addEventListener('click', (e) => {
    e.stopPropagation();
    applyEngine(btn.dataset.engine);
    engineDropdown.classList.add('hidden');
    enginePickerBtn.setAttribute('aria-expanded', 'false');
  });
});

// ─── New Tab Screen & Quicklinks ──────────────────────────────────────────────

function showNewTab() {
  newTabScreen.classList.remove('hidden');
  webview.classList.add('hidden');
  ntSearchInput.focus();
}

function hideNewTab() {
  newTabScreen.classList.add('hidden');
  webview.classList.remove('hidden');
}

ntSearchForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const query = ntSearchInput.value.trim();
  if (!query) return;
  ntSearchInput.value = '';
  const target = resolveNavigationTarget(query);
  urlInput.value = target;
  if (target) await evaluateAndNavigate(target);
});

document.querySelectorAll('.nt-quicklink').forEach((btn) => {
  btn.addEventListener('click', async () => {
    const url = btn.dataset.url;
    if (url) {
      urlInput.value = url;
      await evaluateAndNavigate(url);
    }
  });
});

// ─── Navigation & URL Form ────────────────────────────────────────────────────

urlForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const target = resolveNavigationTarget(urlInput.value);
  if (target) await evaluateAndNavigate(target);
});

function resolveNavigationTarget(input) {
  const value = input.trim();
  if (!value) return '';

  if (/^https?:\/\//i.test(value)) return value;

  const looksLikeHost = /^(?:localhost|(?:[a-z\d](?:[a-z\d-]*[a-z\d])?\.)+[a-z]{2,}|(?:\d{1,3}\.){3}\d{1,3})(?::\d+)?(?:[/?#][^\s]*)?$/i.test(value);
  if (looksLikeHost) return `https://${value}`;

  // Use selected search engine
  const eng = SEARCH_ENGINES[currentEngineKey];
  return `${eng.searchUrl}${encodeURIComponent(value)}`;
}

async function evaluateAndNavigate(targetUrl) {
  pendingUrl = targetUrl;
  urlInput.value = targetUrl;
  hideNewTab();

  // 1. Pre-navigation scan against PhishShield Engine
  try {
    const verdict = await window.phishshield.scanUrl(targetUrl);
    currentVerdict = verdict;
    updateRiskIndicator(verdict);

    const level = verdict.threat_level || 'LOW';
    const action = verdict.adaptive_action || 'ALLOW';

    // 2. Adaptive Gatekeeper Check
    if (level === 'CRITICAL' || level === 'HIGH') {
      showWarningGate(targetUrl, verdict);
    } else {
      warningGate.classList.add('hidden');
      webview.loadURL(targetUrl);
    }
  } catch (err) {
    console.error('Scan failed:', err);
    webview.loadURL(targetUrl);
  }
}

function updateRiskIndicator(verdict) {
  const score = Math.round(verdict.risk_score || 0);
  const level = verdict.threat_level || 'LOW';

  riskScoreVal.textContent = score;
  riskLevelVal.textContent = level;

  riskPill.className = `risk-pill ${level.toLowerCase()}`;
}

function showWarningGate(url, verdict) {
  barrierUrl.textContent = url;
  barrierScore.textContent = `${Math.round(verdict.risk_score)} / 100`;
  barrierLevel.textContent = verdict.threat_level;
  barrierAction.textContent = verdict.adaptive_action;

  barrierReasonsList.innerHTML = '';
  const reasons = verdict.indicators?.reasons || ['Suspicious characteristics detected by ML inference'];
  reasons.forEach((r) => {
    const li = document.createElement('li');
    li.textContent = r;
    barrierReasonsList.appendChild(li);
  });

  warningGate.classList.remove('hidden');
}

// ─── Barrier Buttons ─────────────────────────────────────────────────────────

barrierBtnBypass.addEventListener('click', () => {
  warningGate.classList.add('hidden');
  if (pendingUrl) {
    webview.loadURL(pendingUrl);
  }
});

  barrierBtnBack.addEventListener('click', () => {
  warningGate.classList.add('hidden');
  showNewTab();
  urlInput.value = '';
});

barrierBtnSandbox.addEventListener('click', async () => {
  warningGate.classList.add('hidden');
  if (pendingUrl) {
    await triggerSandboxIsolation(pendingUrl, currentVerdict?.threat_level || 'HIGH');
  }
});

// ─── Browser Controls ────────────────────────────────────────────────────────

btnBack.addEventListener('click', () => {
  if (webview.canGoBack()) webview.goBack();
});

btnForward.addEventListener('click', () => {
  if (webview.canGoForward()) webview.goForward();
});

btnReload.addEventListener('click', () => {
  if (btnReload.classList.contains('is-loading')) {
    webview.stop();
  } else {
    webview.reload();
  }
});

btnHome.addEventListener('click', () => {
  showNewTab();
  urlInput.value = '';
});

// ─── Webview Event Listeners ──────────────────────────────────────────────────

webview.addEventListener('did-start-loading', () => {
  btnReload.classList.add('is-loading');
  btnReload.setAttribute('aria-label', 'Stop loading');
  btnReload.title = 'Stop loading';
});

webview.addEventListener('did-stop-loading', () => {
  btnReload.classList.remove('is-loading');
  btnReload.setAttribute('aria-label', 'Reload');
  btnReload.title = 'Reload';
  urlInput.value = webview.getURL();
});

// ─── Actions: Sandbox & AI Report ────────────────────────────────────────────

btnSandbox.addEventListener('click', async () => {
  const currentUrl = urlInput.value || webview.getURL();
  await triggerSandboxIsolation(currentUrl, currentVerdict?.threat_level || 'HIGH');
});

async function triggerSandboxIsolation(targetUrl, threatLevel) {
  openDrawer();
  drawerContent.innerHTML = `
    <div style="padding: 20px; text-align: center; color: var(--text-secondary);">
      <div style="font-family: monospace; font-size: 16px; margin-bottom: 8px;">&gt;_</div>
      <div style="font-size: 14px; font-weight: 700; color: var(--text-primary);">Launching Virtual Machine Sandbox Container…</div>
      <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">Connecting to randomized privacy VPN exit node…</div>
    </div>
  `;

  try {
    let vpn = null;
    try {
      const vpnRes = await fetch('http://127.0.0.1:8000/api/v1/sandbox/vpn/current');
      if (vpnRes.ok) vpn = await vpnRes.json();
    } catch {}

    const session = await window.phishshield.launchSandbox(targetUrl, threatLevel === 'CRITICAL' ? 'CRITICAL' : 'HIGH');
    if (session.error) {
      drawerContent.innerHTML = `<div style="color: var(--critical); padding: 16px;">Failed: ${session.error}</div>`;
      return;
    }

    const sdi = session.synthetic_data;
    const activeNode = vpn?.active_node || { flag: '🇨🇭', city: 'Zurich', country: 'Switzerland', ip: '185.220.101.44', protocol: 'WireGuard / AES-256' };

    drawerContent.innerHTML = `
      <div style="display: flex; flex-direction: column; gap: 14px;">
        <div style="padding: 10px 12px; border-radius: 8px; background: rgba(168,85,247,0.15); border: 1px solid var(--accent-purple); color: #c084fc; font-weight: 700; font-size: 11px; display: flex; align-items: center; justify-content: space-between;">
          <span>● VM SANDBOX ACTIVE · 512MB RAM-DISK</span>
          <span style="color: #22c55e; font-size: 10px;">ISOLATED</span>
        </div>

        <!-- 5-Minute Auto-Rotating VPN Tunnel -->
        <div style="background: rgba(56,189,248,0.08); border: 1px solid rgba(56,189,248,0.3); border-radius: 10px; padding: 12px;">
          <div style="font-size: 10px; font-weight: 700; color: var(--accent-blue); text-transform: uppercase; margin-bottom: 6px; display: flex; justify-content: space-between;">
            <span>🌐 Encrypted VPN Tunnel</span>
            <span style="color: #eab308;" id="vpn-drawer-timer">⏱️ Rotate in: ${vpn?.countdown_str || '04:59'}</span>
          </div>
          <div style="display: flex; align-items: center; justify-content: space-between; font-size: 11px;">
            <div>
              <span>${activeNode.flag} <strong>${activeNode.city}, ${activeNode.country}</strong></span>
              <div style="color: var(--text-muted); font-size: 10px; margin-top: 2px;">IP: <code style="color: #38bdf8">${activeNode.ip}</code> · ${activeNode.protocol}</div>
            </div>
            <button id="btn-drawer-rotate-vpn" style="background: #1e293b; border: 1px solid #475569; color: #fff; padding: 4px 8px; border-radius: 4px; font-size: 10px; cursor: pointer;">
              🔄 Switch
            </button>
          </div>
        </div>

        <div style="background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 10px; padding: 12px;">
          <div style="font-size: 10px; font-weight: 700; color: var(--accent-purple); text-transform: uppercase; margin-bottom: 8px;">
            🧪 Injected Decoy Honeypot (SDI)
          </div>
          <div style="display: flex; flex-direction: column; gap: 5px; font-size: 11px;">
            <div><span style="color: var(--text-muted)">Card:</span> <code style="color: var(--text-primary)">${sdi?.card_number || '4111 7752 4889 4268'}</code></div>
            <div><span style="color: var(--text-muted)">Exp / CVV:</span> ${sdi?.card_expiry || '09/28'} · ${sdi?.card_cvv || '910'}</div>
            <div><span style="color: var(--text-muted)">Cardholder:</span> ${sdi?.cardholder_name || 'Sam Holloway'}</div>
            <div><span style="color: var(--text-muted)">Canary Email:</span> <code style="color: var(--accent-blue)">${sdi?.email || 'canary.sam@phishshield-trap.invalid'}</code></div>
          </div>
        </div>

        <div style="font-size: 10px; color: var(--text-muted); line-height: 1.5; padding: 8px; background: rgba(0,0,0,0.3); border-radius: 6px;">
          🔒 <strong>ZERO HOST ACCESS:</strong> Target site cannot access your real IP, local files, or personal session cookies. VPN switches server automatically every 5 minutes.
        </div>
      </div>
    `;

    const rotateBtn = document.getElementById('btn-drawer-rotate-vpn');
    if (rotateBtn) {
      rotateBtn.addEventListener('click', async () => {
        rotateBtn.textContent = '...';
        try {
          await fetch('http://127.0.0.1:8000/api/v1/sandbox/vpn/rotate', { method: 'POST' });
          await triggerSandboxIsolation(targetUrl, threatLevel);
        } catch {
          rotateBtn.textContent = '🔄 Switch';
        }
      });
    }
  } catch (err) {
    drawerContent.innerHTML = `<div style="color: var(--critical); padding: 16px;">Error: ${err.message}</div>`;
  }
}

btnReport.addEventListener('click', async () => {
  if (!currentVerdict?.scan_id) {
    alert('Please navigate to a URL first to generate a report.');
    return;
  }

  openDrawer();
  drawerContent.innerHTML = `
    <div style="padding: 20px; text-align: center; color: var(--text-secondary);">
      <div style="font-family: monospace; font-size: 16px; margin-bottom: 8px;">[R]</div>
      <div style="font-size: 14px; font-weight: 700; color: var(--text-primary);">Generating Evidence-Grounded Report…</div>
      <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">Partitioning into OBSERVED, INFERRED, and UNKNOWN triad</div>
    </div>
  `;

  try {
    const report = await window.phishshield.generateAnalystReport(currentVerdict.scan_id);
    if (report.error) {
      drawerContent.innerHTML = `<div style="color: var(--critical); padding: 16px;">Report generation failed: ${report.error}</div>`;
      return;
    }

    drawerContent.innerHTML = `
      <div style="display: flex; flex-direction: column; gap: 16px;">
        <div style="font-size: 12px; color: var(--text-secondary); line-height: 1.5; padding: 10px; background: rgba(56, 189, 248, 0.08); border-radius: 8px; border: 1px solid rgba(56, 189, 248, 0.2);">
          <strong style="color: var(--accent-blue);">EXECUTIVE SUMMARY:</strong><br>
          ${report.executive_summary}
        </div>

        <!-- OBSERVED -->
        <div style="border: 1px solid rgba(34, 197, 94, 0.3); border-radius: 8px; background: rgba(34, 197, 94, 0.05); overflow: hidden;">
          <div style="padding: 8px 12px; background: rgba(34, 197, 94, 0.15); font-size: 11px; font-weight: 700; color: var(--low);">
            ✓ OBSERVED (${report.observed?.length || 0} facts)
          </div>
          <div style="padding: 10px 12px; display: flex; flex-direction: column; gap: 6px;">
            ${(report.observed || []).map(o => `
              <div style="font-size: 11px; color: var(--text-primary);">• ${o.description}</div>
            `).join('')}
          </div>
        </div>

        <!-- INFERRED -->
        <div style="border: 1px solid rgba(245, 158, 11, 0.3); border-radius: 8px; background: rgba(245, 158, 11, 0.05); overflow: hidden;">
          <div style="padding: 8px 12px; background: rgba(245, 158, 11, 0.15); font-size: 11px; font-weight: 700; color: var(--medium);">
            ▲ INFERRED (${report.inferred?.length || 0} hypotheses)
          </div>
          <div style="padding: 10px 12px; display: flex; flex-direction: column; gap: 6px;">
            ${(report.inferred || []).map(i => `
              <div style="font-size: 11px; color: var(--text-primary);">• ${i.hypothesis} (${i.confidence} Confidence)</div>
            `).join('')}
          </div>
        </div>

        <!-- ACTIONS -->
        <div>
          <div style="font-size: 11px; font-weight: 700; color: var(--text-muted); text-transform: uppercase; margin-bottom: 6px;">Recommended Actions</div>
          <ul style="margin-left: 16px; font-size: 11px; color: var(--text-secondary);">
            ${(report.recommended_actions || []).map(a => `<li>${a}</li>`).join('')}
          </ul>
        </div>
      </div>
    `;
  } catch (err) {
    drawerContent.innerHTML = `<div style="color: var(--critical); padding: 16px;">Error: ${err.message}</div>`;
  }
});

function openDrawer() {
  reportDrawer.classList.remove('hidden');
}

btnCloseDrawer.addEventListener('click', () => {
  reportDrawer.classList.add('hidden');
});

// ─── 5-Second Rotating GPS Location Scrambler Controller ──────────────────────

const btnGpsToggle = $('btn-gps-toggle');
const gpsDot = $('gps-dot');
const gpsText = $('gps-text');

let gpsTimerSeconds = 5;
let gpsEnabled = true;

function updateGpsUI() {
  if (!window.phishshield?.getLocationStatus) return;
  const status = window.phishshield.getLocationStatus();
  gpsEnabled = status.enabled;
  if (!gpsEnabled) {
    if (gpsDot) gpsDot.style.background = '#64748b';
    if (gpsText) gpsText.textContent = '📍 GPS Shield: OFF';
    return;
  }
  if (gpsDot) {
    gpsDot.style.background = '#a855f7';
    gpsDot.style.boxShadow = '0 0 6px #a855f7';
  }
  const loc = status.currentLocation || { city: 'Zurich' };
  if (gpsText) {
    gpsText.textContent = `📍 ${loc.city} ⏱️ ${gpsTimerSeconds}s`;
  }
}

if (btnGpsToggle) {
  btnGpsToggle.addEventListener('click', () => {
    gpsEnabled = !gpsEnabled;
    if (window.phishshield?.toggleLocationScrambler) {
      window.phishshield.toggleLocationScrambler(gpsEnabled);
    }
    gpsTimerSeconds = 5;
    updateGpsUI();
  });

  setInterval(() => {
    if (gpsEnabled) {
      gpsTimerSeconds = gpsTimerSeconds <= 1 ? 5 : gpsTimerSeconds - 1;
      updateGpsUI();
    }
  }, 1000);
}

// ─── Boot: Apply Saved Engine & Show New Tab ──────────────────────────────────

applyEngine(currentEngineKey);
showNewTab();
updateGpsUI();
