// PhishShield Dedicated Secure Browser — UI Controller

const $ = (id) => document.getElementById(id);

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

let currentVerdict = null;
let pendingUrl = '';

// ─── Navigation & URL Form ───────────────────────────────────────────────────

urlForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  let target = urlInput.value.trim();
  if (!target) return;

  if (!target.startsWith('http://') && !target.startsWith('https://')) {
    target = 'https://' + target;
  }

  await evaluateAndNavigate(target);
});

async function evaluateAndNavigate(targetUrl) {
  pendingUrl = targetUrl;
  urlInput.value = targetUrl;

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
  webview.loadURL('https://www.google.com');
  urlInput.value = 'https://www.google.com';
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
  webview.reload();
});

btnHome.addEventListener('click', () => {
  evaluateAndNavigate('https://www.google.com');
});

// ─── Webview Event Listeners ─────────────────────────────────────────────────

webview.addEventListener('did-start-loading', () => {
  btnReload.textContent = '✕';
});

webview.addEventListener('did-stop-loading', () => {
  btnReload.textContent = '↻';
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
      <div style="font-size: 24px; margin-bottom: 8px;">🚀</div>
      <div style="font-size: 14px; font-weight: 700; color: var(--text-primary);">Launching Ephemeral Sandbox Session…</div>
      <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">Injecting ISO/IEC 7812 Luhn test card & honeypot identity</div>
    </div>
  `;

  try {
    const session = await window.phishshield.launchSandbox(targetUrl, threatLevel);
    if (session.error) {
      drawerContent.innerHTML = `<div style="color: var(--critical); padding: 16px;">Failed: ${session.error}</div>`;
      return;
    }

    const sdi = session.synthetic_data;
    drawerContent.innerHTML = `
      <div style="display: flex; flex-direction: column; gap: 16px;">
        <div style="padding: 12px; border-radius: 8px; background: rgba(34,197,94,0.1); border: 1px solid var(--low); color: var(--low); font-weight: 700; font-size: 12px;">
          ✓ Ephemeral Sandbox Active · ID: ${session.session_id.slice(0, 8)}…
        </div>

        <div style="background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 10px; padding: 14px;">
          <div style="font-size: 11px; font-weight: 700; color: var(--accent-purple); text-transform: uppercase; margin-bottom: 8px;">
            Injected Honeypot Profile (SDI)
          </div>
          <div style="display: flex; flex-direction: column; gap: 6px; font-size: 11px;">
            <div><span style="color: var(--text-muted)">Card:</span> <code style="color: var(--text-primary)">${sdi?.card_number || 'N/A'}</code></div>
            <div><span style="color: var(--text-muted)">Exp / CVV:</span> ${sdi?.card_expiry || ''} · ${sdi?.card_cvv || ''}</div>
            <div><span style="color: var(--text-muted)">Cardholder:</span> ${sdi?.cardholder_name || ''}</div>
            <div><span style="color: var(--text-muted)">Canary Email:</span> <code style="color: var(--accent-blue)">${sdi?.email || ''}</code></div>
          </div>
        </div>

        <div style="font-size: 11px; color: var(--text-muted); line-height: 1.5;">
          🛡️ The site is now isolated inside the headless container. Real user cookies and network egress are completely blocked.
        </div>
      </div>
    `;
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
      <div style="font-size: 24px; margin-bottom: 8px;">🤖</div>
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

// Initial scan on boot
evaluateAndNavigate('https://www.google.com');
