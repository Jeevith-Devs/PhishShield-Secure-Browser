/**
 * PhishShield Extension Popup — UI Controller
 * Fetches cached verdict from background service worker and renders the threat UI.
 */

const $ = (id) => document.getElementById(id);

const LEVEL_CLASS = { LOW: "LOW", MEDIUM: "MEDIUM", HIGH: "HIGH", CRITICAL: "CRITICAL" };

function show(id) {
  ["loading-state", "verdict-state", "error-state"].forEach((s) => {
    $(s).style.display = s === id ? "block" : "none";
  });
}

function renderVerdict(verdict) {
  const level = verdict.threat_level || "LOW";
  const score = Math.round(verdict.risk_score || 0);

  // URL
  $("url-display").textContent = truncate(verdict.url, 60);

  // Risk card classes
  const card = $("risk-card");
  card.className = `risk-card ${level}`;

  // Score
  const scoreEl = $("score-val");
  scoreEl.textContent = score;
  scoreEl.className = `score-display score-${level}`;

  // Score bar
  $("score-fill").style.width = `${score}%`;
  $("score-fill").className = `score-bar-fill fill-${level}`;

  // Badge
  const badge = $("threat-badge");
  badge.textContent = level;
  badge.className = `threat-badge badge-${level}`;

  // Action pill
  $("action-pill").textContent = verdict.adaptive_action || "ALLOW";
  $("confidence-text").textContent = verdict.confidence
    ? `${Math.round(verdict.confidence * 100)}% confidence`
    : "";

  // Reasons
  const reasons = verdict.indicators?.reasons || [];
  const reasonsList = $("reasons-list");
  reasonsList.innerHTML = "";
  reasons.forEach((r) => {
    const div = document.createElement("div");
    div.className = "reason-item";
    div.innerHTML = `<div class="reason-dot"></div><span>${r}</span>`;
    reasonsList.appendChild(div);
  });

  // Action buttons
  const btns = $("action-btns");
  btns.innerHTML = "";

  if (level === "LOW") {
    btns.appendChild(makeBtn("✓ Site Appears Safe", "btn-secondary", null));
  }

  if (level === "MEDIUM") {
    btns.appendChild(makeBtn("⚠ View Risk Details", "btn-secondary", () => {
      chrome.tabs.create({ url: `http://localhost:3000/scan/${verdict.scan_id}` });
    }));
    btns.appendChild(makeBtn("Proceed Anyway", "btn-secondary", () => window.close()));
  }

  if (level === "HIGH") {
    btns.appendChild(makeBtn("🔬 Investigate in Sandbox", "btn-primary", () => {
      chrome.runtime.sendMessage(
        { type: "LAUNCH_SANDBOX", url: verdict.url, threat_level: "HIGH" },
        (resp) => {
          if (resp?.session) {
            chrome.tabs.create({ url: `http://localhost:3000/sandbox/${resp.session.session_id}` });
          }
        }
      );
    }));
    btns.appendChild(makeBtn("View Full Report", "btn-secondary", () => {
      chrome.tabs.create({ url: `http://localhost:3000/scan/${verdict.scan_id}` });
    }));
  }

  if (level === "CRITICAL") {
    btns.appendChild(makeBtn("🛡 Route to Isolated Sandbox", "btn-danger", () => {
      chrome.runtime.sendMessage(
        { type: "LAUNCH_SANDBOX", url: verdict.url, threat_level: "CRITICAL" },
        (resp) => {
          if (resp?.session) {
            chrome.tabs.create({ url: `http://localhost:3000/sandbox/${resp.session.session_id}` });
          }
        }
      );
    }));
    btns.appendChild(makeBtn("View SOC Dashboard", "btn-secondary", () => {
      chrome.tabs.create({ url: "http://localhost:3000" });
    }));
  }

  show("verdict-state");
}

function makeBtn(label, cls, onClick) {
  const btn = document.createElement("button");
  btn.className = `btn ${cls}`;
  btn.textContent = label;
  if (onClick) btn.addEventListener("click", onClick);
  else btn.disabled = true;
  return btn;
}

function truncate(str, n) {
  return str && str.length > n ? str.slice(0, n) + "…" : str;
}

// ─── Init ──────────────────────────────────────────────────────────────────

async function init() {
  show("loading-state");

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) { showError("No active tab found."); return; }

  chrome.runtime.sendMessage({ type: "GET_VERDICT", tabId: tab.id }, (resp) => {
    if (chrome.runtime.lastError || !resp) {
      showError("Could not reach background worker.");
      return;
    }
    if (resp.verdict) {
      renderVerdict(resp.verdict);
    } else {
      // No cached verdict — request a fresh scan
      chrome.runtime.sendMessage({ type: "RESCAN_TAB", tabId: tab.id }, (r) => {
        if (r?.verdict) {
          renderVerdict(r.verdict);
        } else {
          showError(r?.error || "Scan failed — is the PhishShield API running?");
        }
      });
    }
  });
}

function showError(msg) {
  $("error-msg").textContent = msg;
  show("error-state");
}

$("rescan-btn").addEventListener("click", () => { show("loading-state"); init(); });
$("retry-btn").addEventListener("click", init);

$("open-dashboard").addEventListener("click", () => {
  chrome.tabs.create({ url: "http://localhost:3000" });
});

$("view-history").addEventListener("click", () => {
  chrome.tabs.create({ url: "http://localhost:3000/history" });
});

init();
