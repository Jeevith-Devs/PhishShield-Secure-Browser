/**
 * PhishShield Browser Extension — Service Worker (Manifest V3)
 * Intercepts web navigation, calls the PhishShield API, and enforces
 * the adaptive action (ALLOW / WARN / CONTROLLED / ISOLATE).
 */

const API_BASE = "http://localhost:8000/api/v1";
const ICON_STATES = {
  LOW:      { path: "../icons/icon48_low.png",      text: "LOW",  color: "#22c55e" },
  MEDIUM:   { path: "../icons/icon48_medium.png",   text: "MED",  color: "#f59e0b" },
  HIGH:     { path: "../icons/icon48_high.png",     text: "HIGH", color: "#f97316" },
  CRITICAL: { path: "../icons/icon48_critical.png", text: "CRIT", color: "#ef4444" },
};

// In-memory verdict cache (tab → verdict)
const verdictCache = new Map();

// ─── Navigation Listener ───────────────────────────────────────────────────

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;                   // top-level only
  const { tabId, url } = details;
  if (!url || url.startsWith("chrome") || url.startsWith("about") || url.startsWith("extension")) return;

  try {
    const verdict = await scanUrl(url);
    verdictCache.set(tabId, verdict);
    updateBadge(tabId, verdict.threat_level);
    await handleAdaptiveAction(tabId, url, verdict);
  } catch (err) {
    console.warn("[PhishShield] Scan failed:", err.message);
  }
});

// ─── Tab Activation ────────────────────────────────────────────────────────

chrome.tabs.onActivated.addListener(({ tabId }) => {
  const cached = verdictCache.get(tabId);
  if (cached) {
    updateBadge(tabId, cached.threat_level);
  } else {
    chrome.action.setBadgeText({ text: "", tabId });
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  verdictCache.delete(tabId);
});

// ─── Message Bus (popup ↔ background) ─────────────────────────────────────

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "GET_VERDICT") {
    const verdict = verdictCache.get(msg.tabId);
    sendResponse({ verdict: verdict || null });
  }
  if (msg.type === "RESCAN_TAB") {
    chrome.tabs.get(msg.tabId, async (tab) => {
      if (tab && tab.url) {
        try {
          const verdict = await scanUrl(tab.url);
          verdictCache.set(msg.tabId, verdict);
          updateBadge(msg.tabId, verdict.threat_level);
          sendResponse({ verdict });
        } catch (e) {
          sendResponse({ error: e.message });
        }
      }
    });
    return true;                                       // async response
  }
  if (msg.type === "LAUNCH_SANDBOX") {
    launchSandboxSession(msg.url, msg.threat_level).then((session) => {
      sendResponse({ session });
    });
    return true;
  }
});

// ─── API Calls ─────────────────────────────────────────────────────────────

async function scanUrl(url) {
  const res = await fetch(`${API_BASE}/scan/url`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, client_type: "extension" }),
  });
  if (!res.ok) throw new Error(`API error ${res.status}`);
  return res.json();
}

async function launchSandboxSession(url, threat_level) {
  const res = await fetch(`${API_BASE}/sandbox/launch`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, threat_level, inject_synthetic_data: true }),
  });
  if (!res.ok) throw new Error(`Sandbox API error ${res.status}`);
  return res.json();
}

// ─── Adaptive Action Handler ───────────────────────────────────────────────

async function handleAdaptiveAction(tabId, url, verdict) {
  switch (verdict.adaptive_action) {
    case "ALLOW":
      // Passive telemetry only — navigation continues
      break;

    case "WARN":
      // Redirect to interstitial warning gate
      await redirectToInterstitial(tabId, url, verdict);
      break;

    case "CONTROLLED":
    case "ISOLATE":
      // Block navigation and redirect to interstitial with sandbox option
      await redirectToInterstitial(tabId, url, verdict);
      break;
  }
}

async function redirectToInterstitial(tabId, targetUrl, verdict) {
  const interstitialBase = chrome.runtime.getURL("dist/interstitial.html");
  const params = new URLSearchParams({
    url: targetUrl,
    risk_score: verdict.risk_score,
    threat_level: verdict.threat_level,
    adaptive_action: verdict.adaptive_action,
    scan_id: verdict.scan_id,
  });
  chrome.tabs.update(tabId, { url: `${interstitialBase}?${params.toString()}` });
}

// ─── Badge Helpers ─────────────────────────────────────────────────────────

function updateBadge(tabId, threatLevel) {
  const state = ICON_STATES[threatLevel] || ICON_STATES.LOW;
  chrome.action.setBadgeText({ text: state.text, tabId });
  chrome.action.setBadgeBackgroundColor({ color: state.color, tabId });
}
