// ================================================================
// CryptoGuard — Background Service Worker
// Core detection engine: monitors tabs, manages alerts, stores state
// ================================================================

// ── CONFIG ───────────────────────────────────────────────────────
const CONFIG = {
  scanInterval     : 2000,   // ms between scans
  cpuThreshold     : 70,     // % CPU per tab to flag
  sustainedSeconds : 10,     // seconds above threshold before alert
  maxAlerts        : 50,     // max alerts to store
};

// ── KNOWN MINING SIGNATURES ──────────────────────────────────────
const MINING_DOMAINS = [
  "coinhive.com", "coin-hive.com", "minero.cc", "cryptonight",
  "deepminer", "jsecoin.com", "crypto-loot.com", "ppoi.org",
  "webmine.pro", "coinerra.com", "minegate.pw", "2giga.link",
  "ad-miner.com", "miner.pr0gramm.com", "cryptobara.com",
  "authedmine.com", "monero.com", "coinimp.com", "coinblind.com"
];

const MINING_SCRIPT_SIGNATURES = [
  "CoinHive", "coinhive", "CryptoNight", "cryptonight",
  "Miner.Anonymous", "miner.start(", "miner.stop(",
  "NiceHash", "deepminer", "JSEcoin", "CryptoLoot",
  "WebMinePool", "MineroCC", "stratum+tcp", "mining.submit",
  "hashrate", "getJob", "submitJob", "MoneroMiner",
];

// ── STATE ─────────────────────────────────────────────────────────
// tabState[tabId] = { cpuHistory: [], flaggedSince: null, blocked: false, status: "safe" }
const tabState   = {};
const blockedTabs = new Set();

// ── HELPERS ───────────────────────────────────────────────────────

function getOrCreateTabState(tabId) {
  if (!tabState[tabId]) {
    tabState[tabId] = {
      cpuHistory   : [],
      flaggedSince : null,
      blocked      : false,
      status       : "safe",
      url          : "",
      detectionMethod: null,
    };
  }
  return tabState[tabId];
}

function cleanupTab(tabId) {
  delete tabState[tabId];
  blockedTabs.delete(tabId);
}

async function saveAlert(tabId, url, method, confidence) {
  const result = await chrome.storage.local.get(["alerts", "totalDetections"]);
  const alerts = result.alerts || [];
  const total  = (result.totalDetections || 0) + 1;

  alerts.unshift({
    id         : Date.now(),
    tabId,
    url        : url.substring(0, 100),
    method,
    confidence : Math.round(confidence),
    time       : new Date().toLocaleTimeString(),
    date       : new Date().toLocaleDateString(),
    blocked    : blockedTabs.has(tabId),
  });

  await chrome.storage.local.set({
    alerts          : alerts.slice(0, CONFIG.maxAlerts),
    totalDetections : total,
  });
}

async function updateTabStatus(tabId, status, method, confidence) {
  const state = getOrCreateTabState(tabId);
  state.status          = status;
  state.detectionMethod = method;

  // Update badge
  const badgeConfig = {
    threat  : { text: "!", color: "#f85149" },
    warning : { text: "?", color: "#d29922" },
    blocked : { text: "✕", color: "#8b949e" },
    safe    : { text: "",  color: "#3fb950" },
  };

  const cfg = badgeConfig[status] || badgeConfig.safe;
  try {
    await chrome.action.setBadgeText({ tabId, text: cfg.text });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: cfg.color });
  } catch(e) { /* tab may have closed */ }

  // Store per-tab status for popup
  const stored = await chrome.storage.local.get("tabStatuses");
  const statuses = stored.tabStatuses || {};
  statuses[tabId] = { status, method, confidence: Math.round(confidence), url: state.url };
  await chrome.storage.local.set({ tabStatuses: statuses });
}

function sendNotification(tabId, url, method) {
  chrome.notifications.create(`threat_${tabId}_${Date.now()}`, {
    type    : "basic",
    iconUrl : "icons/icon48.png",
    title   : "🚨 CryptoGuard — Miner Detected!",
    message : `Mining activity detected on ${new URL(url).hostname}\nMethod: ${method}`,
    buttons : [
      { title: "Block Now" },
      { title: "Dismiss" }
    ],
    requireInteraction: true,
  });
}

// ── BLOCK A TAB ───────────────────────────────────────────────────

async function blockTab(tabId) {
  blockedTabs.add(tabId);
  const state = getOrCreateTabState(tabId);
  state.blocked = true;

  // Inject blocking script into the tab
  try {
    await chrome.scripting.executeScript({
      target : { tabId },
      func   : () => {
        // Override WebAssembly and Worker (used by miners)
        window.WebAssembly = undefined;
        const origWorker   = window.Worker;
        window.Worker      = function(url) {
          const urlStr = url.toString().toLowerCase();
          if (urlStr.includes('miner') || urlStr.includes('crypto') ||
              urlStr.includes('hash')  || urlStr.includes('coin')) {
            console.warn('[CryptoGuard] Blocked Worker:', url);
            return { terminate: () => {} };
          }
          return new origWorker(url);
        };
        console.warn('[CryptoGuard] Mining protection active on this page.');
      }
    });
  } catch(e) { /* scripting may be restricted on this page */ }

  await updateTabStatus(tabId, "blocked", "user_blocked", 100);
}

// ── CPU MONITORING ────────────────────────────────────────────────
// Uses performance.now() via injected script to estimate per-tab CPU

async function measureTabCPU(tabId) {
  try {
    const results = await chrome.scripting.executeScript({
      target : { tabId },
      func   : () => {
        // Estimate CPU by measuring how long a known computation takes
        // vs real time — a miner will slow this down significantly
        const start   = performance.now();
        let sum       = 0;
        const OPS     = 100000;
        for (let i = 0; i < OPS; i++) sum += Math.sqrt(i);
        const elapsed = performance.now() - start;

        // Also check for known miner globals
        const minerGlobals = [
          'CoinHive', 'Minero', 'CryptoNight', 'miner',
          'JSEcoin', 'DeepMiner', 'CryptoLoot'
        ];
        const foundGlobals = minerGlobals.filter(g => typeof window[g] !== 'undefined');

        // Check document scripts for mining signatures
        const scripts   = Array.from(document.querySelectorAll('script'));
        const scriptSrc = scripts.map(s => s.src + ' ' + (s.textContent || '')).join(' ').toLowerCase();
        const signatures = [
          'coinhive', 'cryptonight', 'miner.start', 'hashrate',
          'getjob', 'submitjob', 'stratum', 'monero', 'deepminer'
        ];
        const foundSigs = signatures.filter(s => scriptSrc.includes(s));

        return {
          elapsed     : elapsed,      // ms for 100k ops — high = CPU busy
          foundGlobals,
          foundSigs,
          scriptCount : scripts.length,
        };
      }
    });

    return results?.[0]?.result || null;
  } catch(e) {
    return null;
  }
}

// ── MAIN SCAN LOOP ────────────────────────────────────────────────

async function scanAllTabs() {
  let tabs;
  try {
    tabs = await chrome.tabs.query({ active: true });
  } catch(e) { return; }

  for (const tab of tabs) {
    if (!tab.id || !tab.url || tab.url.startsWith("chrome://") ||
        tab.url.startsWith("about:") || tab.url.startsWith("moz-extension://")) {
      continue;
    }

    const state  = getOrCreateTabState(tab.id);
    state.url    = tab.url;

    if (blockedTabs.has(tab.id)) continue;

    // ── Detection Method 1: Known mining domain ──
    const hostname = new URL(tab.url).hostname;
    const isDomain = MINING_DOMAINS.some(d => hostname.includes(d));
    if (isDomain) {
      await updateTabStatus(tab.id, "threat", "known_domain", 99);
      sendNotification(tab.id, tab.url, "Known mining domain");
      await saveAlert(tab.id, tab.url, "known_domain", 99);
      continue;
    }

    // ── Detection Method 2: Script signatures + CPU timing ──
    const metrics = await measureTabCPU(tab.id);
    if (!metrics) continue;

    let confidence    = 0;
    let detectedBy    = [];

    // Known miner globals found in page
    if (metrics.foundGlobals.length > 0) {
      confidence += 60;
      detectedBy.push(`globals: ${metrics.foundGlobals.join(', ')}`);
    }

    // Known signatures in script tags
    if (metrics.foundSigs.length > 0) {
      confidence += 40 * Math.min(metrics.foundSigs.length / 3, 1);
      detectedBy.push(`signatures: ${metrics.foundSigs.join(', ')}`);
    }

    // High CPU timing (100k ops taking >50ms suggests heavy CPU usage)
    if (metrics.elapsed > 50) {
      const cpuScore = Math.min((metrics.elapsed - 50) / 200 * 30, 30);
      confidence    += cpuScore;
      detectedBy.push(`cpu_timing: ${metrics.elapsed.toFixed(1)}ms`);
    }

    confidence = Math.min(confidence, 100);

    // Track sustained high confidence
    state.cpuHistory.push(confidence);
    if (state.cpuHistory.length > 10) state.cpuHistory.shift();

    const avgConf = state.cpuHistory.reduce((a, b) => a + b, 0) / state.cpuHistory.length;

    if (avgConf >= 70) {
      // Sustained high confidence — THREAT
      if (!state.flaggedSince) {
        state.flaggedSince = Date.now();
      }

      const sustainedMs = Date.now() - state.flaggedSince;

      if (sustainedMs >= CONFIG.sustainedSeconds * 1000) {
        if (state.status !== "threat") {
          const method = detectedBy.join(' | ') || "behavioral";
          await updateTabStatus(tab.id, "threat", method, avgConf);
          sendNotification(tab.id, tab.url, method);
          await saveAlert(tab.id, tab.url, method, avgConf);
        }
      } else {
        await updateTabStatus(tab.id, "warning", "sustained_cpu", avgConf);
      }

    } else if (avgConf >= 40) {
      state.flaggedSince = null;
      await updateTabStatus(tab.id, "warning", "low_signal", avgConf);
    } else {
      state.flaggedSince = null;
      if (state.status !== "safe") {
        await updateTabStatus(tab.id, "safe", null, 0);
      }
    }
  }
}

// ── NOTIFICATION BUTTON HANDLER ───────────────────────────────────

chrome.notifications.onButtonClicked.addListener((notifId, btnIdx) => {
  if (btnIdx === 0) {
    // "Block Now" button
    const match = notifId.match(/threat_(\d+)_/);
    if (match) {
      blockTab(parseInt(match[1]));
    }
  }
  chrome.notifications.clear(notifId);
});

// ── MESSAGE HANDLER (from popup) ─────────────────────────────────

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === "blockTab") {
    blockTab(msg.tabId).then(() => sendResponse({ ok: true }));
    return true;
  }
  if (msg.action === "unblockTab") {
    blockedTabs.delete(msg.tabId);
    const state = getOrCreateTabState(msg.tabId);
    state.blocked = false;
    updateTabStatus(msg.tabId, "safe", null, 0)
      .then(() => sendResponse({ ok: true }));
    return true;
  }
  if (msg.action === "getTabState") {
    sendResponse(tabState[msg.tabId] || { status: "safe" });
  }
  if (msg.action === "clearAlerts") {
    chrome.storage.local.set({ alerts: [], totalDetections: 0 })
      .then(() => sendResponse({ ok: true }));
    return true;
  }
});

// ── TAB LIFECYCLE ─────────────────────────────────────────────────

chrome.tabs.onRemoved.addListener((tabId) => cleanupTab(tabId));
chrome.tabs.onUpdated.addListener((tabId, info) => {
  if (info.status === "loading") {
    cleanupTab(tabId);
  }
});

// ── START SCAN LOOP ───────────────────────────────────────────────

setInterval(scanAllTabs, CONFIG.scanInterval);
scanAllTabs();

// Init storage defaults
chrome.storage.local.get(["alerts", "totalDetections"], (result) => {
  if (!result.alerts)          chrome.storage.local.set({ alerts: [] });
  if (!result.totalDetections) chrome.storage.local.set({ totalDetections: 0 });
});

console.log("[CryptoGuard] Background service worker started.");
