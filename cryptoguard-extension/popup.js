// ================================================================
// CryptoGuard — Popup Script
// ================================================================

let currentTabId = null;

// ── INIT ─────────────────────────────────────────────────────────

async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;

  currentTabId = tab.id;

  // Get tab status from storage
  const result   = await chrome.storage.local.get(["tabStatuses", "alerts", "totalDetections"]);
  const statuses = result.tabStatuses || {};
  const tabStatus = statuses[tab.id] || { status: "safe", confidence: 0, method: null };

  updateStatusCard(tabStatus.status, tabStatus.confidence, tab.url, tabStatus.method);
  renderAlerts(result.alerts || []);
  updateTotalBadge(result.totalDetections || 0);

  document.getElementById("scan-status").textContent =
    `Tab #${tab.id} · ${new Date().toLocaleTimeString()}`;
}

// ── STATUS CARD ───────────────────────────────────────────────────

function updateStatusCard(status, confidence, url, method) {
  const card    = document.getElementById("status-card");
  const label   = document.getElementById("status-label");
  const urlEl   = document.getElementById("status-url");
  const confEl  = document.getElementById("confidence");
  const methRow = document.getElementById("method-row");
  const methTxt = document.getElementById("method-text");
  const btnBlock   = document.getElementById("btn-block");
  const btnUnblock = document.getElementById("btn-unblock");

  // Set card class
  card.className = `status-card ${status}`;

  // Labels
  const labels = {
    safe    : "SAFE",
    warning : "WARNING",
    threat  : "THREAT DETECTED",
    blocked : "BLOCKED",
  };
  label.textContent = labels[status] || "SAFE";

  // URL
  try {
    urlEl.textContent = new URL(url).hostname;
  } catch {
    urlEl.textContent = url?.substring(0, 40) || "—";
  }

  // Confidence
  confEl.textContent = `${Math.round(confidence)}%`;

  // Detection method
  if (method && status !== "safe") {
    methRow.classList.add("visible");
    methTxt.textContent = method;
  } else {
    methRow.classList.remove("visible");
  }

  // Buttons
  if (status === "threat" || status === "warning") {
    btnBlock.classList.add("visible");
    btnUnblock.classList.remove("visible");
  } else if (status === "blocked") {
    btnUnblock.classList.add("visible");
    btnBlock.classList.remove("visible");
  } else {
    btnBlock.classList.remove("visible");
    btnUnblock.classList.remove("visible");
  }
}

// ── BLOCK / UNBLOCK ───────────────────────────────────────────────

async function blockCurrentTab() {
  if (!currentTabId) return;
  const btn = document.getElementById("btn-block");
  btn.textContent = "⏳ Blocking...";
  btn.disabled    = true;

  await chrome.runtime.sendMessage({ action: "blockTab", tabId: currentTabId });

  setTimeout(() => init(), 500);
}

async function unblockCurrentTab() {
  if (!currentTabId) return;
  await chrome.runtime.sendMessage({ action: "unblockTab", tabId: currentTabId });
  setTimeout(() => init(), 500);
}

window.blockCurrentTab   = blockCurrentTab;
window.unblockCurrentTab = unblockCurrentTab;

// ── ALERTS ────────────────────────────────────────────────────────

function renderAlerts(alerts) {
  const list = document.getElementById("alert-list");

  if (!alerts || alerts.length === 0) {
    list.innerHTML = '<div class="no-alerts">No threats detected yet</div>';
    return;
  }

  list.innerHTML = alerts.slice(0, 10).map(a => {
    let host = a.url;
    try { host = new URL(a.url).hostname; } catch {}
    return `
      <div class="alert-item">
        <div class="alert-header">
          <span class="alert-host">${host}</span>
          <span class="alert-time">${a.time}</span>
        </div>
        <div class="alert-method">${a.method || "behavioral"} · ${a.confidence}% confidence</div>
      </div>
    `;
  }).join("");
}

async function clearAlerts() {
  await chrome.runtime.sendMessage({ action: "clearAlerts" });
  document.getElementById("alert-list").innerHTML =
    '<div class="no-alerts">No threats detected yet</div>';
  updateTotalBadge(0);
}

window.clearAlerts = clearAlerts;

// ── TOTAL BADGE ───────────────────────────────────────────────────

function updateTotalBadge(total) {
  const el = document.getElementById("total-badge");
  el.textContent = `${total} detected`;
  el.style.display = total > 0 ? "inline-block" : "none";
}

// ── HISTORY PAGE (opens in new tab) ──────────────────────────────

function openAlertHistory() {
  chrome.tabs.create({ url: chrome.runtime.getURL("history.html") });
}
window.openAlertHistory = openAlertHistory;

// ── RUN ──────────────────────────────────────────────────────────
init();
