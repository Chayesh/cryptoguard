"""
Cryptojacking Detection — Real-Time Dashboard
=============================================
Author  : Your Name (FYP Project)

SETUP:
    pip3 install flask psutil scikit-learn pandas numpy

USAGE:
    python3 dashboard.py

    Then open browser: http://localhost:5000

NOTES:
    - Make sure cryptojacking_model.pkl and scaler.pkl are in the same folder
    - Run XMRig in another terminal to test detection
"""

from flask import Flask, jsonify, render_template_string
import psutil
import pickle
import numpy as np
import time
import threading
from collections import deque
from datetime import datetime
import os

# ──────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────

MODEL_PATH  = "cryptojacking_model_v2.pkl"
SCALER_PATH = "scaler_v2.pkl"
SAMPLE_INTERVAL = 2       # seconds
HISTORY_SIZE    = 60      # data points to show on chart (~2 mins)
CPU_SPIKE_THRESH = 75

KNOWN_MINER_NAMES = [
    "xmrig", "xmr-stak", "minerd", "cpuminer",
    "ethminer", "nbminer", "gminer", "cryptonight"
]

app = Flask(__name__)

# ──────────────────────────────────────────────
# GLOBAL STATE
# ──────────────────────────────────────────────

state = {
    "status"         : "SAFE",        # SAFE | WARNING | THREAT
    "confidence"     : 0.0,
    "alerts"         : [],
    "sample_count"   : 0,
    "start_time"     : time.time(),
    "last_features"  : {},
}

# Rolling history for charts
history = {
    "timestamps"        : deque(maxlen=HISTORY_SIZE),
    "cpu_total"         : deque(maxlen=HISTORY_SIZE),
    "memory_percent"    : deque(maxlen=HISTORY_SIZE),
    "net_sent"          : deque(maxlen=HISTORY_SIZE),
    "net_recv"          : deque(maxlen=HISTORY_SIZE),
    "prediction_score"  : deque(maxlen=HISTORY_SIZE),
}

# ──────────────────────────────────────────────
# LOAD MODEL
# ──────────────────────────────────────────────

def load_model():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Model not found: {MODEL_PATH}. Train it first with train_model.py")
    if not os.path.exists(SCALER_PATH):
        raise FileNotFoundError(f"Scaler not found: {SCALER_PATH}")

    with open(MODEL_PATH, "rb") as f:
        bundle = pickle.load(f)
    with open(SCALER_PATH, "rb") as f:
        scaler = pickle.load(f)

    model    = bundle["model"]
    features = bundle["features"]
    print(f"[+] Model loaded — {len(features)} features")
    return model, scaler, features

model, scaler, feature_names = load_model()

# ──────────────────────────────────────────────
# FEATURE EXTRACTION (same as collector)
# ──────────────────────────────────────────────

spike_start   = None
spike_dur     = 0.0
spike_count   = 0
prev_net      = None
prev_disk     = None

def collect_features():
    global spike_start, spike_dur, spike_count, prev_net, prev_disk

    # CPU
    cpu_total = psutil.cpu_percent(interval=1)
    cores     = psutil.cpu_percent(interval=None, percpu=True)
    n         = len(cores)
    mean      = sum(cores) / n
    std       = (sum((x - mean)**2 for x in cores) / n) ** 0.5

    # Spike tracking
    if cpu_total >= CPU_SPIKE_THRESH:
        if spike_start is None:
            spike_start = time.time()
            spike_count += 1
        spike_dur = round(time.time() - spike_start, 2)
    else:
        spike_start = None
        spike_dur   = 0.0

    # Memory
    mem  = psutil.virtual_memory()
    swap = psutil.swap_memory()

    # Network
    net = psutil.net_io_counters()
    if prev_net is None:
        sent, recv, ratio = 0, 0, 0.0
    else:
        sent  = max(0, net.bytes_sent - prev_net.bytes_sent)
        recv  = max(0, net.bytes_recv - prev_net.bytes_recv)
        ratio = round(sent / recv, 4) if recv > 0 else 0.0
    prev_net = net

    # Disk
    disk = psutil.disk_io_counters()
    if prev_disk is None or disk is None:
        disk_r, disk_w = 0, 0
    else:
        disk_r = max(0, disk.read_bytes  - prev_disk.read_bytes)
        disk_w = max(0, disk.write_bytes - prev_disk.write_bytes)
    prev_disk = disk

    # Processes
    procs          = list(psutil.process_iter(['name', 'cpu_percent', 'status']))
    proc_count     = len(procs)
    top_cpu        = 0.0
    high_cpu_count = 0
    miner_det      = 0

    for p in procs:
        try:
            pname = (p.info['name'] or '').lower()
            pcpu  = p.info['cpu_percent'] or 0.0
            if pcpu > top_cpu:
                top_cpu = pcpu
            if pcpu > CPU_SPIKE_THRESH:
                high_cpu_count += 1
            if any(m in pname for m in KNOWN_MINER_NAMES):
                miner_det = 1
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    features = {
        "cpu_total_percent"      : round(cpu_total, 2),
        "cpu_max_core_percent"   : round(max(cores), 2),
        "cpu_mean_core_percent"  : round(mean, 2),
        "cpu_core_std"           : round(std, 2),
        "cpu_core_count"         : n,
        "cpu_spike_duration_sec" : spike_dur,
        "cpu_spike_count"        : spike_count,
        "memory_percent"         : round(mem.percent, 2),
        "memory_available_mb"    : mem.available // (1024*1024),
        "swap_percent"           : round(swap.percent, 2),
        "net_bytes_sent_delta"   : sent,
        "net_bytes_recv_delta"   : recv,
        "net_sent_recv_ratio"    : ratio,
        "disk_read_delta"        : disk_r,
        "disk_write_delta"       : disk_w,
        "process_count"          : proc_count,
        "top_process_cpu_percent": round(top_cpu, 2),
        "high_cpu_process_count" : high_cpu_count,
        "miner_process_detected" : miner_det,
        "mining_pool_connection" : 0,
    }
    return features

# ──────────────────────────────────────────────
# DETECTION LOOP (background thread)
# ──────────────────────────────────────────────

def detection_loop():
    while True:
        try:
            features = collect_features()

            # Build feature vector in correct order
            vec = np.array([[features.get(f, 0) for f in feature_names]])
            vec_scaled = scaler.transform(vec)

            prob       = model.predict_proba(vec_scaled)[0][1]   # P(cryptojacking)
            prediction = model.predict(vec_scaled)[0]

            # ── FIX 3: VETO RULES ─────────────────────────────────────
            # Even if model says THREAT, apply hard veto conditions.
            # Real miners MUST send data to a pool (net outbound > threshold)
            # OR be detectable by process name.
            # If neither condition is met, downgrade THREAT → WARNING.

            NET_VETO_THRESHOLD = 1 * 1024   # 1 KB/s — tighter threshold for VM environment
            miner_detected     = features.get("miner_process_detected", 0)
            net_sent           = features.get("net_bytes_sent_delta", 0)

            veto_triggered = False
            veto_reason    = ""

            if prediction == 1 and prob >= 0.80:
                if miner_detected == 0 and net_sent < NET_VETO_THRESHOLD:
                    # High model confidence but no network activity + no process name
                    # → likely a false positive (memory-heavy legitimate app)
                    veto_triggered = True
                    veto_reason    = f"No mining network traffic (sent {net_sent//1024}KB/s) & no miner process"

            # Update status
            if prob >= 0.80 and not veto_triggered:
                new_status = "THREAT"
            elif prob >= 0.50 or veto_triggered:
                new_status = "WARNING"
            else:
                new_status = "SAFE"

            # Log veto in alerts (once)
            if veto_triggered and state.get("last_veto") != veto_reason:
                state["alerts"].insert(0, {
                    "time"    : datetime.now().strftime("%H:%M:%S"),
                    "message" : f"🛡️ Veto applied — downgraded to WARNING. Reason: {veto_reason}",
                    "type"    : "safe"
                })
                state["last_veto"] = veto_reason
            elif not veto_triggered:
                state["last_veto"] = ""
            # ── END FIX 3 ─────────────────────────────────────────────

            # Alert on status change to THREAT
            if new_status == "THREAT" and state["status"] != "THREAT":
                state["alerts"].insert(0, {
                    "time"    : datetime.now().strftime("%H:%M:%S"),
                    "message" : f"🚨 Cryptojacking detected! Confidence: {prob*100:.1f}%",
                    "type"    : "threat"
                })
            elif new_status == "SAFE" and state["status"] == "THREAT":
                state["alerts"].insert(0, {
                    "time"    : datetime.now().strftime("%H:%M:%S"),
                    "message" : "✅ Threat cleared — system returned to normal",
                    "type"    : "safe"
                })

            # Keep only last 20 alerts
            state["alerts"] = state["alerts"][:20]

            state["status"]        = new_status
            state["confidence"]    = round(prob * 100, 1)
            state["sample_count"] += 1
            state["last_features"] = features

            # Update history
            now = datetime.now().strftime("%H:%M:%S")
            history["timestamps"].append(now)
            history["cpu_total"].append(features["cpu_total_percent"])
            history["memory_percent"].append(features["memory_percent"])
            history["net_sent"].append(round(features["net_bytes_sent_delta"] / 1024, 2))
            history["net_recv"].append(round(features["net_bytes_recv_delta"] / 1024, 2))
            history["prediction_score"].append(round(prob * 100, 1))

        except Exception as e:
            print(f"[!] Detection error: {e}")

        time.sleep(SAMPLE_INTERVAL)


# Start background thread
thread = threading.Thread(target=detection_loop, daemon=True)
thread.start()

# ──────────────────────────────────────────────
# API ROUTES
# ──────────────────────────────────────────────

@app.route("/api/status")
def api_status():
    uptime = int(time.time() - state["start_time"])
    return jsonify({
        "status"      : state["status"],
        "confidence"  : state["confidence"],
        "sample_count": state["sample_count"],
        "uptime"      : uptime,
        "alerts"      : state["alerts"][:5],
        "features"    : state["last_features"],
        "history"     : {k: list(v) for k, v in history.items()},
        "veto_active" : bool(state.get("last_veto", "")),
    })

@app.route("/api/clear_alerts", methods=["POST"])
def clear_alerts():
    state["alerts"] = []
    return jsonify({"ok": True})

@app.route("/api/kill_miners", methods=["POST"])
def kill_miners():
    import os, signal
    killed = []
    errors = []
    for proc in psutil.process_iter(['name', 'pid']):
        try:
            name = (proc.info['name'] or '').lower()
            if any(m in name for m in KNOWN_MINER_NAMES):
                pid = proc.info['pid']
                os.kill(pid, signal.SIGKILL)
                killed.append(f"{proc.info['name']} (PID {pid})")
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            errors.append(str(e))
        except Exception as e:
            errors.append(str(e))

    if killed:
        state["alerts"].insert(0, {
            "time"    : datetime.now().strftime("%H:%M:%S"),
            "message" : f"🔴 Killed: {', '.join(killed)}",
            "type"    : "threat"
        })
        state["status"] = "SAFE"
        msg = f"Killed {len(killed)} process(es): {', '.join(killed)}"
    else:
        msg = "No miner processes found to kill"

    return jsonify({"ok": True, "killed": killed, "message": msg, "errors": errors})

# ──────────────────────────────────────────────
# DASHBOARD HTML
# ──────────────────────────────────────────────

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CryptoGuard — Live Detection</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600&display=swap');

  :root {
    --bg         : #080c10;
    --surface    : #0d1117;
    --surface2   : #161b22;
    --border     : #21262d;
    --text       : #e6edf3;
    --muted      : #8b949e;
    --safe       : #3fb950;
    --warn       : #d29922;
    --threat     : #f85149;
    --accent     : #58a6ff;
    --purple     : #bc8cff;
    --mono       : 'JetBrains Mono', monospace;
    --sans       : 'Inter', sans-serif;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    min-height: 100vh;
    overflow-x: hidden;
  }

  /* ── HEADER ── */
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 16px 28px;
    border-bottom: 1px solid var(--border);
    background: var(--surface);
    position: sticky;
    top: 0;
    z-index: 100;
  }

  .logo {
    display: flex;
    align-items: center;
    gap: 10px;
    font-family: var(--mono);
    font-weight: 700;
    font-size: 1.1rem;
    letter-spacing: 0.05em;
  }

  .logo-icon {
    width: 32px; height: 32px;
    background: linear-gradient(135deg, var(--accent), var(--purple));
    border-radius: 8px;
    display: flex; align-items: center; justify-content: center;
    font-size: 16px;
  }

  .header-meta {
    display: flex;
    align-items: center;
    gap: 20px;
    font-family: var(--mono);
    font-size: 0.78rem;
    color: var(--muted);
  }

  .uptime-badge {
    background: var(--surface2);
    border: 1px solid var(--border);
    padding: 4px 10px;
    border-radius: 6px;
  }

  /* ── STATUS BANNER ── */
  #status-banner {
    padding: 20px 28px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    border-bottom: 1px solid var(--border);
    transition: background 0.4s ease;
  }

  #status-banner.SAFE    { background: rgba(63,185,80,0.08); }
  #status-banner.WARNING { background: rgba(210,153,34,0.10); }
  #status-banner.THREAT  { background: rgba(248,81,73,0.12); animation: pulse-bg 1.5s infinite; }

  @keyframes pulse-bg {
    0%, 100% { background: rgba(248,81,73,0.12); }
    50%       { background: rgba(248,81,73,0.22); }
  }

  .status-left { display: flex; align-items: center; gap: 16px; }

  .status-dot {
    width: 14px; height: 14px;
    border-radius: 50%;
    flex-shrink: 0;
  }
  .SAFE .status-dot    { background: var(--safe);   box-shadow: 0 0 10px var(--safe); }
  .WARNING .status-dot { background: var(--warn);   box-shadow: 0 0 10px var(--warn); animation: blink 1s infinite; }
  .THREAT .status-dot  { background: var(--threat); box-shadow: 0 0 14px var(--threat); animation: blink 0.6s infinite; }

  @keyframes blink { 0%,100% { opacity:1; } 50% { opacity:0.3; } }

  .status-label {
    font-family: var(--mono);
    font-size: 1.5rem;
    font-weight: 700;
    letter-spacing: 0.08em;
  }
  .SAFE .status-label    { color: var(--safe); }
  .WARNING .status-label { color: var(--warn); }
  .THREAT .status-label  { color: var(--threat); }

  .status-sub { color: var(--muted); font-size: 0.85rem; margin-top: 2px; }

  .confidence-ring {
    text-align: right;
    font-family: var(--mono);
  }
  .confidence-ring .val {
    font-size: 2.2rem;
    font-weight: 700;
    line-height: 1;
  }
  .confidence-ring .lbl {
    font-size: 0.72rem;
    color: var(--muted);
    letter-spacing: 0.1em;
    text-transform: uppercase;
  }

  /* ── MAIN GRID ── */
  .main {
    padding: 24px 28px;
    display: grid;
    grid-template-columns: 1fr 1fr 1fr;
    grid-template-rows: auto auto auto;
    gap: 16px;
  }

  /* ── STAT CARDS ── */
  .stat-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 18px 20px;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .stat-label {
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    color: var(--muted);
    font-family: var(--mono);
  }

  .stat-value {
    font-family: var(--mono);
    font-size: 2rem;
    font-weight: 700;
    line-height: 1;
  }

  .stat-bar {
    height: 4px;
    background: var(--border);
    border-radius: 2px;
    margin-top: 8px;
    overflow: hidden;
  }
  .stat-bar-fill {
    height: 100%;
    border-radius: 2px;
    transition: width 0.5s ease;
  }

  /* ── CHART PANELS ── */
  .chart-panel {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 18px 20px;
    grid-column: span 3;
  }

  .chart-panel.half { grid-column: span 2; }
  .chart-panel.third { grid-column: span 1; }

  .panel-title {
    font-family: var(--mono);
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    color: var(--muted);
    margin-bottom: 14px;
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .panel-title::before {
    content: '';
    display: inline-block;
    width: 3px; height: 12px;
    background: var(--accent);
    border-radius: 2px;
  }

  canvas { max-height: 180px; }

  /* ── THREAT SCORE CHART ── */
  #score-chart-wrap canvas { max-height: 160px; }

  /* ── ALERTS PANEL ── */
  .alerts-panel {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 18px 20px;
    grid-column: span 1;
  }

  .alert-list { display: flex; flex-direction: column; gap: 8px; margin-top: 4px; }

  .alert-item {
    display: flex;
    gap: 10px;
    padding: 10px 12px;
    border-radius: 6px;
    font-size: 0.82rem;
    border: 1px solid transparent;
  }

  .alert-item.threat {
    background: rgba(248,81,73,0.08);
    border-color: rgba(248,81,73,0.2);
  }
  .alert-item.safe {
    background: rgba(63,185,80,0.07);
    border-color: rgba(63,185,80,0.2);
  }

  .alert-time {
    font-family: var(--mono);
    font-size: 0.72rem;
    color: var(--muted);
    white-space: nowrap;
    margin-top: 1px;
  }

  .no-alerts {
    color: var(--muted);
    font-size: 0.82rem;
    text-align: center;
    padding: 20px 0;
    font-family: var(--mono);
  }

  /* ── FEATURES TABLE ── */
  .features-panel {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 18px 20px;
    grid-column: span 2;
  }

  .feat-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 6px;
    margin-top: 4px;
  }

  .feat-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 6px 10px;
    border-radius: 6px;
    background: var(--surface2);
    font-size: 0.80rem;
  }

  .feat-name { color: var(--muted); font-family: var(--mono); font-size: 0.72rem; }
  .feat-val  { font-family: var(--mono); font-weight: 600; color: var(--text); }

  .feat-row.highlight { border-left: 2px solid var(--accent); }

  /* ── CLEAR BTN ── */
  .btn-clear {
    margin-left: auto;
    background: transparent;
    border: 1px solid var(--border);
    color: var(--muted);
    font-family: var(--mono);
    font-size: 0.72rem;
    padding: 3px 10px;
    border-radius: 4px;
    cursor: pointer;
    transition: all 0.2s;
  }
  .btn-clear:hover { border-color: var(--threat); color: var(--threat); }

  .btn-kill {
    background: rgba(248,81,73,0.12);
    border: 1px solid var(--threat);
    color: var(--threat);
    font-family: var(--mono);
    font-size: 0.82rem;
    font-weight: 600;
    padding: 8px 18px;
    border-radius: 6px;
    cursor: pointer;
    letter-spacing: 0.05em;
    transition: all 0.2s;
    display: none;
  }
  .btn-kill:hover { background: rgba(248,81,73,0.25); }
  .btn-kill.visible { display: inline-block; }
  .btn-kill:disabled { opacity: 0.5; cursor: not-allowed; }

  /* ── SAMPLE COUNTER ── */
  #sample-count { color: var(--accent); }
</style>
</head>
<body>

<!-- HEADER -->
<header>
  <div class="logo">
    <div class="logo-icon">🛡</div>
    CRYPTOGUARD
  </div>
  <div class="header-meta">
    <span>Samples: <span id="sample-count">0</span></span>
    <span class="uptime-badge">Uptime: <span id="uptime">0s</span></span>
    <span id="last-update" style="color:var(--muted)">—</span>
  </div>
</header>

<!-- STATUS BANNER -->
<div id="status-banner" class="SAFE">
  <div class="status-left">
    <div class="status-dot"></div>
    <div>
      <div class="status-label" id="status-text">SAFE</div>
      <div style="display:flex;align-items:center;gap:8px;margin-top:2px">
        <div class="status-sub" id="status-sub">Monitoring system activity...</div>
        <span id="veto-badge" style="display:none;background:rgba(88,166,255,0.15);border:1px solid var(--accent);color:var(--accent);font-family:var(--mono);font-size:0.68rem;padding:1px 7px;border-radius:4px;letter-spacing:0.05em">🛡️ VETO ACTIVE</span>
      </div>
    </div>
  </div>
  <div style="display:flex;align-items:center;gap:20px">
    <button class="btn-kill" id="kill-btn" onclick="killMiners()">⚡ TERMINATE MINER</button>
    <div class="confidence-ring">
      <div class="val" id="confidence-val">0.0<span style="font-size:1rem">%</span></div>
      <div class="lbl">Threat Score</div>
    </div>
  </div>
</div>

<!-- MAIN GRID -->
<div class="main">

  <!-- STAT CARDS -->
  <div class="stat-card">
    <div class="stat-label">CPU Usage</div>
    <div class="stat-value" id="cpu-val" style="color:var(--accent)">—</div>
    <div class="stat-bar"><div class="stat-bar-fill" id="cpu-bar" style="background:var(--accent);width:0%"></div></div>
  </div>

  <div class="stat-card">
    <div class="stat-label">Memory Usage</div>
    <div class="stat-value" id="mem-val" style="color:var(--purple)">—</div>
    <div class="stat-bar"><div class="stat-bar-fill" id="mem-bar" style="background:var(--purple);width:0%"></div></div>
  </div>

  <div class="stat-card">
    <div class="stat-label">CPU Spike Duration</div>
    <div class="stat-value" id="spike-val" style="color:var(--warn)">—</div>
    <div class="stat-sub" style="font-size:0.75rem;color:var(--muted);font-family:var(--mono)" id="spike-count">spikes: 0</div>
  </div>

  <!-- CPU + MEMORY CHART -->
  <div class="chart-panel half">
    <div class="panel-title">CPU &amp; Memory — Live</div>
    <canvas id="cpu-chart"></canvas>
  </div>

  <!-- THREAT SCORE CHART -->
  <div class="chart-panel third" id="score-chart-wrap">
    <div class="panel-title">Threat Score — Live</div>
    <canvas id="score-chart"></canvas>
  </div>

  <!-- FEATURES -->
  <div class="features-panel">
    <div class="panel-title">Live Feature Readings</div>
    <div class="feat-grid" id="feat-grid">
      <div class="feat-row"><span class="feat-name">cpu_total</span><span class="feat-val" id="f-cpu">—</span></div>
      <div class="feat-row"><span class="feat-name">cpu_max_core</span><span class="feat-val" id="f-maxcore">—</span></div>
      <div class="feat-row highlight"><span class="feat-name">memory_percent</span><span class="feat-val" id="f-mem">—</span></div>
      <div class="feat-row highlight"><span class="feat-name">memory_available</span><span class="feat-val" id="f-memavail">—</span></div>
      <div class="feat-row"><span class="feat-name">net_sent_kb</span><span class="feat-val" id="f-netsent">—</span></div>
      <div class="feat-row"><span class="feat-name">net_recv_kb</span><span class="feat-val" id="f-netrecv">—</span></div>
      <div class="feat-row"><span class="feat-name">process_count</span><span class="feat-val" id="f-procs">—</span></div>
      <div class="feat-row"><span class="feat-name">top_proc_cpu</span><span class="feat-val" id="f-topcpu">—</span></div>
      <div class="feat-row highlight"><span class="feat-name">miner_detected</span><span class="feat-val" id="f-miner">—</span></div>
      <div class="feat-row"><span class="feat-name">spike_duration</span><span class="feat-val" id="f-spike">—</span></div>
    </div>
  </div>

  <!-- ALERTS -->
  <div class="alerts-panel">
    <div class="panel-title">
      Alert Log
      <button class="btn-clear" onclick="clearAlerts()">Clear</button>
    </div>
    <div class="alert-list" id="alert-list">
      <div class="no-alerts">No alerts yet</div>
    </div>
  </div>

  <!-- NETWORK CHART -->
  <div class="chart-panel">
    <div class="panel-title">Network Traffic — KB/s</div>
    <canvas id="net-chart"></canvas>
  </div>

</div>

<script>
// ── CHART SETUP ──────────────────────────────

const chartDefaults = {
  responsive: true,
  maintainAspectRatio: true,
  animation: { duration: 300 },
  plugins: { legend: { labels: { color: '#8b949e', font: { family: 'JetBrains Mono', size: 11 } } } },
  scales: {
    x: { ticks: { color: '#8b949e', font: { family: 'JetBrains Mono', size: 10 }, maxTicksLimit: 6 }, grid: { color: '#21262d' } },
    y: { ticks: { color: '#8b949e', font: { family: 'JetBrains Mono', size: 10 } }, grid: { color: '#21262d' } }
  }
};

function makeChart(id, datasets, yMax) {
  const ctx = document.getElementById(id).getContext('2d');
  return new Chart(ctx, {
    type: 'line',
    data: { labels: [], datasets },
    options: {
      ...chartDefaults,
      scales: {
        ...chartDefaults.scales,
        y: { ...chartDefaults.scales.y, min: 0, max: yMax || undefined }
      }
    }
  });
}

const cpuChart = makeChart('cpu-chart', [
  { label: 'CPU %',    data: [], borderColor: '#58a6ff', backgroundColor: 'rgba(88,166,255,0.08)', tension: 0.4, fill: true, pointRadius: 0 },
  { label: 'Memory %', data: [], borderColor: '#bc8cff', backgroundColor: 'rgba(188,140,255,0.08)', tension: 0.4, fill: true, pointRadius: 0 },
], 100);

const scoreChart = makeChart('score-chart', [
  { label: 'Threat Score', data: [], borderColor: '#f85149', backgroundColor: 'rgba(248,81,73,0.12)', tension: 0.4, fill: true, pointRadius: 0 },
], 100);

const netChart = makeChart('net-chart', [
  { label: '↑ Sent KB',   data: [], borderColor: '#3fb950', backgroundColor: 'rgba(63,185,80,0.08)', tension: 0.4, fill: true, pointRadius: 0 },
  { label: '↓ Recv KB',   data: [], borderColor: '#d29922', backgroundColor: 'rgba(210,153,34,0.08)', tension: 0.4, fill: true, pointRadius: 0 },
]);

function updateChart(chart, labels, ...datasets) {
  chart.data.labels = labels;
  datasets.forEach((d, i) => { chart.data.datasets[i].data = d; });
  chart.update('none');
}

// ── HELPERS ──────────────────────────────────

function fmtUptime(s) {
  const h = Math.floor(s/3600), m = Math.floor((s%3600)/60), sec = s%60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${sec}s`;
  return `${sec}s`;
}

function setStatus(status, confidence) {
  const banner = document.getElementById('status-banner');
  banner.className = status;
  document.getElementById('status-text').textContent = status;
  document.getElementById('confidence-val').innerHTML =
    `${confidence}<span style="font-size:1rem">%</span>`;

  const subs = {
    SAFE    : 'System activity is within normal parameters.',
    WARNING : 'Elevated activity detected — monitoring closely.',
    THREAT  : '🚨 Cryptojacking activity detected!'
  };
  document.getElementById('status-sub').textContent = subs[status];

  const colors = { SAFE: '#3fb950', WARNING: '#d29922', THREAT: '#f85149' };
  document.getElementById('confidence-val').style.color = colors[status];
}

// ── MAIN POLL LOOP ────────────────────────────

async function poll() {
  try {
    const res  = await fetch('/api/status');
    const data = await res.json();

    // Status
    setStatus(data.status, data.confidence);
    updateKillButton(data.status);

    // Veto indicator
    const vetoEl = document.getElementById('veto-badge');
    if (data.veto_active) {
      vetoEl.style.display = 'inline-block';
    } else {
      vetoEl.style.display = 'none';
    }

    // Header
    document.getElementById('sample-count').textContent = data.sample_count;
    document.getElementById('uptime').textContent = fmtUptime(data.uptime);
    document.getElementById('last-update').textContent =
      new Date().toLocaleTimeString();

    // Stat cards
    const f = data.features;
    const cpu = f.cpu_total_percent || 0;
    const mem = f.memory_percent    || 0;

    document.getElementById('cpu-val').textContent = cpu.toFixed(1) + '%';
    document.getElementById('mem-val').textContent = mem.toFixed(1) + '%';
    document.getElementById('cpu-bar').style.width = cpu + '%';
    document.getElementById('mem-bar').style.width = mem + '%';

    const spike = f.cpu_spike_duration_sec || 0;
    document.getElementById('spike-val').textContent = spike.toFixed(1) + 's';
    document.getElementById('spike-count').textContent = `spikes: ${f.cpu_spike_count || 0}`;

    // Feature table
    document.getElementById('f-cpu').textContent     = (f.cpu_total_percent||0).toFixed(1) + '%';
    document.getElementById('f-maxcore').textContent = (f.cpu_max_core_percent||0).toFixed(1) + '%';
    document.getElementById('f-mem').textContent     = (f.memory_percent||0).toFixed(1) + '%';
    document.getElementById('f-memavail').textContent= (f.memory_available_mb||0) + ' MB';
    document.getElementById('f-netsent').textContent = ((f.net_bytes_sent_delta||0)/1024).toFixed(1) + ' KB';
    document.getElementById('f-netrecv').textContent = ((f.net_bytes_recv_delta||0)/1024).toFixed(1) + ' KB';
    document.getElementById('f-procs').textContent   = f.process_count || 0;
    document.getElementById('f-topcpu').textContent  = (f.top_process_cpu_percent||0).toFixed(1) + '%';

    const minerEl = document.getElementById('f-miner');
    minerEl.textContent = f.miner_process_detected ? 'YES' : 'no';
    minerEl.style.color = f.miner_process_detected ? '#f85149' : '#3fb950';

    document.getElementById('f-spike').textContent = (f.cpu_spike_duration_sec||0).toFixed(1) + 's';

    // Charts
    const h = data.history;
    updateChart(cpuChart,   h.timestamps, h.cpu_total, h.memory_percent);
    updateChart(scoreChart, h.timestamps, h.prediction_score);
    updateChart(netChart,   h.timestamps, h.net_sent, h.net_recv);

    // Alerts
    const alertList = document.getElementById('alert-list');
    if (data.alerts.length === 0) {
      alertList.innerHTML = '<div class="no-alerts">No alerts yet</div>';
    } else {
      alertList.innerHTML = data.alerts.map(a => `
        <div class="alert-item ${a.type}">
          <div class="alert-time">${a.time}</div>
          <div>${a.message}</div>
        </div>
      `).join('');
    }

  } catch(e) {
    console.error('Poll error:', e);
  }
}

async function clearAlerts() {
  await fetch('/api/clear_alerts', { method: 'POST' });
}

async function killMiners() {
  const btn = document.getElementById('kill-btn');
  btn.disabled = true;
  btn.textContent = '⏳ Terminating...';
  try {
    const res  = await fetch('/api/kill_miners', { method: 'POST' });
    const data = await res.json();
    if (data.killed.length > 0) {
      btn.textContent = `✅ Killed ${data.killed.length} process(es)`;
      setTimeout(() => {
        btn.textContent = '⚡ TERMINATE MINER';
        btn.disabled = false;
      }, 3000);
    } else {
      btn.textContent = '⚠️ No miners found';
      setTimeout(() => {
        btn.textContent = '⚡ TERMINATE MINER';
        btn.disabled = false;
      }, 2000);
    }
  } catch(e) {
    btn.textContent = '⚡ TERMINATE MINER';
    btn.disabled = false;
  }
}

function updateKillButton(status) {
  const btn = document.getElementById('kill-btn');
  if (status === 'THREAT') {
    btn.classList.add('visible');
  } else {
    btn.classList.remove('visible');
    btn.disabled = false;
    btn.textContent = '⚡ TERMINATE MINER';
  }
}

// Poll every 2 seconds
poll();
setInterval(poll, 2000);
</script>
</body>
</html>"""

@app.route("/")
def dashboard():
    return render_template_string(DASHBOARD_HTML)

# ──────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "─"*50)
    print("  CryptoGuard — Real-Time Detection Dashboard")
    print("─"*50)
    print("  Open browser: http://localhost:5000")
    print("  Press Ctrl+C to stop")
    print("─"*50 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=False)
