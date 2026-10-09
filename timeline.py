"""
CryptoGuard — Threat Timeline
==============================
Author  : CK (FYP / Portfolio Project)

Standalone Flask route that shows a visual timeline of all
detection events — when attacks started, how long they ran,
confidence over time, and ATT&CK tags per event.

USAGE:
    This file is imported by dashboard.py automatically.
    Copy it to ~/cryptojacking-fyp/ and add one line to dashboard.py:
        from timeline import register_timeline
        register_timeline(app, state, history)

    Then visit: http://localhost:5000/timeline
"""

from flask import Blueprint, jsonify, render_template_string
from datetime import datetime

timeline_bp = Blueprint("timeline", __name__)

# ── TIMELINE HTML ──────────────────────────────────────────────────

TIMELINE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CryptoGuard — Threat Timeline</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600&display=swap');

  :root {
    --bg      : #080c10;
    --surface : #0d1117;
    --surface2: #161b22;
    --border  : #21262d;
    --text    : #e6edf3;
    --muted   : #8b949e;
    --safe    : #3fb950;
    --warn    : #d29922;
    --threat  : #f85149;
    --accent  : #58a6ff;
    --purple  : #bc8cff;
    --mono    : 'JetBrains Mono', monospace;
    --sans    : 'Inter', sans-serif;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    min-height: 100vh;
    padding: 0 0 40px;
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
    font-size: 1rem;
    letter-spacing: 0.05em;
    color: var(--accent);
  }

  .nav-links {
    display: flex;
    gap: 16px;
    font-family: var(--mono);
    font-size: 0.78rem;
  }

  .nav-links a {
    color: var(--muted);
    text-decoration: none;
    padding: 4px 10px;
    border-radius: 5px;
    border: 1px solid transparent;
    transition: all 0.2s;
  }

  .nav-links a:hover, .nav-links a.active {
    border-color: var(--border);
    color: var(--text);
  }

  .nav-links a.active { color: var(--accent); border-color: var(--accent); }

  /* ── MAIN ── */
  .main { padding: 24px 28px; }

  /* ── STATS ROW ── */
  .stats-row {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 14px;
    margin-bottom: 20px;
  }

  .stat-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 16px 18px;
  }

  .stat-label {
    font-family: var(--mono);
    font-size: 0.70rem;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    color: var(--muted);
    margin-bottom: 6px;
  }

  .stat-val {
    font-family: var(--mono);
    font-size: 1.8rem;
    font-weight: 700;
    line-height: 1;
  }

  .stat-sub {
    font-size: 0.72rem;
    color: var(--muted);
    margin-top: 4px;
    font-family: var(--mono);
  }

  /* ── CHART PANEL ── */
  .panel {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 20px 22px;
    margin-bottom: 16px;
  }

  .panel-title {
    font-family: var(--mono);
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    color: var(--muted);
    margin-bottom: 16px;
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

  canvas { max-height: 200px; }

  /* ── TIMELINE EVENTS ── */
  .timeline {
    position: relative;
    padding-left: 28px;
  }

  .timeline::before {
    content: '';
    position: absolute;
    left: 9px; top: 0; bottom: 0;
    width: 2px;
    background: linear-gradient(to bottom, var(--threat), var(--border));
    border-radius: 1px;
  }

  .timeline-event {
    position: relative;
    margin-bottom: 16px;
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 14px 16px;
    transition: border-color 0.2s;
  }

  .timeline-event:hover { border-color: var(--accent); }

  .timeline-event::before {
    content: '';
    position: absolute;
    left: -23px;
    top: 16px;
    width: 10px; height: 10px;
    border-radius: 50%;
    background: var(--threat);
    box-shadow: 0 0 8px var(--threat);
    border: 2px solid var(--bg);
  }

  .timeline-event.safe::before   { background: var(--safe); box-shadow: 0 0 8px var(--safe); }
  .timeline-event.warning::before { background: var(--warn); box-shadow: 0 0 8px var(--warn); }

  .event-header {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 8px;
  }

  .event-time {
    font-family: var(--mono);
    font-size: 0.78rem;
    color: var(--muted);
  }

  .event-type {
    font-family: var(--mono);
    font-size: 0.78rem;
    font-weight: 700;
    padding: 2px 8px;
    border-radius: 4px;
  }

  .event-type.threat  { background: rgba(248,81,73,0.15); color: var(--threat); }
  .event-type.safe    { background: rgba(63,185,80,0.12); color: var(--safe); }
  .event-type.warning { background: rgba(210,153,34,0.12); color: var(--warn); }

  .event-conf {
    margin-left: auto;
    font-family: var(--mono);
    font-size: 0.78rem;
    color: var(--accent);
  }

  .event-msg {
    font-size: 0.85rem;
    color: var(--text);
    margin-bottom: 6px;
  }

  .attack-tags {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
  }

  .attack-tag {
    font-family: var(--mono);
    font-size: 0.68rem;
    padding: 2px 7px;
    border-radius: 4px;
    background: rgba(248,81,73,0.10);
    border: 1px solid rgba(248,81,73,0.25);
    color: var(--threat);
    text-decoration: none;
  }

  .safe-tag {
    font-family: var(--mono);
    font-size: 0.68rem;
    padding: 2px 7px;
    border-radius: 4px;
    background: rgba(63,185,80,0.10);
    border: 1px solid rgba(63,185,80,0.25);
    color: var(--safe);
  }

  /* ── EMPTY STATE ── */
  .empty-state {
    text-align: center;
    padding: 40px;
    color: var(--muted);
    font-family: var(--mono);
    font-size: 0.85rem;
  }

  /* ── DURATION BADGE ── */
  .duration-badge {
    display: inline-block;
    background: var(--surface);
    border: 1px solid var(--border);
    font-family: var(--mono);
    font-size: 0.68rem;
    padding: 1px 6px;
    border-radius: 4px;
    color: var(--muted);
  }

  /* ── EXPORT BTN ── */
  .btn-export {
    background: transparent;
    border: 1px solid var(--border);
    color: var(--muted);
    font-family: var(--mono);
    font-size: 0.75rem;
    padding: 5px 12px;
    border-radius: 5px;
    cursor: pointer;
    transition: all 0.2s;
    margin-left: auto;
  }
  .btn-export:hover { border-color: var(--accent); color: var(--accent); }
</style>
</head>
<body>

<!-- HEADER -->
<header>
  <div class="logo">🛡️ CRYPTOGUARD</div>
  <div class="nav-links">
    <a href="/">Dashboard</a>
    <a href="/timeline" class="active">Timeline</a>
  </div>
</header>

<!-- MAIN -->
<div class="main">

  <!-- STATS -->
  <div class="stats-row">
    <div class="stat-card">
      <div class="stat-label">Total Events</div>
      <div class="stat-val" id="stat-total" style="color:var(--text)">0</div>
      <div class="stat-sub">all time</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Threats</div>
      <div class="stat-val" id="stat-threats" style="color:var(--threat)">0</div>
      <div class="stat-sub">detected</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Avg Confidence</div>
      <div class="stat-val" id="stat-avgconf" style="color:var(--accent)">0%</div>
      <div class="stat-sub">on threat events</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Top Technique</div>
      <div class="stat-val" id="stat-technique" style="color:var(--threat);font-size:1.1rem">—</div>
      <div class="stat-sub" id="stat-technique-name">—</div>
    </div>
  </div>

  <!-- CONFIDENCE CHART -->
  <div class="panel">
    <div class="panel-title">
      Threat Score History
      <button class="btn-export" onclick="exportJSON()">⬇ Export JSON</button>
    </div>
    <canvas id="conf-chart"></canvas>
  </div>

  <!-- TIMELINE -->
  <div class="panel">
    <div class="panel-title">Attack Timeline</div>
    <div class="timeline" id="timeline-list">
      <div class="empty-state">
        No events recorded yet.<br>
        Run a detection to see the timeline.
      </div>
    </div>
  </div>

</div>

<script>
// ── CHART ─────────────────────────────────────────────────────────

const ctx = document.getElementById('conf-chart').getContext('2d');
const confChart = new Chart(ctx, {
  type: 'line',
  data: {
    labels: [],
    datasets: [
      {
        label: 'Threat Score %',
        data: [],
        borderColor: '#f85149',
        backgroundColor: 'rgba(248,81,73,0.08)',
        tension: 0.4,
        fill: true,
        pointRadius: 2,
      },
      {
        label: 'CPU %',
        data: [],
        borderColor: '#58a6ff',
        backgroundColor: 'transparent',
        tension: 0.4,
        fill: false,
        pointRadius: 0,
      },
      {
        label: 'Memory %',
        data: [],
        borderColor: '#bc8cff',
        backgroundColor: 'transparent',
        tension: 0.4,
        fill: false,
        pointRadius: 0,
      }
    ]
  },
  options: {
    responsive: true,
    maintainAspectRatio: true,
    animation: { duration: 300 },
    plugins: {
      legend: {
        labels: {
          color: '#8b949e',
          font: { family: 'JetBrains Mono', size: 11 }
        }
      }
    },
    scales: {
      x: {
        ticks: { color: '#8b949e', font: { family: 'JetBrains Mono', size: 10 }, maxTicksLimit: 8 },
        grid: { color: '#21262d' }
      },
      y: {
        min: 0, max: 100,
        ticks: { color: '#8b949e', font: { family: 'JetBrains Mono', size: 10 } },
        grid: { color: '#21262d' }
      }
    }
  }
});

// ── DATA ──────────────────────────────────────────────────────────

let allEvents = [];

async function fetchData() {
  try {
    const res  = await fetch('/api/timeline');
    const data = await res.json();
    allEvents  = data.events || [];
    renderStats(data);
    renderChart(data);
    renderTimeline(data.events);
  } catch(e) {
    console.error('Fetch error:', e);
  }
}

// ── STATS ─────────────────────────────────────────────────────────

function renderStats(data) {
  const events  = data.events || [];
  const threats = events.filter(e => e.type === 'threat');
  const avgConf = threats.length
    ? (threats.reduce((s, e) => s + (e.confidence || 0), 0) / threats.length).toFixed(1)
    : 0;

  document.getElementById('stat-total').textContent   = events.length;
  document.getElementById('stat-threats').textContent = threats.length;
  document.getElementById('stat-avgconf').textContent = avgConf + '%';

  // Top technique
  const techCounts = {};
  events.forEach(e => {
    (e.attack_tags || '').split(' | ').forEach(t => {
      if (t) techCounts[t] = (techCounts[t] || 0) + 1;
    });
  });
  const topTech = Object.entries(techCounts).sort((a,b) => b[1]-a[1])[0];
  if (topTech) {
    document.getElementById('stat-technique').textContent      = topTech[0];
    document.getElementById('stat-technique-name').textContent = `×${topTech[1]} detections`;
  }
}

// ── CHART ─────────────────────────────────────────────────────────

function renderChart(data) {
  const h = data.history || {};
  confChart.data.labels                  = h.timestamps || [];
  confChart.data.datasets[0].data        = h.prediction_score || [];
  confChart.data.datasets[1].data        = h.cpu_total || [];
  confChart.data.datasets[2].data        = h.memory_percent || [];
  confChart.update('none');
}

// ── TIMELINE ──────────────────────────────────────────────────────

function renderTimeline(events) {
  const container = document.getElementById('timeline-list');
  if (!events || events.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        No events recorded yet.<br>
        Run a detection to see the timeline.
      </div>`;
    return;
  }

  container.innerHTML = events.map(e => {
    const tags = (e.attack_tags || '').split(' | ')
      .filter(Boolean)
      .map(t => `<span class="attack-tag">${t}</span>`)
      .join('');

    const safeTags = e.type === 'safe'
      ? `<span class="safe-tag">✅ Cleared</span>` : '';

    const confStr = e.confidence != null
      ? `<span class="event-conf">${e.confidence.toFixed(1)}%</span>` : '';

    const dur = e.duration_sec != null
      ? `<span class="duration-badge">⏱ ${e.duration_sec}s</span>` : '';

    return `
      <div class="timeline-event ${e.type}">
        <div class="event-header">
          <span class="event-time">${e.date} ${e.time}</span>
          <span class="event-type ${e.type}">${e.type.toUpperCase()}</span>
          ${dur}
          ${confStr}
        </div>
        <div class="event-msg">${e.message}</div>
        <div class="attack-tags">${tags}${safeTags}</div>
      </div>
    `;
  }).join('');
}

// ── EXPORT ────────────────────────────────────────────────────────

function exportJSON() {
  const blob = new Blob([JSON.stringify(allEvents, null, 2)], { type: 'application/json' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = `cryptoguard_timeline_${new Date().toISOString().slice(0,10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

// ── POLL ──────────────────────────────────────────────────────────

fetchData();
setInterval(fetchData, 3000);
</script>
</body>
</html>"""


def register_timeline(app, state_ref, history_ref, alert_log_ref):
    """
    Register timeline blueprint + API route on the Flask app.
    Call this from dashboard.py after creating the app.
    """

    @app.route("/timeline")
    def timeline_page():
        return render_template_string(TIMELINE_HTML)

    @app.route("/api/timeline")
    def api_timeline():
        alerts = alert_log_ref

        # Enrich alerts with duration
        enriched = []
        threat_start = None

        for i, alert in enumerate(reversed(alerts)):
            ev = dict(alert)
            if alert.get("type") == "threat" and threat_start is None:
                threat_start = alert.get("time")
            elif alert.get("type") == "safe" and threat_start is not None:
                # Try to compute duration
                try:
                    fmt = "%H:%M:%S"
                    t1  = datetime.strptime(threat_start, fmt)
                    t2  = datetime.strptime(alert.get("time"), fmt)
                    ev["duration_sec"] = int((t2 - t1).total_seconds())
                except Exception:
                    ev["duration_sec"] = None
                threat_start = None

            ev["date"] = ev.get("date", datetime.now().strftime("%Y-%m-%d"))
            ev["confidence"] = state_ref.get("confidence", 0) if alert.get("type") == "threat" else None
            enriched.append(ev)

        enriched.reverse()

        return jsonify({
            "events"  : enriched,
            "history" : {k: list(v) for k, v in history_ref.items()},
            "summary" : {
                "total"   : len(alerts),
                "threats" : sum(1 for a in alerts if a.get("type") == "threat"),
                "uptime"  : state_ref.get("sample_count", 0),
            }
        })
