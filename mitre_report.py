"""
CryptoGuard — MITRE ATT&CK SOC Report Generator
================================================
Author  : CK (FYP / Portfolio Project)

Reads detection history from dashboard state and generates:
  1. A SOC-style terminal report
  2. ATT&CK Navigator heatmap JSON
  3. A markdown incident report

USAGE:
    # After running dashboard.py and triggering some detections:
    python3 mitre_report.py

    # Or pass a custom alert log:
    python3 mitre_report.py --alerts alerts.json
"""

import json
import os
import argparse
from datetime import datetime
from mitre_mapping import (
    map_to_attack,
    generate_navigator_layer,
    get_highest_severity,
    format_attack_summary,
    ATTACK_TECHNIQUES,
)

# ANSI
R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"
C = "\033[96m"; W = "\033[97m"; RESET = "\033[0m"; BOLD = "\033[1m"
DIM = "\033[2m"

OUTPUT_DIR = "mitre_output"

# ──────────────────────────────────────────────────────────────────
# SAMPLE DETECTION EVENTS (used when no real data is available)
# ──────────────────────────────────────────────────────────────────

SAMPLE_EVENTS = [
    {
        "time"      : "06:43:28",
        "date"      : datetime.now().strftime("%Y-%m-%d"),
        "confidence": 98.5,
        "status"    : "THREAT",
        "features"  : {
            "cpu_total_percent"      : 94.2,
            "memory_percent"         : 87.3,
            "memory_available_mb"    : 412,
            "net_bytes_sent_delta"   : 12480,
            "cpu_spike_duration_sec" : 48.0,
            "miner_process_detected" : 1,
            "mining_pool_connection" : 0,
            "top_process_cpu_percent": 91.0,
        }
    },
    {
        "time"      : "06:51:14",
        "date"      : datetime.now().strftime("%Y-%m-%d"),
        "confidence": 76.2,
        "status"    : "THREAT",
        "features"  : {
            "cpu_total_percent"      : 81.0,
            "memory_percent"         : 79.5,
            "memory_available_mb"    : 890,
            "net_bytes_sent_delta"   : 4096,
            "cpu_spike_duration_sec" : 22.0,
            "miner_process_detected" : 0,
            "mining_pool_connection" : 0,
            "top_process_cpu_percent": 78.0,
        }
    },
    {
        "time"      : "07:12:03",
        "date"      : datetime.now().strftime("%Y-%m-%d"),
        "confidence": 99.1,
        "status"    : "THREAT",
        "features"  : {
            "cpu_total_percent"      : 98.7,
            "memory_percent"         : 91.2,
            "memory_available_mb"    : 280,
            "net_bytes_sent_delta"   : 18920,
            "cpu_spike_duration_sec" : 120.0,
            "miner_process_detected" : 1,
            "mining_pool_connection" : 1,
            "top_process_cpu_percent": 97.0,
        }
    },
]


# ──────────────────────────────────────────────────────────────────
# TERMINAL REPORT
# ──────────────────────────────────────────────────────────────────

def print_soc_report(events_with_techniques):
    print(f"\n{BOLD}{C}{'═'*65}{RESET}")
    print(f"{BOLD}{C}  CryptoGuard — MITRE ATT&CK SOC Report{RESET}")
    print(f"{BOLD}{C}  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
    print(f"{BOLD}{C}{'═'*65}{RESET}")

    total     = len(events_with_techniques)
    high_sev  = sum(1 for e in events_with_techniques
                    if get_highest_severity(e["techniques"]) == "HIGH")

    print(f"\n  {BOLD}EXECUTIVE SUMMARY{RESET}")
    print(f"  {'─'*40}")
    print(f"  Total detections  : {BOLD}{total}{RESET}")
    print(f"  High severity     : {R}{BOLD}{high_sev}{RESET}")
    print(f"  Medium severity   : {Y}{total - high_sev}{RESET}")
    print(f"  Primary technique : {R}T1496 — Resource Hijacking{RESET}")
    print(f"  Tactic            : {Y}TA0040 — Impact{RESET}")

    print(f"\n  {BOLD}DETECTION EVENTS{RESET}")
    print(f"  {'─'*40}")

    for i, event in enumerate(events_with_techniques, 1):
        sev     = get_highest_severity(event["techniques"])
        sev_col = R if sev == "HIGH" else Y
        conf    = event["confidence"]

        print(f"\n  {BOLD}[Event {i}]{RESET}  {event['date']} {event['time']}  "
              f"Confidence: {C}{conf:.1f}%{RESET}  "
              f"Severity: {sev_col}{sev}{RESET}")

        for m in event["techniques"]:
            tech = m["technique"]
            print(f"\n    {R}▶ {tech['id']} — {tech['name']}{RESET}")
            print(f"      {DIM}Tactic: {tech['tactic']} ({tech['tactic_id']}){RESET}")
            print(f"      {DIM}URL: {tech['url']}{RESET}")
            print(f"      Evidence:")
            for ev in m["evidence"]:
                print(f"        {Y}•{RESET} {ev}")
            print(f"      Mitigations:")
            for mit in tech["mitigations"]:
                print(f"        {G}→{RESET} {mit}")

    print(f"\n{BOLD}{C}{'═'*65}{RESET}\n")


# ──────────────────────────────────────────────────────────────────
# MARKDOWN INCIDENT REPORT
# ──────────────────────────────────────────────────────────────────

def generate_markdown_report(events_with_techniques) -> str:
    now   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = len(events_with_techniques)
    lines = []

    lines.append("# 🛡️ CryptoGuard — Incident Report")
    lines.append(f"\n**Generated:** {now}  ")
    lines.append(f"**Tool:** CryptoGuard v2.0  ")
    lines.append(f"**Analyst:** CK  ")
    lines.append(f"**Total Detections:** {total}  ")
    lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(
        "CryptoGuard detected cryptojacking activity on the monitored host. "
        "The primary MITRE ATT&CK technique observed is **T1496 — Resource Hijacking** "
        "under tactic **TA0040 — Impact**. "
        "Detection was based on sustained anomalies in memory utilisation, CPU load, "
        "and process behaviour consistent with the XMRig RandomX mining algorithm."
    )
    lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## MITRE ATT&CK Techniques Observed")
    lines.append("")

    # Collect unique techniques across all events
    seen = {}
    for event in events_with_techniques:
        for m in event["techniques"]:
            tid = m["technique"]["id"]
            if tid not in seen:
                seen[tid] = m

    lines.append("| Technique ID | Name | Tactic | Severity |")
    lines.append("|---|---|---|---|")
    for tid, m in seen.items():
        t = m["technique"]
        lines.append(
            f"| [{t['id']}]({t['url']}) | {t['name']} | "
            f"{t['tactic']} ({t['tactic_id']}) | {t['severity']} |"
        )

    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Detection Events")
    lines.append("")

    for i, event in enumerate(events_with_techniques, 1):
        lines.append(f"### Event {i} — {event['date']} {event['time']}")
        lines.append("")
        lines.append(f"- **Confidence:** {event['confidence']:.1f}%")
        lines.append(f"- **Severity:** {get_highest_severity(event['techniques'])}")
        lines.append(f"- **Techniques:** {format_attack_summary(event['techniques'])}")
        lines.append("")

        for m in event["techniques"]:
            t = m["technique"]
            lines.append(f"#### {t['id']} — {t['name']}")
            lines.append("")
            lines.append(f"> {t['description'][:200]}...")
            lines.append("")
            lines.append("**Evidence observed:**")
            for ev in m["evidence"]:
                lines.append(f"- {ev}")
            lines.append("")
            lines.append("**Recommended mitigations:**")
            for mit in t["mitigations"]:
                lines.append(f"- {mit}")
            lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## Recommended Response Actions")
    lines.append("")
    lines.append("1. **Immediate:** Terminate the miner process using CryptoGuard kill button")
    lines.append("2. **Short-term:** Audit crontab and systemd services for persistence (`crontab -l`, `systemctl list-units`)")
    lines.append("3. **Short-term:** Review `/tmp`, `~/.cache`, `~/.config` for dropped binaries")
    lines.append("4. **Network:** Block outbound traffic to mining pool ports (3333, 4444, 5555, 14433)")
    lines.append("5. **Long-term:** Deploy network-level Stratum protocol detection")
    lines.append("6. **Long-term:** Integrate CryptoGuard alerts with SIEM (Wazuh/Splunk/Sentinel)")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## ATT&CK Navigator")
    lines.append("")
    lines.append(
        "A heatmap layer JSON has been generated for the "
        "[ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/). "
        "Load `mitre_navigator_layer.json` to visualise technique coverage."
    )
    lines.append("")
    lines.append("---")
    lines.append(f"*Report generated by CryptoGuard — github.com/Chayesh/cryptoguard*")

    return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────
# SAVE OUTPUTS
# ──────────────────────────────────────────────────────────────────

def save_outputs(events_with_techniques):
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # ── Navigator JSON ──
    layer      = generate_navigator_layer(events_with_techniques)
    nav_path   = os.path.join(OUTPUT_DIR, "mitre_navigator_layer.json")
    with open(nav_path, "w") as f:
        json.dump(layer, f, indent=2)
    print(f"\n  {G}✅ Navigator layer : {nav_path}{RESET}")
    print(f"     → Load at: https://mitre-attack.github.io/attack-navigator/")

    # ── Markdown report ──
    md         = generate_markdown_report(events_with_techniques)
    md_path    = os.path.join(OUTPUT_DIR, "incident_report.md")
    with open(md_path, "w") as f:
        f.write(md)
    print(f"  {G}✅ Incident report  : {md_path}{RESET}")

    # ── Raw JSON (for SIEM integration later) ──
    raw = []
    for event in events_with_techniques:
        raw.append({
            "time"       : event["time"],
            "date"       : event["date"],
            "confidence" : event["confidence"],
            "severity"   : get_highest_severity(event["techniques"]),
            "techniques" : format_attack_summary(event["techniques"]),
            "features"   : event["features"],
        })
    raw_path = os.path.join(OUTPUT_DIR, "detections_raw.json")
    with open(raw_path, "w") as f:
        json.dump(raw, f, indent=2)
    print(f"  {G}✅ Raw JSON          : {raw_path}{RESET}")
    print(f"     → Use this for Wazuh/Splunk/Sentinel integration\n")


# ──────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────

def main(alerts_file=None):
    # Load events
    if alerts_file and os.path.exists(alerts_file):
        with open(alerts_file) as f:
            raw_events = json.load(f)
        print(f"\n  {G}[+]{RESET} Loaded {len(raw_events)} events from {alerts_file}")
    else:
        print(f"\n  {Y}[~]{RESET} No alert file found — using sample detection events")
        raw_events = SAMPLE_EVENTS

    # Map each event to ATT&CK techniques
    events_with_techniques = []
    for event in raw_events:
        techniques = map_to_attack(event["features"], event["confidence"])
        events_with_techniques.append({
            **event,
            "techniques": techniques,
        })

    # Print SOC report to terminal
    print_soc_report(events_with_techniques)

    # Save all outputs
    save_outputs(events_with_techniques)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="CryptoGuard — MITRE ATT&CK SOC Report Generator"
    )
    parser.add_argument(
        "--alerts", type=str, default=None,
        help="Path to alerts JSON file from dashboard (mitre_output/detections_raw.json)"
    )
    args = parser.parse_args()
    main(args.alerts)
