"""
CryptoGuard — MITRE ATT&CK Mapping Engine
==========================================
Author  : CK (FYP / Portfolio Project)

Maps cryptojacking detection events to MITRE ATT&CK techniques.
Used by dashboard.py, mitre_report.py, and the navigator heatmap.

MITRE ATT&CK Reference: https://attack.mitre.org/
Relevant Tactic: Impact (TA0040), Execution (TA0002), Defense Evasion (TA0005)
"""

from datetime import datetime

# ──────────────────────────────────────────────────────────────────
# ATT&CK TECHNIQUE DATABASE
# Techniques relevant to cryptojacking attacks
# ──────────────────────────────────────────────────────────────────

ATTACK_TECHNIQUES = {

    # ── IMPACT ───────────────────────────────────────────────────
    "T1496": {
        "id"         : "T1496",
        "name"       : "Resource Hijacking",
        "tactic"     : "Impact",
        "tactic_id"  : "TA0040",
        "url"        : "https://attack.mitre.org/techniques/T1496/",
        "description": (
            "Adversaries may leverage the resources of co-opted systems to "
            "complete resource-intensive tasks, which may impact system and/or "
            "hosted service availability. Cryptojacking is the primary example — "
            "using victim CPU/GPU to mine cryptocurrency."
        ),
        "detection_signals": [
            "Sustained high CPU utilisation (>75%) with no user-initiated task",
            "Memory allocation spike consistent with RandomX (~2GB)",
            "Known miner process name detected (xmrig, minerd, cpuminer)",
            "Outbound network traffic to known mining pool endpoints",
        ],
        "mitigations": [
            "M1038 — Execution Prevention: block known miner binaries",
            "M1031 — Network Intrusion Prevention: block mining pool IPs/domains",
            "M1018 — User Account Management: restrict execution privileges",
        ],
        "severity"   : "HIGH",
        "confidence_weight": 0.90,   # primary technique — almost always applies
    },

    # ── EXECUTION ─────────────────────────────────────────────────
    "T1059": {
        "id"         : "T1059",
        "name"       : "Command and Scripting Interpreter",
        "tactic"     : "Execution",
        "tactic_id"  : "TA0002",
        "url"        : "https://attack.mitre.org/techniques/T1059/",
        "description": (
            "Adversaries may abuse command and script interpreters to execute "
            "commands, scripts, or binaries. In cryptojacking, bash scripts are "
            "commonly used to download and execute miners silently."
        ),
        "detection_signals": [
            "Shell script execution followed by miner process spawn",
            "curl/wget downloading executable to /tmp or hidden directory",
            "nohup or disown used to detach miner from terminal",
        ],
        "mitigations": [
            "M1038 — Execution Prevention",
            "M1026 — Privileged Account Management",
        ],
        "severity"   : "MEDIUM",
        "confidence_weight": 0.60,
    },

    # ── DEFENSE EVASION ───────────────────────────────────────────
    "T1036": {
        "id"         : "T1036",
        "name"       : "Masquerading",
        "tactic"     : "Defense Evasion",
        "tactic_id"  : "TA0005",
        "url"        : "https://attack.mitre.org/techniques/T1036/",
        "description": (
            "Adversaries may attempt to manipulate features of their artifacts "
            "to make them appear legitimate. Miners are commonly renamed to "
            "system-sounding names (e.g. .update-service, kworker, sysupdate) "
            "or placed in hidden directories to avoid detection."
        ),
        "detection_signals": [
            "Process name mimicking system process (kworker, sysupdate, etc.)",
            "Miner binary in hidden directory (~/.cache, ~/.config)",
            "High CPU process with non-standard name",
        ],
        "mitigations": [
            "M1045 — Code Signing",
            "M1022 — Restrict File and Directory Permissions",
        ],
        "severity"   : "MEDIUM",
        "confidence_weight": 0.40,
    },

    # ── PERSISTENCE ───────────────────────────────────────────────
    "T1053": {
        "id"         : "T1053",
        "name"       : "Scheduled Task/Job",
        "tactic"     : "Persistence",
        "tactic_id"  : "TA0003",
        "url"        : "https://attack.mitre.org/techniques/T1053/",
        "description": (
            "Adversaries may abuse task scheduling functionality to facilitate "
            "initial or recurring execution of malicious code. Cryptojackers "
            "commonly install cron jobs to restart the miner if killed."
        ),
        "detection_signals": [
            "New cron job added after miner detection",
            "Systemd service created by non-root user",
            "Miner restarts automatically after termination",
        ],
        "mitigations": [
            "M1028 — Operating System Configuration",
            "M1018 — User Account Management",
        ],
        "severity"   : "HIGH",
        "confidence_weight": 0.35,
    },

    # ── COMMAND & CONTROL ─────────────────────────────────────────
    "T1571": {
        "id"         : "T1571",
        "name"       : "Non-Standard Port",
        "tactic"     : "Command and Control",
        "tactic_id"  : "TA0011",
        "url"        : "https://attack.mitre.org/techniques/T1571/",
        "description": (
            "Adversaries may communicate using a protocol and port pairing that "
            "are typically not associated with the standard use of the port. "
            "Mining pools commonly use non-standard ports (3333, 4444, 5555, 14433) "
            "via the Stratum protocol."
        ),
        "detection_signals": [
            "Outbound connection on port 3333, 4444, 5555, or 14433",
            "Stratum protocol traffic pattern detected",
            "Regular periodic outbound packets (share submission timing)",
        ],
        "mitigations": [
            "M1031 — Network Intrusion Prevention",
            "M1037 — Filter Network Traffic",
        ],
        "severity"   : "MEDIUM",
        "confidence_weight": 0.50,
    },

    # ── COLLECTION / RESOURCE DEV ─────────────────────────────────
    "T1496.001": {
        "id"         : "T1496.001",
        "name"       : "Resource Hijacking: Compute Hijacking",
        "tactic"     : "Impact",
        "tactic_id"  : "TA0040",
        "url"        : "https://attack.mitre.org/techniques/T1496/001/",
        "description": (
            "Adversaries may use compute resources for tasks such as "
            "cryptocurrency mining. This sub-technique specifically covers "
            "CPU/GPU compute hijacking as opposed to network bandwidth hijacking."
        ),
        "detection_signals": [
            "CPU utilisation >75% sustained for >30 seconds",
            "Memory footprint consistent with RandomX dataset (~2GB)",
            "Per-core CPU std deviation indicating uneven mining load",
        ],
        "mitigations": [
            "M1038 — Execution Prevention",
            "M1031 — Network Intrusion Prevention",
        ],
        "severity"   : "HIGH",
        "confidence_weight": 0.85,
    },
}

# ──────────────────────────────────────────────────────────────────
# MAPPING ENGINE
# Maps a detection event to relevant ATT&CK techniques
# ──────────────────────────────────────────────────────────────────

def map_to_attack(features: dict, confidence: float) -> list:
    """
    Given system features and model confidence, return a list of
    relevant ATT&CK techniques with evidence notes.

    Args:
        features   : dict of system features from collect_features()
        confidence : float 0-100, model's cryptojacking confidence

    Returns:
        list of dicts, each containing technique + evidence
    """
    mapped = []

    cpu_total   = features.get("cpu_total_percent", 0)
    mem_pct     = features.get("memory_percent", 0)
    mem_avail   = features.get("memory_available_mb", 9999)
    net_sent    = features.get("net_bytes_sent_delta", 0)
    spike_dur   = features.get("cpu_spike_duration_sec", 0)
    miner_det   = features.get("miner_process_detected", 0)
    pool_conn   = features.get("mining_pool_connection", 0)
    top_cpu     = features.get("top_process_cpu_percent", 0)

    # ── T1496 / T1496.001 — Resource Hijacking ──────────────────
    # Always map if confidence >= 50
    if confidence >= 50:
        evidence = []
        if cpu_total > 75:
            evidence.append(f"CPU at {cpu_total:.1f}% (threshold: 75%)")
        if mem_pct > 60:
            evidence.append(f"Memory at {mem_pct:.1f}% — consistent with RandomX dataset")
        if spike_dur > 10:
            evidence.append(f"Sustained CPU spike for {spike_dur:.0f}s")
        if miner_det:
            evidence.append("Known miner process name detected in process list")

        mapped.append({
            "technique" : ATTACK_TECHNIQUES["T1496"],
            "sub"       : ATTACK_TECHNIQUES["T1496.001"],
            "evidence"  : evidence or ["Behavioural pattern consistent with compute hijacking"],
            "score"     : min(confidence * ATTACK_TECHNIQUES["T1496"]["confidence_weight"], 100),
        })

    # ── T1059 — Command and Scripting Interpreter ────────────────
    # Map if miner process is detected (it was executed somehow)
    if miner_det:
        mapped.append({
            "technique" : ATTACK_TECHNIQUES["T1059"],
            "sub"       : None,
            "evidence"  : [
                "Miner process detected — likely executed via shell script or command line",
                f"Top process CPU: {top_cpu:.1f}%",
            ],
            "score"     : confidence * ATTACK_TECHNIQUES["T1059"]["confidence_weight"],
        })

    # ── T1036 — Masquerading ─────────────────────────────────────
    # Map if high CPU but miner name NOT in known list (could be renamed)
    if cpu_total > 75 and not miner_det and confidence >= 60:
        mapped.append({
            "technique" : ATTACK_TECHNIQUES["T1036"],
            "sub"       : None,
            "evidence"  : [
                "High CPU consumption without matching known miner process name",
                "Possible process name masquerading or renamed binary",
                f"CPU: {cpu_total:.1f}% with no identifiable miner process",
            ],
            "score"     : confidence * ATTACK_TECHNIQUES["T1036"]["confidence_weight"],
        })

    # ── T1571 — Non-Standard Port ────────────────────────────────
    # Map if network traffic detected (mining pool communication)
    if net_sent > 2048 or pool_conn:   # >2KB outbound or pool connection flag
        evidence = []
        if pool_conn:
            evidence.append("Direct connection to known mining pool endpoint detected")
        if net_sent > 2048:
            evidence.append(f"Sustained outbound traffic: {net_sent//1024}KB/s (Stratum protocol pattern)")
        mapped.append({
            "technique" : ATTACK_TECHNIQUES["T1571"],
            "sub"       : None,
            "evidence"  : evidence,
            "score"     : confidence * ATTACK_TECHNIQUES["T1571"]["confidence_weight"],
        })

    # ── T1053 — Scheduled Task/Job ───────────────────────────────
    # Map only at high confidence — persistence is implied
    if confidence >= 85:
        mapped.append({
            "technique" : ATTACK_TECHNIQUES["T1053"],
            "sub"       : None,
            "evidence"  : [
                "High-confidence sustained attack — persistence mechanism likely",
                "Recommend checking crontab and systemd services for miner entries",
            ],
            "score"     : confidence * ATTACK_TECHNIQUES["T1053"]["confidence_weight"],
        })

    # Sort by score descending
    mapped.sort(key=lambda x: x["score"], reverse=True)
    return mapped


def format_attack_summary(mapped_techniques: list) -> str:
    """Returns a short string summary for dashboard alerts."""
    if not mapped_techniques:
        return ""
    techs = [m["technique"]["id"] for m in mapped_techniques]
    return " | ".join(techs)


def get_highest_severity(mapped_techniques: list) -> str:
    """Returns the highest severity across all mapped techniques."""
    order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    if not mapped_techniques:
        return "LOW"
    severities = [m["technique"]["severity"] for m in mapped_techniques]
    return max(severities, key=lambda s: order.get(s, 0))


# ──────────────────────────────────────────────────────────────────
# NAVIGATOR HEATMAP GENERATOR
# Produces ATT&CK Navigator layer JSON
# ──────────────────────────────────────────────────────────────────

def generate_navigator_layer(detection_events: list) -> dict:
    """
    Generate an ATT&CK Navigator layer JSON from a list of detection events.

    detection_events: list of dicts with keys:
        { "techniques": [...mapped techniques...], "confidence": float }

    Returns a dict that can be saved as JSON and loaded into
    https://mitre-attack.github.io/attack-navigator/
    """

    # Count how many times each technique was triggered
    technique_counts = {}
    for event in detection_events:
        for m in event.get("techniques", []):
            tid = m["technique"]["id"]
            technique_counts[tid] = technique_counts.get(tid, 0) + 1

    # Build navigator technique entries
    techniques = []
    max_count  = max(technique_counts.values()) if technique_counts else 1

    for tid, count in technique_counts.items():
        tech = ATTACK_TECHNIQUES.get(tid)
        if not tech:
            continue

        # Score 0-100 based on detection frequency
        score = round((count / max_count) * 100)

        techniques.append({
            "techniqueID" : tid,
            "tactic"      : tech["tactic"].lower().replace(" ", "-"),
            "score"       : score,
            "color"       : "",
            "comment"     : f"Detected {count} time(s). {tech['description'][:100]}...",
            "enabled"     : True,
            "metadata"    : [
                { "name": "detections", "value": str(count) },
                { "name": "severity",   "value": tech["severity"] },
                { "name": "tool",       "value": "CryptoGuard" },
            ],
            "links"       : [{ "label": "ATT&CK", "url": tech["url"] }],
            "showSubtechniques": True,
        })

    layer = {
        "name"        : "CryptoGuard — Cryptojacking Detection",
        "versions"    : { "attack": "14", "navigator": "4.9", "layer": "4.5" },
        "domain"      : "enterprise-attack",
        "description" : (
            f"ATT&CK techniques observed by CryptoGuard. "
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}. "
            f"Total detections: {len(detection_events)}."
        ),
        "filters"     : {
            "platforms": ["Linux", "Windows", "macOS"]
        },
        "sorting"     : 3,
        "layout"      : {
            "layout"          : "side",
            "aggregateFunction": "max",
            "showID"          : True,
            "showName"        : True,
            "showAggregateScores": True,
            "countUnscored"   : False,
        },
        "hideDisabled": False,
        "techniques"  : techniques,
        "gradient"    : {
            "colors"  : ["#ffffff", "#d29922", "#f85149"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems" : [
            { "label": "Low frequency",    "color": "#d29922" },
            { "label": "High frequency",   "color": "#f85149" },
        ],
        "metadata"    : [
            { "name": "tool",    "value": "CryptoGuard" },
            { "name": "version", "value": "2.0" },
            { "name": "author",  "value": "CK" },
        ],
        "links"       : [],
        "showTacticRowBackground": True,
        "tacticRowBackground"    : "#161b22",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "expandedSubtechniques"        : "annotated",
    }

    return layer
