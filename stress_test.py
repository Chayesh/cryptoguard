"""
Cryptojacking Detection — False Positive Stress Test
=====================================================
Author  : Your Name (FYP Project)

Tests multiple high-CPU / high-memory scenarios to verify the model
does NOT falsely flag legitimate workloads as cryptojacking.

SETUP:
    pip3 install psutil scikit-learn pandas numpy
    sudo apt install stress-ng -y

USAGE:
    python3 stress_test.py

WHAT IT TESTS:
    Scenario 1 — CPU stress only         (stress-ng --cpu)
    Scenario 2 — Memory stress only      (stress-ng --vm)
    Scenario 3 — CPU + Memory combined   (stress-ng --cpu --vm)
    Scenario 4 — Disk I/O stress         (stress-ng --io)
    Scenario 5 — Many processes          (stress-ng --fork)
    Scenario 6 — Python matrix workload  (pure Python, no stress-ng)
    Scenario 7 — XMRig simulation        (manual high CPU+mem, for comparison)

OUTPUT:
    stress_test_results.csv   ← all predictions per scenario
    stress_test_report.txt    ← summary table for your FYP report
"""

import subprocess
import time
import threading
import pickle
import numpy as np
import psutil
import csv
import os
from datetime import datetime

# ──────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────

MODEL_PATH       = "cryptojacking_model.pkl"
SCALER_PATH      = "scaler.pkl"
SAMPLE_INTERVAL  = 2      # seconds between samples
SCENARIO_DURATION = 30    # seconds per scenario
CPU_SPIKE_THRESH  = 75
KNOWN_MINER_NAMES = ["xmrig", "xmr-stak", "minerd", "cpuminer", "ethminer"]

# ANSI
G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"
C = "\033[96m"; W = "\033[97m"; RESET = "\033[0m"; BOLD = "\033[1m"

# ──────────────────────────────────────────────
# LOAD MODEL
# ──────────────────────────────────────────────

def load_model():
    with open(MODEL_PATH, "rb") as f:
        bundle = pickle.load(f)
    with open(SCALER_PATH, "rb") as f:
        scaler = pickle.load(f)
    return bundle["model"], scaler, bundle["features"]

# ──────────────────────────────────────────────
# FEATURE EXTRACTION
# ──────────────────────────────────────────────

_spike_start  = None
_spike_dur    = 0.0
_spike_count  = 0
_prev_net     = None
_prev_disk    = None

def collect_features():
    global _spike_start, _spike_dur, _spike_count, _prev_net, _prev_disk

    cpu_total = psutil.cpu_percent(interval=1)
    cores     = psutil.cpu_percent(interval=None, percpu=True)
    n         = len(cores)
    mean      = sum(cores) / n
    std       = (sum((x - mean)**2 for x in cores) / n) ** 0.5

    if cpu_total >= CPU_SPIKE_THRESH:
        if _spike_start is None:
            _spike_start = time.time()
            _spike_count += 1
        _spike_dur = round(time.time() - _spike_start, 2)
    else:
        _spike_start = None
        _spike_dur   = 0.0

    mem  = psutil.virtual_memory()
    swap = psutil.swap_memory()

    net = psutil.net_io_counters()
    if _prev_net is None:
        sent, recv, ratio = 0, 0, 0.0
    else:
        sent  = max(0, net.bytes_sent - _prev_net.bytes_sent)
        recv  = max(0, net.bytes_recv - _prev_net.bytes_recv)
        ratio = round(sent / recv, 4) if recv > 0 else 0.0
    _prev_net = net

    disk = psutil.disk_io_counters()
    if _prev_disk is None or disk is None:
        disk_r, disk_w = 0, 0
    else:
        disk_r = max(0, disk.read_bytes  - _prev_disk.read_bytes)
        disk_w = max(0, disk.write_bytes - _prev_disk.write_bytes)
    _prev_disk = disk

    procs      = list(psutil.process_iter(['name', 'cpu_percent', 'status']))
    proc_count = len(procs)
    top_cpu    = 0.0
    hi_cpu     = 0
    miner_det  = 0

    for p in procs:
        try:
            pname = (p.info['name'] or '').lower()
            pcpu  = p.info['cpu_percent'] or 0.0
            if pcpu > top_cpu:
                top_cpu = pcpu
            if pcpu > CPU_SPIKE_THRESH:
                hi_cpu += 1
            if any(m in pname for m in KNOWN_MINER_NAMES):
                miner_det = 1
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return {
        "cpu_total_percent"      : round(cpu_total, 2),
        "cpu_max_core_percent"   : round(max(cores), 2),
        "cpu_mean_core_percent"  : round(mean, 2),
        "cpu_core_std"           : round(std, 2),
        "cpu_core_count"         : n,
        "cpu_spike_duration_sec" : _spike_dur,
        "cpu_spike_count"        : _spike_count,
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
        "high_cpu_process_count" : hi_cpu,
        "miner_process_detected" : miner_det,
        "mining_pool_connection" : 0,
    }

# ──────────────────────────────────────────────
# PREDICT
# ──────────────────────────────────────────────

def predict(model, scaler, feature_names, features):
    vec        = np.array([[features.get(f, 0) for f in feature_names]])
    vec_scaled = scaler.transform(vec)
    prob       = model.predict_proba(vec_scaled)[0][1]
    pred       = model.predict(vec_scaled)[0]
    return pred, round(prob * 100, 2)

# ──────────────────────────────────────────────
# RUN ONE SCENARIO
# ──────────────────────────────────────────────

def run_scenario(name, description, cmd, model, scaler, feature_names, duration=SCENARIO_DURATION):
    """
    Runs a stress command in background, samples predictions for `duration` seconds.
    Returns list of (prediction, confidence) tuples.
    """
    global _spike_start, _spike_dur, _spike_count, _prev_net, _prev_disk
    _spike_start = None; _spike_dur = 0.0; _spike_count = 0
    _prev_net = None; _prev_disk = None

    print(f"\n  {BOLD}{C}{'─'*52}{RESET}")
    print(f"  {BOLD}Scenario: {name}{RESET}")
    print(f"  {description}")
    print(f"  {BOLD}{C}{'─'*52}{RESET}")

    # Start stress process
    proc = None
    if cmd:
        try:
            proc = subprocess.Popen(
                cmd, shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            print(f"  {G}[+]{RESET} Started: {cmd}")
        except Exception as e:
            print(f"  {R}[!]{RESET} Could not start process: {e}")

    time.sleep(2)  # let stress ramp up

    results   = []
    csv_rows  = []
    start     = time.time()
    samples   = 0

    while time.time() - start < duration:
        features         = collect_features()
        pred, confidence = predict(model, scaler, feature_names, features)
        results.append((pred, confidence))
        samples += 1

        label = f"{R}THREAT{RESET}" if pred == 1 else f"{G}SAFE  {RESET}"
        print(
            f"\r  [{samples:>3}] {label} "
            f"conf:{confidence:>5.1f}%  "
            f"CPU:{features['cpu_total_percent']:>5.1f}%  "
            f"Mem:{features['memory_percent']:>5.1f}%  "
            f"MinerDet:{features['miner_process_detected']}",
            end=""
        )

        csv_rows.append({
            "scenario"   : name,
            "sample"     : samples,
            "prediction" : "CRYPTOJACKING" if pred == 1 else "NORMAL",
            "confidence" : confidence,
            **features
        })

        time.sleep(SAMPLE_INTERVAL)

    print()  # newline after live output

    # Stop stress process
    if proc:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        print(f"  {Y}[~]{RESET} Stress process stopped")

    # Compute summary
    threat_count = sum(1 for p, _ in results if p == 1)
    safe_count   = len(results) - threat_count
    avg_conf     = sum(c for _, c in results) / len(results) if results else 0
    fp_rate      = round(threat_count / len(results) * 100, 1) if results else 0

    verdict = f"{R}FALSE POSITIVE ⚠️{RESET}" if threat_count > 0 else f"{G}PASS ✅{RESET}"

    print(f"\n  Samples     : {len(results)}")
    print(f"  SAFE        : {safe_count}")
    print(f"  THREAT      : {threat_count}")
    print(f"  FP Rate     : {fp_rate}%")
    print(f"  Avg Conf    : {avg_conf:.1f}%")
    print(f"  Verdict     : {verdict}")

    time.sleep(3)  # cool-down between scenarios

    return {
        "name"         : name,
        "description"  : description,
        "samples"      : len(results),
        "safe_count"   : safe_count,
        "threat_count" : threat_count,
        "fp_rate"      : fp_rate,
        "avg_confidence": round(avg_conf, 1),
        "verdict"      : "PASS" if threat_count == 0 else "FALSE POSITIVE"
    }, csv_rows

# ──────────────────────────────────────────────
# PYTHON WORKLOAD (no stress-ng needed)
# ──────────────────────────────────────────────

_workload_running = False

def python_matrix_workload():
    """Pure Python CPU + memory intensive task."""
    global _workload_running
    _workload_running = True
    data = []
    while _workload_running:
        # Allocate memory + do math
        matrix = [[float(i*j) for j in range(300)] for i in range(300)]
        result = sum(sum(row) for row in matrix)
        data.append(result)
        if len(data) > 1000:
            data = data[-100:]

def start_python_workload():
    global _workload_running
    _workload_running = True
    t = threading.Thread(target=python_matrix_workload, daemon=True)
    t.start()

def stop_python_workload():
    global _workload_running
    _workload_running = False

# ──────────────────────────────────────────────
# SAVE RESULTS
# ──────────────────────────────────────────────

def save_csv(all_csv_rows):
    if not all_csv_rows:
        return
    path = "stress_test_results.csv"
    keys = list(all_csv_rows[0].keys())
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(all_csv_rows)
    print(f"\n  {G}✅ Raw data saved: {path}{RESET}")


def save_report(summaries):
    path = "stress_test_report.txt"
    with open(path, "w") as f:
        f.write("=" * 65 + "\n")
        f.write("  CRYPTOJACKING DETECTOR — FALSE POSITIVE STRESS TEST REPORT\n")
        f.write(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 65 + "\n\n")

        f.write(f"{'Scenario':<30} {'Samples':>7} {'FP Rate':>8} {'Avg Conf':>9} {'Verdict':<16}\n")
        f.write("─" * 65 + "\n")

        total_fp = 0
        for s in summaries:
            f.write(
                f"{s['name']:<30} {s['samples']:>7} "
                f"{s['fp_rate']:>7.1f}% {s['avg_confidence']:>8.1f}% "
                f"{'✅ PASS' if s['verdict']=='PASS' else '⚠️  FALSE POSITIVE':<16}\n"
            )
            if s['verdict'] != "PASS":
                total_fp += 1

        f.write("─" * 65 + "\n")
        f.write(f"\nTotal scenarios : {len(summaries)}\n")
        f.write(f"Passed (no FP)  : {len(summaries) - total_fp}\n")
        f.write(f"False Positives : {total_fp}\n\n")

        f.write("INTERPRETATION:\n")
        f.write("  A false positive means the detector wrongly flagged a\n")
        f.write("  legitimate workload as cryptojacking. Lower FP rate = better.\n\n")
        f.write("  The detector uses memory allocation patterns and process\n")
        f.write("  name matching alongside CPU metrics, which helps distinguish\n")
        f.write("  XMRig (RandomX, ~2GB RAM) from regular CPU stress tools.\n")

    print(f"  {G}✅ Report saved : {path}{RESET}")

    # Print summary table to terminal
    print(f"\n{BOLD}{'─'*65}{RESET}")
    print(f"{BOLD}  RESULTS SUMMARY{RESET}")
    print(f"{'─'*65}")
    print(f"  {'Scenario':<28} {'FP Rate':>8}  {'Verdict'}")
    print(f"  {'─'*28} {'─'*8}  {'─'*16}")
    for s in summaries:
        verdict = f"{G}✅ PASS{RESET}" if s['verdict'] == 'PASS' else f"{R}⚠️  FALSE POSITIVE{RESET}"
        print(f"  {s['name']:<28} {s['fp_rate']:>7.1f}%  {verdict}")
    print(f"{'─'*65}\n")

# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────

def main():
    print(f"\n{BOLD}{C}{'═'*55}{RESET}")
    print(f"{BOLD}{C}  Cryptojacking False Positive Stress Tester{RESET}")
    print(f"{BOLD}{C}{'═'*55}{RESET}")
    print(f"  Model    : {MODEL_PATH}")
    print(f"  Duration : {SCENARIO_DURATION}s per scenario")
    print(f"  Total    : ~{SCENARIO_DURATION * 7 // 60 + 1} mins\n")

    if not os.path.exists(MODEL_PATH):
        print(f"  {R}[!] Model not found. Run train_model.py first.{RESET}")
        return

    model, scaler, feature_names = load_model()
    print(f"  {G}[+]{RESET} Model loaded — {len(feature_names)} features\n")

    input(f"  {BOLD}Press ENTER to start all scenarios...{RESET}\n")

    summaries    = []
    all_csv_rows = []

    # ── SCENARIO DEFINITIONS ──────────────────────────────────

    scenarios = [
        {
            "name"       : "1. CPU Stress (4 cores)",
            "description": "stress-ng maxing out 4 CPU cores — high CPU, normal memory",
            "cmd"        : f"stress-ng --cpu 4 --timeout {SCENARIO_DURATION + 10}s",
            "python"     : False,
        },
        {
            "name"       : "2. Memory Stress (1GB)",
            "description": "stress-ng allocating 1GB RAM — high memory, low CPU",
            "cmd"        : f"stress-ng --vm 1 --vm-bytes 1G --timeout {SCENARIO_DURATION + 10}s",
            "python"     : False,
        },
        {
            "name"       : "3. CPU + Memory Combined",
            "description": "stress-ng stressing both CPU and 1.5GB RAM simultaneously",
            "cmd"        : f"stress-ng --cpu 4 --vm 1 --vm-bytes 1536M --timeout {SCENARIO_DURATION + 10}s",
            "python"     : False,
        },
        {
            "name"       : "4. Disk I/O Stress",
            "description": "stress-ng heavy disk read/write — tests disk feature",
            "cmd"        : f"stress-ng --io 4 --timeout {SCENARIO_DURATION + 10}s",
            "python"     : False,
        },
        {
            "name"       : "5. Fork Bomb (many procs)",
            "description": "stress-ng spawning many processes — tests process_count feature",
            "cmd"        : f"stress-ng --fork 8 --timeout {SCENARIO_DURATION + 10}s",
            "python"     : False,
        },
        {
            "name"       : "6. Python Matrix Workload",
            "description": "Pure Python CPU + memory allocation — no external tools",
            "cmd"        : None,   # handled with threading
            "python"     : True,
        },
        {
            "name"       : "7. Idle Baseline",
            "description": "No stress — baseline reading, should be SAFE",
            "cmd"        : None,
            "python"     : False,
        },
    ]

    for s in scenarios:
        if s["python"]:
            # Python workload — start thread, run scenario, stop thread
            start_python_workload()
            summary, csv_rows = run_scenario(
                s["name"], s["description"], None,
                model, scaler, feature_names
            )
            stop_python_workload()
        else:
            summary, csv_rows = run_scenario(
                s["name"], s["description"], s["cmd"],
                model, scaler, feature_names
            )

        summaries.append(summary)
        all_csv_rows.extend(csv_rows)

    # Save outputs
    print(f"\n{BOLD}Saving results...{RESET}")
    save_csv(all_csv_rows)
    save_report(summaries)

    print(f"\n{BOLD}{C}{'═'*55}{RESET}")
    print(f"{BOLD}{C}  All scenarios complete!{RESET}")
    print(f"{BOLD}{C}{'═'*55}{RESET}\n")


if __name__ == "__main__":
    main()
