"""
Cryptojacking Detection — Data Collector (Kali Linux / VMware)
==============================================================
Author  : Your Name (FYP Project)
Version : 1.0

SETUP:
    sudo apt update
    sudo apt install python3-pip lm-sensors -y
    sudo sensors-detect --auto          # enable temp sensors
    pip3 install psutil

USAGE:
    # Normal activity (browse, idle, compile etc.)
    python3 collect_data_linux.py --label 0 --session "idle" --duration 2700 --output dataset.csv

    # Attack — XMRig running in another terminal
    python3 collect_data_linux.py --label 1 --session "xmrig_6t" --duration 1800 --output dataset.csv

    # Merge all CSVs later:
    python3 collect_data_linux.py --merge normal.csv attack.csv --output full_dataset.csv

SESSIONS (recommended names):
    Label 0: "idle", "browsing", "compiling"
    Label 1: "xmrig_1t", "xmrig_3t", "xmrig_6t"
"""

import psutil
import csv
import time
import argparse
import os
import sys
import subprocess
from datetime import datetime

# ──────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────
SAMPLE_INTERVAL    = 2      # seconds between samples
CPU_SPIKE_THRESH   = 75     # % above which we count as a spike
HIGH_NET_THRESH    = 50000  # bytes/s — above this = high network activity

KNOWN_MINER_NAMES  = [
    "xmrig", "xmr-stak", "minerd", "cpuminer",
    "ethminer", "nbminer", "gminer", "cryptonight", "ccminer"
]
MINING_POOL_IPS    = [
    "pool", "minexmr", "nanopool", "supportxmr",
    "moneroocean", "hashvault", "2miners", "f2pool"
]

# ANSI colors for terminal output
R  = "\033[91m"   # red
G  = "\033[92m"   # green
Y  = "\033[93m"   # yellow
B  = "\033[94m"   # blue
C  = "\033[96m"   # cyan
W  = "\033[97m"   # white
DIM = "\033[2m"
RESET = "\033[0m"
BOLD  = "\033[1m"

# ──────────────────────────────────────────────
# FEATURE COLLECTION
# ──────────────────────────────────────────────

def get_cpu_features():
    """Overall + per-core CPU usage stats."""
    cpu_total = psutil.cpu_percent(interval=1)
    cores     = psutil.cpu_percent(interval=None, percpu=True)
    n         = len(cores)
    mean      = sum(cores) / n
    std       = (sum((x - mean) ** 2 for x in cores) / n) ** 0.5
    return (
        round(cpu_total, 2),
        round(max(cores), 2),
        round(mean, 2),
        round(std, 2),
        n
    )


def get_memory_features():
    """RAM + swap usage."""
    mem  = psutil.virtual_memory()
    swap = psutil.swap_memory()
    return (
        round(mem.percent, 2),
        mem.available // (1024 * 1024),
        round(swap.percent, 2)
    )


def get_network_features(prev_net):
    """Delta bytes sent/received since last sample."""
    net = psutil.net_io_counters()
    if prev_net is None:
        return 0, 0, 0, net
    sent  = max(0, net.bytes_sent - prev_net.bytes_sent)
    recv  = max(0, net.bytes_recv - prev_net.bytes_recv)
    ratio = round(sent / recv, 4) if recv > 0 else 0.0
    return sent, recv, ratio, net


def get_disk_features(prev_disk):
    """Disk read/write delta — miners have low disk I/O."""
    disk = psutil.disk_io_counters()
    if prev_disk is None or disk is None:
        return 0, 0, disk
    read  = max(0, disk.read_bytes  - prev_disk.read_bytes)
    write = max(0, disk.write_bytes - prev_disk.write_bytes)
    return read, write, disk


def get_process_features():
    """
    Process-level features:
    - Total process count
    - Top CPU consuming process %
    - Miner process name match
    - Mining pool connection detected
    - Number of processes above CPU threshold
    """
    procs = list(psutil.process_iter(
    ['name', 'cpu_percent', 'status']
    ))

    count          = len(procs)
    top_cpu        = 0.0
    high_cpu_procs = 0
    miner_detected = 0
    pool_conn      = 0

    for p in procs:
        try:
            name  = (p.info['name'] or '').lower()
            cpu   = p.info['cpu_percent'] or 0.0

            if cpu > top_cpu:
                top_cpu = cpu
            if cpu > CPU_SPIKE_THRESH:
                high_cpu_procs += 1
            if any(m in name for m in KNOWN_MINER_NAMES):
                miner_detected = 1

            try:
                conns = p.connections()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                conns = []
            for conn in conns:
                if conn.raddr:
                    ip = str(conn.raddr.ip).lower()
                    if any(kw in ip for kw in MINING_POOL_IPS):
                        pool_conn = 1

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return count, round(top_cpu, 2), high_cpu_procs, miner_detected, pool_conn


def get_cpu_temp_linux():
    """
    Read CPU temperature on Linux via psutil sensors or lm-sensors.
    Returns float temp in Celsius, or -1 if unavailable.
    """
    # Method 1: psutil sensors_temperatures (works if lm-sensors is installed)
    try:
        temps = psutil.sensors_temperatures()
        if temps:
            # Priority: coretemp > k10temp (AMD) > acpitz
            for key in ['coretemp', 'k10temp', 'acpitz']:
                if key in temps and temps[key]:
                    return round(temps[key][0].current, 1)
            # fallback: first available
            for entries in temps.values():
                if entries:
                    return round(entries[0].current, 1)
    except Exception:
        pass

    # Method 2: Read directly from /sys/class/thermal
    try:
        with open("/sys/class/thermal/thermal_zone0/temp", "r") as f:
            return round(int(f.read().strip()) / 1000.0, 1)
    except Exception:
        pass

    return -1.0


# ──────────────────────────────────────────────
# SPIKE TRACKER
# ──────────────────────────────────────────────

class SpikeTracker:
    """Tracks continuous CPU spike duration above threshold."""
    def __init__(self, threshold=CPU_SPIKE_THRESH):
        self.threshold    = threshold
        self.spike_start  = None
        self.spike_dur    = 0.0
        self.spike_count  = 0   # how many spikes have occurred total

    def update(self, cpu_pct):
        if cpu_pct >= self.threshold:
            if self.spike_start is None:
                self.spike_start = time.time()
                self.spike_count += 1
            self.spike_dur = round(time.time() - self.spike_start, 2)
        else:
            self.spike_start = None
            self.spike_dur   = 0.0
        return self.spike_dur, self.spike_count


# ──────────────────────────────────────────────
# CSV SETUP
# ──────────────────────────────────────────────

FIELDNAMES = [
    "timestamp",
    "session",
    # CPU
    "cpu_total_percent",
    "cpu_max_core_percent",
    "cpu_mean_core_percent",
    "cpu_core_std",
    "cpu_core_count",
    "cpu_spike_duration_sec",
    "cpu_spike_count",
    "cpu_temp_celsius",
    # Memory
    "memory_percent",
    "memory_available_mb",
    "swap_percent",
    # Network
    "net_bytes_sent_delta",
    "net_bytes_recv_delta",
    "net_sent_recv_ratio",
    # Disk
    "disk_read_delta",
    "disk_write_delta",
    # Process
    "process_count",
    "top_process_cpu_percent",
    "high_cpu_process_count",
    "miner_process_detected",
    "mining_pool_connection",
    # Label
    "label"
]


def init_csv(filepath):
    exists = os.path.isfile(filepath)
    f = open(filepath, 'a', newline='')
    writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
    if not exists:
        writer.writeheader()
    return f, writer


# ──────────────────────────────────────────────
# MERGE UTILITY
# ──────────────────────────────────────────────

def merge_csvs(input_files, output_file):
    print(f"\n{BOLD}Merging {len(input_files)} files → {output_file}{RESET}")
    rows = []
    for fp in input_files:
        if not os.path.isfile(fp):
            print(f"  {R}[!] File not found: {fp}{RESET}")
            continue
        with open(fp, 'r') as f:
            reader = csv.DictReader(f)
            file_rows = list(reader)
            rows.extend(file_rows)
            print(f"  {G}[+]{RESET} {fp} → {len(file_rows)} rows")

    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)

    label_counts = {}
    for r in rows:
        l = r.get('label', '?')
        label_counts[l] = label_counts.get(l, 0) + 1

    print(f"\n  {BOLD}Total rows : {len(rows)}{RESET}")
    for lbl, cnt in sorted(label_counts.items()):
        name = "Normal" if lbl == '0' else "Attack"
        print(f"  Label {lbl} ({name}) : {cnt} rows")
    print(f"\n  {G}✅ Saved to: {output_file}{RESET}\n")


# ──────────────────────────────────────────────
# HEADER DISPLAY
# ──────────────────────────────────────────────

def print_header(label, session, duration, output):
    label_str = f"{G}NORMAL{RESET}" if label == 0 else f"{R}CRYPTOJACKING (ATTACK){RESET}"
    print(f"\n{BOLD}{C}{'─'*58}{RESET}")
    print(f"{BOLD}{C}   Cryptojacking Data Collector — Kali Linux{RESET}")
    print(f"{BOLD}{C}{'─'*58}{RESET}")
    print(f"  Label    : {label_str}")
    print(f"  Session  : {Y}{session}{RESET}")
    print(f"  Duration : {duration}s (~{duration//60} mins)")
    print(f"  Interval : {SAMPLE_INTERVAL}s per sample")
    print(f"  Output   : {output}")
    print(f"  Est rows : ~{duration // SAMPLE_INTERVAL}")
    print(f"{BOLD}{C}{'─'*58}{RESET}")

    if label == 1:
        print(f"\n  {Y}⚠️  Make sure XMRig is already running!{RESET}")
        print(f"  {DIM}Open another terminal and run:{RESET}")
        print(f"  {W}  ./xmrig --benchmark --threads 6{RESET}\n")


# ──────────────────────────────────────────────
# LIVE STATS BAR
# ──────────────────────────────────────────────

def cpu_bar(pct, width=20):
    filled = int(pct / 100 * width)
    color  = G if pct < 60 else (Y if pct < 85 else R)
    bar    = '█' * filled + '░' * (width - filled)
    return f"{color}[{bar}]{RESET} {pct:>5.1f}%"


def print_status(samples, elapsed, remaining, cpu, max_core, spike, sent, recv, temp, label):
    label_tag = f"{G}[NORMAL]{RESET}" if label == 0 else f"{R}[ATTACK]{RESET}"
    bar = cpu_bar(cpu)
    temp_str = f"{temp:.0f}°C" if temp > 0 else " N/A"
    temp_color = G if temp < 75 else (Y if temp < 85 else R)

    sys.stdout.write(
        f"\r  {label_tag} "
        f"#{samples:>4}  "
        f"CPU {bar}  "
        f"MaxCore:{Y}{max_core:>5.1f}%{RESET}  "
        f"Spike:{Y}{spike:>5.1f}s{RESET}  "
        f"↑{sent//1024:>5}KB ↓{recv//1024:>5}KB  "
        f"Temp:{temp_color}{temp_str}{RESET}  "
        f"Left:{W}{int(remaining):>4}s{RESET}  "
    )
    sys.stdout.flush()


# ──────────────────────────────────────────────
# MAIN COLLECTION LOOP
# ──────────────────────────────────────────────

def collect(label, session, duration, output):
    print_header(label, session, duration, output)
    input(f"\n  {BOLD}Press ENTER to start...{RESET}\n")

    f, writer    = init_csv(output)
    spike_tracker = SpikeTracker()
    prev_net     = None
    prev_disk    = None
    samples      = 0
    start        = time.time()

    try:
        while True:
            elapsed   = time.time() - start
            remaining = duration - elapsed
            if remaining <= 0:
                break

            # ── collect all features ──
            cpu_total, cpu_max, cpu_mean, cpu_std, cpu_count = get_cpu_features()
            mem_pct, mem_avail, swap_pct                      = get_memory_features()
            sent, recv, ratio, prev_net                       = get_network_features(prev_net)
            disk_r, disk_w, prev_disk                         = get_disk_features(prev_disk)
            proc_count, top_cpu, hi_cpu, miner, pool          = get_process_features()
            spike_dur, spike_cnt                              = spike_tracker.update(cpu_total)
            temp                                              = get_cpu_temp_linux()

            row = {
                "timestamp"              : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "session"                : session,
                "cpu_total_percent"      : cpu_total,
                "cpu_max_core_percent"   : cpu_max,
                "cpu_mean_core_percent"  : cpu_mean,
                "cpu_core_std"           : cpu_std,
                "cpu_core_count"         : cpu_count,
                "cpu_spike_duration_sec" : spike_dur,
                "cpu_spike_count"        : spike_cnt,
                "cpu_temp_celsius"       : temp,
                "memory_percent"         : mem_pct,
                "memory_available_mb"    : mem_avail,
                "swap_percent"           : swap_pct,
                "net_bytes_sent_delta"   : sent,
                "net_bytes_recv_delta"   : recv,
                "net_sent_recv_ratio"    : ratio,
                "disk_read_delta"        : disk_r,
                "disk_write_delta"       : disk_w,
                "process_count"          : proc_count,
                "top_process_cpu_percent": top_cpu,
                "high_cpu_process_count" : hi_cpu,
                "miner_process_detected" : miner,
                "mining_pool_connection" : pool,
                "label"                  : label
            }

            writer.writerow(row)
            f.flush()
            samples += 1

            print_status(samples, elapsed, remaining,
                         cpu_total, cpu_max, spike_dur,
                         sent, recv, temp, label)

            time.sleep(SAMPLE_INTERVAL)

    except KeyboardInterrupt:
        print(f"\n\n  {Y}[!] Stopped by user.{RESET}")

    finally:
        f.close()
        total_time = round(time.time() - start, 1)
        print(f"\n\n{BOLD}{C}{'─'*58}{RESET}")
        print(f"  {G}✅ Collection complete!{RESET}")
        print(f"  Samples collected : {BOLD}{samples}{RESET}")
        print(f"  Time elapsed      : {total_time}s")
        print(f"  Saved to          : {BOLD}{output}{RESET}")
        print(f"{BOLD}{C}{'─'*58}{RESET}\n")


# ──────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Cryptojacking Data Collector — Kali Linux"
    )
    subparsers = parser.add_subparsers(dest="command")

    # ── collect mode ──
    collect_parser = subparsers.add_parser("collect", help="Collect data")
    collect_parser.add_argument("--label",    type=int, required=True, choices=[0, 1],
                                 help="0=normal, 1=attack")
    collect_parser.add_argument("--session",  type=str, default="default",
                                 help="Session name e.g. idle, xmrig_6t")
    collect_parser.add_argument("--duration", type=int, default=1800,
                                 help="Duration in seconds (default: 1800)")
    collect_parser.add_argument("--output",   type=str, default="dataset.csv",
                                 help="Output CSV file")

    # ── merge mode ──
    merge_parser = subparsers.add_parser("merge", help="Merge multiple CSVs")
    merge_parser.add_argument("--inputs",  nargs="+", required=True,
                               help="Input CSV files to merge")
    merge_parser.add_argument("--output",  type=str, required=True,
                               help="Output merged CSV file")

    # ── default: collect (backward compat with --label etc.) ──
    parser.add_argument("--label",    type=int, choices=[0, 1])
    parser.add_argument("--session",  type=str, default="default")
    parser.add_argument("--duration", type=int, default=1800)
    parser.add_argument("--output",   type=str, default="dataset.csv")
    parser.add_argument("--merge",    nargs="+")

    args = parser.parse_args()

    # handle merge shorthand
    if args.merge:
        merge_csvs(args.merge, args.output)
    elif args.command == "merge":
        merge_csvs(args.inputs, args.output)
    elif args.label is not None:
        collect(args.label, args.session, args.duration, args.output)
    else:
        parser.print_help()
