"""
Cryptojacking Detection — Fix 2: Retrain with Memory-Heavy Normal Data
=======================================================================
Author  : Your Name (FYP Project)

The original model had false positives for memory-heavy legitimate workloads
because normal data was collected only during idle/compiling sessions.

This script:
  1. Guides you to collect NEW normal data with memory-heavy apps running
  2. Merges it with your existing dataset
  3. Retrains the Random Forest with the improved dataset
  4. Compares old vs new model performance

SETUP:
    pip3 install pandas scikit-learn matplotlib seaborn imbalanced-learn
    sudo apt install stress-ng firefox -y

USAGE:
    # Step 1: Collect new memory-heavy normal data (run this first)
    python3 retrain_fix2.py --collect --output memory_heavy_normal.csv

    # Step 2: Retrain with all data combined
    python3 retrain_fix2.py --retrain \
        --original full_dataset.csv \
        --new memory_heavy_normal.csv \
        --output improved_dataset.csv
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import argparse
import os
import pickle
import time
import csv
import sys
import subprocess
import warnings
warnings.filterwarnings("ignore")

from sklearn.ensemble        import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.preprocessing   import StandardScaler
from sklearn.metrics         import (
    confusion_matrix, classification_report,
    roc_curve, auc, accuracy_score,
    precision_score, recall_score, f1_score
)
from imblearn.over_sampling  import SMOTE

# ──────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────

RANDOM_STATE     = 42
TEST_SIZE        = 0.2
SAMPLE_INTERVAL  = 2
CPU_SPIKE_THRESH = 75
KNOWN_MINER_NAMES = ["xmrig", "xmr-stak", "minerd", "cpuminer", "ethminer"]

OLD_MODEL_PATH   = "cryptojacking_model.pkl"
OLD_SCALER_PATH  = "scaler.pkl"
NEW_MODEL_PATH   = "cryptojacking_model_v2.pkl"
NEW_SCALER_PATH  = "scaler_v2.pkl"
RESULTS_DIR      = "results_v2"

# ANSI
G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"
C = "\033[96m"; W = "\033[97m"; RESET = "\033[0m"; BOLD = "\033[1m"

import psutil

# ──────────────────────────────────────────────
# FEATURE COLLECTION (same as collect_data_linux.py)
# ──────────────────────────────────────────────

_spike_start = None
_spike_dur   = 0.0
_spike_count = 0
_prev_net    = None
_prev_disk   = None

FIELDNAMES = [
    "timestamp", "session",
    "cpu_total_percent", "cpu_max_core_percent", "cpu_mean_core_percent",
    "cpu_core_std", "cpu_core_count", "cpu_spike_duration_sec", "cpu_spike_count",
    "cpu_temp_celsius", "memory_percent", "memory_available_mb", "swap_percent",
    "net_bytes_sent_delta", "net_bytes_recv_delta", "net_sent_recv_ratio",
    "disk_read_delta", "disk_write_delta", "process_count",
    "top_process_cpu_percent", "high_cpu_process_count",
    "miner_process_detected", "mining_pool_connection", "label"
]

def collect_sample():
    global _spike_start, _spike_dur, _spike_count, _prev_net, _prev_disk

    cpu_total = psutil.cpu_percent(interval=1)
    cores     = psutil.cpu_percent(interval=None, percpu=True)
    n         = len(cores)
    mean      = sum(cores) / n
    std       = (sum((x - mean)**2 for x in cores) / n) ** 0.5

    if cpu_total >= CPU_SPIKE_THRESH:
        if _spike_start is None:
            _spike_start = time.time(); _spike_count += 1
        _spike_dur = round(time.time() - _spike_start, 2)
    else:
        _spike_start = None; _spike_dur = 0.0

    mem  = psutil.virtual_memory()
    swap = psutil.swap_memory()
    net  = psutil.net_io_counters()

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
    top_cpu    = 0.0; hi_cpu = 0; miner_det = 0

    for p in procs:
        try:
            pname = (p.info['name'] or '').lower()
            pcpu  = p.info['cpu_percent'] or 0.0
            if pcpu > top_cpu: top_cpu = pcpu
            if pcpu > CPU_SPIKE_THRESH: hi_cpu += 1
            if any(m in pname for m in KNOWN_MINER_NAMES): miner_det = 1
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # Temp
    temp = -1.0
    try:
        temps = psutil.sensors_temperatures()
        if temps:
            for key in ['coretemp', 'k10temp', 'acpitz']:
                if key in temps and temps[key]:
                    temp = round(temps[key][0].current, 1); break
    except Exception:
        pass

    from datetime import datetime
    return {
        "timestamp"              : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "session"                : "",
        "cpu_total_percent"      : round(cpu_total, 2),
        "cpu_max_core_percent"   : round(max(cores), 2),
        "cpu_mean_core_percent"  : round(mean, 2),
        "cpu_core_std"           : round(std, 2),
        "cpu_core_count"         : n,
        "cpu_spike_duration_sec" : _spike_dur,
        "cpu_spike_count"        : _spike_count,
        "cpu_temp_celsius"       : temp,
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
        "label"                  : 0   # always 0 — this is normal data
    }


# ──────────────────────────────────────────────
# FIX 2 — COLLECT MEMORY-HEAVY NORMAL DATA
# ──────────────────────────────────────────────

MEMORY_SESSIONS = [
    {
        "name"    : "stress_1gb",
        "label"   : "Memory stress 1GB (stress-ng)",
        "cmd"     : "stress-ng --vm 1 --vm-bytes 1G --timeout 700s",
        "duration": 600,
        "note"    : "This simulates video editing / large app memory usage"
    },
    {
        "name"    : "stress_cpu_mem",
        "label"   : "CPU + Memory combined (stress-ng)",
        "cmd"     : "stress-ng --cpu 4 --vm 1 --vm-bytes 1536M --timeout 700s",
        "duration": 600,
        "note"    : "This is the hardest false positive case — train on it!"
    },
    {
        "name"    : "stress_1_5gb",
        "label"   : "Memory stress 1.5GB (stress-ng)",
        "cmd"     : "stress-ng --vm 1 --vm-bytes 1536M --timeout 400s",
        "duration": 300,
        "note"    : "Higher memory allocation — pushes the boundary"
    },
]


def collect_session(session, output_path):
    global _spike_start, _spike_dur, _spike_count, _prev_net, _prev_disk
    _spike_start = None; _spike_dur = 0.0; _spike_count = 0
    _prev_net = None; _prev_disk = None

    print(f"\n  {BOLD}{C}{'─'*52}{RESET}")
    print(f"  {BOLD}Session: {session['label']}{RESET}")
    print(f"  {Y}{session['note']}{RESET}")
    print(f"  Duration : {session['duration']}s (~{session['duration']//60} mins)")
    print(f"  {BOLD}{C}{'─'*52}{RESET}\n")

    input(f"  {BOLD}Press ENTER to start...{RESET}\n")

    # Start stress process
    proc = None
    if session["cmd"]:
        proc = subprocess.Popen(
            session["cmd"], shell=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        print(f"  {G}[+]{RESET} Stress started: {session['cmd'][:60]}...")
        time.sleep(3)  # ramp up

    # Open CSV
    file_exists = os.path.isfile(output_path)
    f = open(output_path, 'a', newline='')
    writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
    if not file_exists:
        writer.writeheader()

    samples = 0
    start   = time.time()

    try:
        while time.time() - start < session["duration"]:
            sample = collect_sample()
            sample["session"] = session["name"]
            writer.writerow(sample)
            f.flush()
            samples += 1

            remaining = session["duration"] - (time.time() - start)
            sys.stdout.write(
                f"\r  {G}[NORMAL]{RESET} #{samples:>4}  "
                f"CPU:{sample['cpu_total_percent']:>5.1f}%  "
                f"Mem:{sample['memory_percent']:>5.1f}%  "
                f"MemAvail:{sample['memory_available_mb']:>5}MB  "
                f"Left:{int(remaining):>4}s  "
            )
            sys.stdout.flush()
            time.sleep(SAMPLE_INTERVAL)

    except KeyboardInterrupt:
        print(f"\n  {Y}[!] Interrupted{RESET}")
    finally:
        f.close()
        if proc:
            proc.terminate()
            try: proc.wait(timeout=5)
            except: proc.kill()

    print(f"\n  {G}✅ {samples} samples collected → {output_path}{RESET}")
    time.sleep(3)
    return samples


def run_collect(output):
    print(f"\n{BOLD}{C}{'═'*55}{RESET}")
    print(f"{BOLD}{C}  Fix 2 — Memory-Heavy Normal Data Collection{RESET}")
    print(f"{BOLD}{C}{'═'*55}{RESET}")
    print(f"""
  WHY WE'RE DOING THIS:
  Your original normal data was idle + compiling sessions.
  The model never saw high-memory legitimate apps, so it
  flagged them as cryptojacking.

  We'll now collect normal data while stress-ng simulates
  memory-heavy workloads (video editors, browsers, VMs).
  This teaches the model: "high memory alone ≠ mining."

  Sessions to collect:
    1. Memory stress 1GB          (~10 mins)
    2. CPU + Memory combined      (~10 mins)
    3. Memory stress 1.5GB        (~5 mins)

  Total: ~25 mins
""")
    input(f"  {BOLD}Press ENTER to begin...{RESET}\n")

    total = 0
    for session in MEMORY_SESSIONS:
        n = collect_session(session, output)
        total += n

    print(f"\n{BOLD}{G}✅ Collection complete! Total new samples: {total}{RESET}")
    print(f"   Saved to: {output}\n")


# ──────────────────────────────────────────────
# RETRAIN
# ──────────────────────────────────────────────

DROP_COLS = ["timestamp", "session", "label"]


def load_and_merge(original_path, new_path, output_path):
    print(f"\n{BOLD}{'─'*52}{RESET}")
    print(f"{BOLD}  Merging datasets{RESET}")
    print(f"{'─'*52}")

    df_orig = pd.read_csv(original_path)
    df_new  = pd.read_csv(new_path)

    print(f"  Original dataset : {len(df_orig)} rows  {dict(df_orig['label'].value_counts().sort_index())}")
    print(f"  New normal data  : {len(df_new)} rows  {dict(df_new['label'].value_counts().sort_index())}")

    df_merged = pd.concat([df_orig, df_new], ignore_index=True)
    df_merged.to_csv(output_path, index=False)

    print(f"  Merged dataset   : {len(df_merged)} rows  {dict(df_merged['label'].value_counts().sort_index())}")
    print(f"  {G}✅ Saved: {output_path}{RESET}")
    return df_merged


def prepare(df):
    drop = [c for c in DROP_COLS if c in df.columns]
    X    = df.drop(columns=drop).select_dtypes(include=[np.number])
    y    = df["label"]

    # Drop cpu_temp if mostly -1
    if "cpu_temp_celsius" in X.columns:
        if (X["cpu_temp_celsius"] == -1).sum() / len(X) > 0.5:
            X = X.drop(columns=["cpu_temp_celsius"])

    X = X.fillna(X.median())
    return X, y


def train(X_train, y_train):
    sm           = SMOTE(random_state=RANDOM_STATE)
    X_res, y_res = sm.fit_resample(X_train, y_train)

    model = RandomForestClassifier(
        n_estimators  = 200,
        max_features  = "sqrt",
        class_weight  = "balanced",
        random_state  = RANDOM_STATE,
        n_jobs        = -1
    )
    model.fit(X_res, y_res)
    return model, X_res, y_res


def evaluate_model(model, X_test, y_test, X_train, y_train, label="Model"):
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec  = recall_score(y_test, y_pred, zero_division=0)
    f1   = f1_score(y_test, y_pred, zero_division=0)

    cv      = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
    cv_f1   = cross_val_score(model, X_train, y_train, cv=cv, scoring="f1")

    fpr, tpr, _ = roc_curve(y_test, y_prob)
    roc_auc     = auc(fpr, tpr)

    print(f"\n  {BOLD}{label}{RESET}")
    print(f"  Accuracy  : {acc*100:.2f}%")
    print(f"  Precision : {prec*100:.2f}%")
    print(f"  Recall    : {rec*100:.2f}%")
    print(f"  F1        : {f1*100:.2f}%")
    print(f"  AUC       : {roc_auc:.4f}")
    print(f"  CV F1     : {cv_f1.mean():.3f} ± {cv_f1.std():.3f}")

    return {
        "label"   : label,
        "acc"     : acc, "prec": prec, "rec": rec,
        "f1"      : f1,  "auc" : roc_auc,
        "cv_mean" : cv_f1.mean(), "cv_std": cv_f1.std(),
        "y_pred"  : y_pred, "y_prob": y_prob,
        "fpr"     : fpr, "tpr": tpr,
    }


def plot_comparison(old_res, new_res, feature_names_old, feature_names_new,
                    old_model, new_model, y_test_old, y_test_new):
    os.makedirs(RESULTS_DIR, exist_ok=True)

    plt.rcParams.update({
        "figure.facecolor": "#0d1117", "axes.facecolor": "#161b22",
        "axes.edgecolor": "#30363d", "axes.labelcolor": "#e6edf3",
        "text.color": "#e6edf3", "xtick.color": "#8b949e",
        "ytick.color": "#8b949e", "grid.color": "#21262d",
        "font.family": "monospace",
    })

    # ── Comparison bar chart ──
    fig, axes = plt.subplots(1, 2, figsize=(14, 6))
    fig.suptitle("Model v1 vs v2 — Performance Comparison",
                 fontsize=15, color="#58a6ff", fontweight="bold", y=1.02)

    metrics     = ["Accuracy", "Precision", "Recall", "F1", "AUC"]
    old_vals    = [old_res["acc"], old_res["prec"], old_res["rec"], old_res["f1"], old_res["auc"]]
    new_vals    = [new_res["acc"], new_res["prec"], new_res["rec"], new_res["f1"], new_res["auc"]]
    x           = np.arange(len(metrics))
    width       = 0.35

    ax = axes[0]
    ax.bar(x - width/2, [v*100 for v in old_vals], width, label="v1 (original)", color="#58a6ff", alpha=0.85)
    ax.bar(x + width/2, [v*100 for v in new_vals], width, label="v2 (improved)", color="#3fb950", alpha=0.85)
    ax.set_xticks(x); ax.set_xticklabels(metrics)
    ax.set_ylim(0, 110); ax.set_ylabel("Score (%)")
    ax.set_title("Metrics Comparison", color="#8b949e")
    ax.legend(facecolor="#161b22", edgecolor="#30363d")
    ax.grid(True, axis="y", alpha=0.3)

    # ── ROC curves ──
    ax2 = axes[1]
    ax2.plot(old_res["fpr"], old_res["tpr"], color="#58a6ff", lw=2,
             label=f"v1 (AUC={old_res['auc']:.4f})")
    ax2.plot(new_res["fpr"], new_res["tpr"], color="#3fb950", lw=2,
             label=f"v2 (AUC={new_res['auc']:.4f})")
    ax2.plot([0,1],[0,1], color="#8b949e", lw=1, linestyle="--")
    ax2.set_xlabel("False Positive Rate"); ax2.set_ylabel("True Positive Rate")
    ax2.set_title("ROC Curves", color="#8b949e")
    ax2.legend(facecolor="#161b22", edgecolor="#30363d")
    ax2.grid(True, alpha=0.3)

    plt.tight_layout()
    path = os.path.join(RESULTS_DIR, "v1_vs_v2_comparison.png")
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  {G}✅ Saved: {path}{RESET}")

    # ── Feature importance comparison ──
    fig, axes = plt.subplots(1, 2, figsize=(16, 7))
    fig.suptitle("Feature Importance — v1 vs v2",
                 fontsize=14, color="#58a6ff", fontweight="bold")

    for ax, model, names, title in [
        (axes[0], old_model, feature_names_old, "v1 (Original)"),
        (axes[1], new_model, feature_names_new, "v2 (Improved)"),
    ]:
        imp     = model.feature_importances_
        idx     = np.argsort(imp)
        colors  = ["#f85149" if v >= 0.10 else "#d29922" if v >= 0.05 else "#58a6ff"
                   for v in imp[idx]]
        ax.barh([names[i] for i in idx], imp[idx], color=colors, edgecolor="#21262d")
        ax.set_title(title, color="#8b949e")
        ax.set_xlabel("Importance (Gini)")
        ax.grid(True, axis="x", alpha=0.3)

    plt.tight_layout()
    path2 = os.path.join(RESULTS_DIR, "feature_importance_v1_v2.png")
    plt.savefig(path2, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  {G}✅ Saved: {path2}{RESET}")


def save_new_model(model, scaler, feature_names):
    with open(NEW_MODEL_PATH, "wb") as f:
        pickle.dump({"model": model, "features": feature_names}, f)
    with open(NEW_SCALER_PATH, "wb") as f:
        pickle.dump(scaler, f)
    print(f"  {G}✅ New model saved : {NEW_MODEL_PATH}{RESET}")
    print(f"  {G}✅ New scaler saved: {NEW_SCALER_PATH}{RESET}")


def save_comparison_report(old_res, new_res):
    path = os.path.join(RESULTS_DIR, "v1_vs_v2_report.txt")
    with open(path, "w") as f:
        f.write("=" * 55 + "\n")
        f.write("  MODEL IMPROVEMENT REPORT — v1 vs v2\n")
        f.write("=" * 55 + "\n\n")
        f.write(f"{'Metric':<15} {'v1 (Original)':>15} {'v2 (Improved)':>15} {'Change':>10}\n")
        f.write("─" * 55 + "\n")

        pairs = [
            ("Accuracy",  old_res["acc"],     new_res["acc"]),
            ("Precision", old_res["prec"],    new_res["prec"]),
            ("Recall",    old_res["rec"],      new_res["rec"]),
            ("F1 Score",  old_res["f1"],       new_res["f1"]),
            ("AUC",       old_res["auc"],      new_res["auc"]),
            ("CV F1 Mean",old_res["cv_mean"],  new_res["cv_mean"]),
        ]
        for name, v1, v2 in pairs:
            delta = (v2 - v1) * 100
            sign  = "+" if delta >= 0 else ""
            f.write(f"{name:<15} {v1*100:>14.2f}% {v2*100:>14.2f}% {sign}{delta:>8.2f}%\n")

        f.write("\n\nIMPROVEMENT SUMMARY:\n")
        f.write("  v2 was retrained with additional normal data collected\n")
        f.write("  during memory-heavy workloads (stress-ng --vm 1G, 1.5G,\n")
        f.write("  and CPU+memory combined). This reduces false positives\n")
        f.write("  for legitimate memory-intensive applications.\n")

    print(f"  {G}✅ Report saved: {path}{RESET}")


def run_retrain(original_path, new_path, merged_output):
    print(f"\n{BOLD}{C}{'═'*55}{RESET}")
    print(f"{BOLD}{C}  Fix 2 — Retraining with Improved Dataset{RESET}")
    print(f"{BOLD}{C}{'═'*55}{RESET}")

    # Merge
    df_merged = load_and_merge(original_path, new_path, merged_output)

    # ── Train OLD model on original data for fair comparison ──
    print(f"\n{BOLD}  Training v1 on original data for comparison...{RESET}")
    df_orig   = pd.read_csv(original_path)
    X_o, y_o  = prepare(df_orig)
    Xtr_o, Xte_o, ytr_o, yte_o = train_test_split(
        X_o, y_o, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y_o)
    sc_o = StandardScaler()
    Xtr_o_s = sc_o.fit_transform(Xtr_o); Xte_o_s = sc_o.transform(Xte_o)
    old_model, Xtr_o_res, ytr_o_res = train(Xtr_o_s, ytr_o)
    old_res = evaluate_model(old_model, Xte_o_s, yte_o, Xtr_o_res, ytr_o_res, "v1 — Original")

    # ── Train NEW model on merged data ──
    print(f"\n{BOLD}  Training v2 on improved dataset...{RESET}")
    X_n, y_n  = prepare(df_merged)
    Xtr_n, Xte_n, ytr_n, yte_n = train_test_split(
        X_n, y_n, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y_n)
    sc_n = StandardScaler()
    Xtr_n_s = sc_n.fit_transform(Xtr_n); Xte_n_s = sc_n.transform(Xte_n)
    new_model, Xtr_n_res, ytr_n_res = train(Xtr_n_s, ytr_n)
    new_res = evaluate_model(new_model, Xte_n_s, yte_n, Xtr_n_res, ytr_n_res, "v2 — Improved")

    # ── Plots ──
    print(f"\n{BOLD}  Generating comparison plots...{RESET}")
    plot_comparison(
        old_res, new_res,
        list(X_o.columns), list(X_n.columns),
        old_model, new_model, yte_o, yte_n
    )

    # ── Save ──
    save_new_model(new_model, sc_n, list(X_n.columns))
    save_comparison_report(old_res, new_res)

    print(f"\n{BOLD}{C}{'═'*55}{RESET}")
    print(f"{BOLD}{C}  Done! Use {NEW_MODEL_PATH} in your dashboard.{RESET}")
    print(f"{BOLD}{C}{'═'*55}{RESET}")
    print(f"""
  To use the new model in dashboard.py, change:
    MODEL_PATH  = "{NEW_MODEL_PATH}"
    SCALER_PATH = "{NEW_SCALER_PATH}"
""")


# ──────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Fix 2: Collect memory-heavy normal data and retrain"
    )
    parser.add_argument("--collect",  action="store_true",
                        help="Collect new memory-heavy normal data")
    parser.add_argument("--retrain",  action="store_true",
                        help="Retrain model with improved dataset")
    parser.add_argument("--original", type=str, default="full_dataset.csv",
                        help="Original dataset CSV")
    parser.add_argument("--new",      type=str, default="memory_heavy_normal.csv",
                        help="New normal data CSV")
    parser.add_argument("--output",   type=str, default="improved_dataset.csv",
                        help="Output merged dataset or collection file")

    args = parser.parse_args()

    if args.collect:
        run_collect(args.output)
    elif args.retrain:
        run_retrain(args.original, args.new, args.output)
    else:
        parser.print_help()
