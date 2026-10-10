"""
CryptoGuard — Multi-Algorithm Detection Training Script
=======================================================
Author  : CK (FYP / Portfolio Project)

Trains a multi-class Random Forest to detect AND identify
which mining algorithm is running.

Classes:
    Label 0 → Normal
    Label 1 → RandomX  (XMRig rx/0)    — Monero
    Label 2 → RandomARQ (XMRig rx/arq) — Arqma
    Label 3 → Argon2   (XMRig argon2)  — Chukwa

SETUP:
    pip3 install pandas scikit-learn matplotlib seaborn imbalanced-learn

USAGE:
    python3 train_multi_algo.py --dataset multi_algo_dataset.csv
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns
import argparse
import os
import pickle
import warnings
warnings.filterwarnings("ignore")

from sklearn.ensemble          import RandomForestClassifier
from sklearn.model_selection   import train_test_split, cross_val_score, StratifiedKFold
from sklearn.preprocessing     import StandardScaler, label_binarize
from sklearn.metrics           import (
    confusion_matrix, classification_report,
    roc_curve, auc, accuracy_score,
    precision_score, recall_score, f1_score
)
from sklearn.multiclass        import OneVsRestClassifier
from imblearn.over_sampling    import SMOTE

# ──────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────

RANDOM_STATE = 42
TEST_SIZE    = 0.2
RESULTS_DIR  = "results_multi"
MODEL_PATH   = "cryptojacking_model_multi.pkl"
SCALER_PATH  = "scaler_multi.pkl"

CLASS_NAMES  = {
    0: "Normal",
    1: "RandomX",
    2: "RandomARQ",
    3: "Argon2"
}

CLASS_COLORS = {
    0: "#3fb950",   # green
    1: "#f85149",   # red
    2: "#d29922",   # yellow
    3: "#bc8cff",   # purple
}

DROP_COLS = ["timestamp", "session", "label"]

# Plot style
plt.rcParams.update({
    "figure.facecolor" : "#0d1117",
    "axes.facecolor"   : "#161b22",
    "axes.edgecolor"   : "#30363d",
    "axes.labelcolor"  : "#e6edf3",
    "text.color"       : "#e6edf3",
    "xtick.color"      : "#8b949e",
    "ytick.color"      : "#8b949e",
    "grid.color"       : "#21262d",
    "grid.linestyle"   : "--",
    "grid.alpha"       : 0.5,
    "font.family"      : "monospace",
})

# ──────────────────────────────────────────────
# STEP 1 — LOAD & CLEAN
# ──────────────────────────────────────────────

def load_data(path):
    print(f"\n{'─'*55}")
    print(f"  📂 Loading: {path}")
    print(f"{'─'*55}")

    df = pd.read_csv(path)
    df.dropna(how="all", inplace=True)

    num_cols = df.select_dtypes(include=[np.number]).columns
    df[num_cols] = df[num_cols].fillna(df[num_cols].median())

    # Drop cpu_temp if mostly unavailable
    if "cpu_temp_celsius" in df.columns:
        if (df["cpu_temp_celsius"] == -1).sum() / len(df) > 0.5:
            df.drop(columns=["cpu_temp_celsius"], inplace=True)
            print(f"  ⚠️  cpu_temp_celsius dropped (unavailable in VM)")

    print(f"  Total rows : {len(df)}")
    print(f"\n  Class distribution:")
    for lbl, cnt in df["label"].value_counts().sort_index().items():
        name = CLASS_NAMES.get(lbl, f"Label {lbl}")
        bar  = "█" * int(cnt / 10)
        print(f"    {lbl} {name:<12} : {cnt:>4} rows  {bar}")

    return df


# ──────────────────────────────────────────────
# STEP 2 — PREPARE FEATURES
# ──────────────────────────────────────────────

def prepare_features(df):
    drop = [c for c in DROP_COLS if c in df.columns]
    X    = df.drop(columns=drop).select_dtypes(include=[np.number])
    y    = df["label"]

    print(f"\n  Features ({len(X.columns)}): {', '.join(X.columns.tolist())}")
    return X, y


# ──────────────────────────────────────────────
# STEP 3 — SMOTE FOR MULTI-CLASS
# ──────────────────────────────────────────────

def apply_smote(X_train, y_train):
    print(f"\n  Before SMOTE: {dict(pd.Series(y_train).value_counts().sort_index())}")
    sm           = SMOTE(random_state=RANDOM_STATE)
    X_res, y_res = sm.fit_resample(X_train, y_train)
    print(f"  After SMOTE : {dict(pd.Series(y_res).value_counts().sort_index())}")
    return X_res, y_res


# ──────────────────────────────────────────────
# STEP 4 — TRAIN
# ──────────────────────────────────────────────

def train_model(X_train, y_train):
    print(f"\n{'─'*55}")
    print(f"  🤖 Training Multi-Class Random Forest...")
    print(f"{'─'*55}")

    model = RandomForestClassifier(
        n_estimators      = 200,
        max_depth         = None,
        max_features      = "sqrt",
        class_weight      = "balanced",
        random_state      = RANDOM_STATE,
        n_jobs            = -1
    )
    model.fit(X_train, y_train)
    print(f"  ✅ Done — {model.n_estimators} trees, {len(model.classes_)} classes")
    return model


# ──────────────────────────────────────────────
# STEP 5 — EVALUATE
# ──────────────────────────────────────────────

def evaluate(model, X_train, y_train, X_test, y_test):
    print(f"\n{'─'*55}")
    print(f"  📊 Evaluation")
    print(f"{'─'*55}")

    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)

    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, average="weighted", zero_division=0)
    rec  = recall_score(y_test, y_pred, average="weighted", zero_division=0)
    f1   = f1_score(y_test, y_pred, average="weighted", zero_division=0)

    print(f"  Accuracy  : {acc*100:.2f}%")
    print(f"  Precision : {prec*100:.2f}% (weighted)")
    print(f"  Recall    : {rec*100:.2f}% (weighted)")
    print(f"  F1 Score  : {f1*100:.2f}% (weighted)")

    # Per-class metrics
    print(f"\n  Per-class breakdown:")
    report = classification_report(
        y_test, y_pred,
        target_names=[CLASS_NAMES[i] for i in sorted(CLASS_NAMES)],
        zero_division=0
    )
    print(report)

    # Cross-validation
    print(f"  5-fold cross-validation (F1 weighted)...")
    cv      = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
    cv_f1   = cross_val_score(model, X_train, y_train,
                               cv=cv, scoring="f1_weighted")
    print(f"  CV scores : {[f'{s:.3f}' for s in cv_f1]}")
    print(f"  CV mean   : {cv_f1.mean():.3f} ± {cv_f1.std():.3f}")

    return y_pred, y_prob, acc, prec, rec, f1, report, cv_f1


# ──────────────────────────────────────────────
# PLOT 1 — CONFUSION MATRIX
# ──────────────────────────────────────────────

def plot_confusion_matrix(y_test, y_pred):
    labels     = sorted(CLASS_NAMES.keys())
    label_names = [CLASS_NAMES[l] for l in labels]
    cm         = confusion_matrix(y_test, y_pred, labels=labels)

    fig, ax = plt.subplots(figsize=(8, 7))
    sns.heatmap(
        cm, annot=True, fmt="d", cmap="Blues",
        xticklabels=label_names,
        yticklabels=label_names,
        linewidths=1, linecolor="#21262d",
        annot_kws={"size": 14, "weight": "bold", "color": "white"},
        ax=ax
    )
    ax.set_title("Multi-Class Confusion Matrix",
                 fontsize=15, color="#58a6ff", fontweight="bold", pad=15)
    ax.set_xlabel("Predicted", fontsize=12, labelpad=10)
    ax.set_ylabel("Actual",    fontsize=12, labelpad=10)

    plt.tight_layout()
    path = os.path.join(RESULTS_DIR, "confusion_matrix_multi.png")
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  ✅ {path}")


# ──────────────────────────────────────────────
# PLOT 2 — ROC CURVES (One vs Rest)
# ──────────────────────────────────────────────

def plot_roc_curves(y_test, y_prob, n_classes):
    labels      = sorted(CLASS_NAMES.keys())
    y_test_bin  = label_binarize(y_test, classes=labels)

    fig, ax = plt.subplots(figsize=(9, 7))

    for i, lbl in enumerate(labels):
        if y_test_bin[:, i].sum() == 0:
            continue
        fpr, tpr, _ = roc_curve(y_test_bin[:, i], y_prob[:, i])
        roc_auc     = auc(fpr, tpr)
        color       = CLASS_COLORS.get(lbl, "#58a6ff")
        ax.plot(fpr, tpr, color=color, lw=2,
                label=f"{CLASS_NAMES[lbl]} (AUC = {roc_auc:.4f})")
        ax.fill_between(fpr, tpr, alpha=0.06, color=color)

    ax.plot([0,1],[0,1], color="#8b949e", lw=1.5, linestyle="--",
            label="Random (AUC = 0.50)")
    ax.set_xlim([0.0, 1.0])
    ax.set_ylim([0.0, 1.05])
    ax.set_xlabel("False Positive Rate", fontsize=12)
    ax.set_ylabel("True Positive Rate",  fontsize=12)
    ax.set_title("ROC Curves — One vs Rest (Multi-Class)",
                 fontsize=14, color="#58a6ff", fontweight="bold", pad=15)
    ax.legend(loc="lower right", fontsize=10,
              facecolor="#161b22", edgecolor="#30363d")
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    path = os.path.join(RESULTS_DIR, "roc_curves_multi.png")
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  ✅ {path}")


# ──────────────────────────────────────────────
# PLOT 3 — FEATURE IMPORTANCE
# ──────────────────────────────────────────────

def plot_feature_importance(model, feature_names):
    imp     = model.feature_importances_
    idx     = np.argsort(imp)
    names   = [feature_names[i] for i in idx]
    vals    = imp[idx]

    colors = []
    for v in vals:
        if v >= 0.10:   colors.append("#f85149")
        elif v >= 0.05: colors.append("#d29922")
        else:           colors.append("#58a6ff")

    fig, ax = plt.subplots(figsize=(10, max(6, len(feature_names) * 0.45)))
    bars = ax.barh(names, vals, color=colors, edgecolor="#21262d", height=0.7)

    for bar, val in zip(bars, vals):
        ax.text(bar.get_width() + 0.002, bar.get_y() + bar.get_height()/2,
                f"{val:.4f}", va="center", ha="left",
                color="#8b949e", fontsize=9)

    ax.set_title("Feature Importance — Multi-Algorithm RF",
                 fontsize=14, color="#58a6ff", fontweight="bold", pad=15)
    ax.set_xlabel("Importance (Gini)", fontsize=12)
    ax.set_xlim(0, max(vals) * 1.2)
    ax.grid(True, axis="x", alpha=0.3)

    legend = [
        mpatches.Patch(color="#f85149", label="High (≥10%)"),
        mpatches.Patch(color="#d29922", label="Medium (5–10%)"),
        mpatches.Patch(color="#58a6ff", label="Low (<5%)"),
    ]
    ax.legend(handles=legend, loc="lower right",
              facecolor="#161b22", edgecolor="#30363d", fontsize=9)

    plt.tight_layout()
    path = os.path.join(RESULTS_DIR, "feature_importance_multi.png")
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  ✅ {path}")

    print(f"\n  Top 5 features:")
    top_idx = np.argsort(imp)[::-1][:5]
    for rank, i in enumerate(top_idx, 1):
        bar = "█" * int(imp[i] * 100)
        print(f"    {rank}. {feature_names[i]:<35} {imp[i]:.4f}  {bar}")


# ──────────────────────────────────────────────
# PLOT 4 — ALGORITHM SIGNATURE COMPARISON
# Shows mean feature values per class — key finding!
# ──────────────────────────────────────────────

def plot_algorithm_signatures(df, feature_names):
    """
    Radar/bar chart showing how each algorithm's feature profile differs.
    This is the KEY research finding — different algos have different signatures.
    """
    # Pick the most important features to compare
    key_features = [
        "cpu_total_percent",
        "memory_percent",
        "memory_available_mb",
        "cpu_spike_duration_sec",
        "net_bytes_sent_delta",
        "top_process_cpu_percent",
    ]
    key_features = [f for f in key_features if f in df.columns]

    fig, axes = plt.subplots(1, len(key_features),
                              figsize=(3 * len(key_features), 5))
    fig.suptitle("Algorithm Signature Comparison — Mean Feature Values per Class",
                 fontsize=13, color="#58a6ff", fontweight="bold", y=1.02)

    labels = sorted(CLASS_NAMES.keys())

    for ax, feat in zip(axes, key_features):
        means  = [df[df["label"] == lbl][feat].mean() for lbl in labels]
        colors = [CLASS_COLORS.get(lbl, "#58a6ff") for lbl in labels]
        names  = [CLASS_NAMES[lbl] for lbl in labels]

        bars = ax.bar(names, means, color=colors, edgecolor="#21262d", width=0.6)
        ax.set_title(feat.replace("_", "\n"), fontsize=9, color="#8b949e")
        ax.set_xticklabels(names, rotation=30, ha="right", fontsize=8)
        ax.grid(True, axis="y", alpha=0.3)

        for bar, val in zip(bars, means):
            ax.text(bar.get_x() + bar.get_width()/2,
                    bar.get_height() + max(means) * 0.02,
                    f"{val:.0f}", ha="center", va="bottom",
                    fontsize=8, color="#e6edf3")

    # Legend
    handles = [mpatches.Patch(color=CLASS_COLORS[l], label=CLASS_NAMES[l])
               for l in labels]
    fig.legend(handles=handles, loc="upper right",
               facecolor="#161b22", edgecolor="#30363d", fontsize=9)

    plt.tight_layout()
    path = os.path.join(RESULTS_DIR, "algorithm_signatures.png")
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  ✅ {path}")


# ──────────────────────────────────────────────
# SAVE
# ──────────────────────────────────────────────

def save_model(model, scaler, feature_names):
    with open(MODEL_PATH, "wb") as f:
        pickle.dump({"model": model, "features": feature_names,
                     "classes": CLASS_NAMES}, f)
    with open(SCALER_PATH, "wb") as f:
        pickle.dump(scaler, f)
    print(f"\n  ✅ Model  : {MODEL_PATH}")
    print(f"  ✅ Scaler : {SCALER_PATH}")


def save_report(report, acc, prec, rec, f1, cv_f1, feature_names, importances):
    path = os.path.join(RESULTS_DIR, "multi_algo_report.txt")
    with open(path, "w") as f:
        f.write("=" * 55 + "\n")
        f.write("  CRYPTOGUARD — MULTI-ALGORITHM DETECTION REPORT\n")
        f.write("=" * 55 + "\n\n")
        f.write(f"  Classes:\n")
        for lbl, name in CLASS_NAMES.items():
            f.write(f"    {lbl} → {name}\n")
        f.write(f"\n  Accuracy  : {acc*100:.2f}%\n")
        f.write(f"  Precision : {prec*100:.2f}% (weighted)\n")
        f.write(f"  Recall    : {rec*100:.2f}% (weighted)\n")
        f.write(f"  F1 Score  : {f1*100:.2f}% (weighted)\n")
        f.write(f"  CV F1     : {cv_f1.mean():.3f} ± {cv_f1.std():.3f}\n\n")
        f.write("Classification Report:\n")
        f.write(report + "\n")
        f.write("Feature Importances:\n")
        idx = np.argsort(importances)[::-1]
        for i in idx:
            f.write(f"  {feature_names[i]:<35} {importances[i]:.4f}\n")
    print(f"  ✅ Report : {path}")


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────

def main(dataset_path):
    os.makedirs(RESULTS_DIR, exist_ok=True)

    # 1. Load
    df = load_data(dataset_path)

    # 2. Features
    X, y = prepare_features(df)
    feature_names = list(X.columns)

    # 3. Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE,
        random_state=RANDOM_STATE, stratify=y
    )
    print(f"\n  Train: {len(X_train)}  Test: {len(X_test)}")

    # 4. Scale
    scaler  = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s  = scaler.transform(X_test)

    # 5. SMOTE
    X_train_s, y_train = apply_smote(X_train_s, y_train)

    # 6. Train
    model = train_model(X_train_s, y_train)

    # 7. Evaluate
    y_pred, y_prob, acc, prec, rec, f1, report, cv_f1 = evaluate(
        model, X_train_s, y_train, X_test_s, y_test
    )

    # 8. Plots
    print(f"\n{'─'*55}")
    print(f"  📈 Generating plots...")
    print(f"{'─'*55}")
    plot_confusion_matrix(y_test, y_pred)
    plot_roc_curves(y_test, y_prob, len(CLASS_NAMES))
    plot_feature_importance(model, feature_names)
    plot_algorithm_signatures(df, feature_names)

    # 9. Save
    save_model(model, scaler, feature_names)
    save_report(report, acc, prec, rec, f1, cv_f1,
                feature_names, model.feature_importances_)

    print(f"\n{'─'*55}")
    print(f"  🎉 Done! Check results_multi/ folder.")
    print(f"{'─'*55}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Multi-algorithm cryptojacking detection training"
    )
    parser.add_argument("--dataset", type=str, required=True,
                        help="Path to multi_algo_dataset.csv")
    args = parser.parse_args()
    main(args.dataset)
