"""
Cryptojacking Detection — Random Forest Training Script
=======================================================
Author  : Your Name (FYP Project)

SETUP:
    pip3 install pandas scikit-learn matplotlib seaborn imbalanced-learn

USAGE:
    python3 train_model.py --dataset full_dataset.csv

OUTPUT FILES:
    cryptojacking_model.pkl     ← trained model (use this for real-time detection)
    scaler.pkl                  ← feature scaler
    results/confusion_matrix.png
    results/roc_curve.png
    results/feature_importance.png
    results/classification_report.txt
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
from sklearn.preprocessing     import StandardScaler
from sklearn.metrics           import (
    confusion_matrix, classification_report,
    roc_curve, auc, accuracy_score,
    precision_score, recall_score, f1_score
)
from imblearn.over_sampling    import SMOTE

# ──────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────

RESULTS_DIR  = "results"
MODEL_PATH   = "cryptojacking_model.pkl"
SCALER_PATH  = "scaler.pkl"
RANDOM_STATE = 42
TEST_SIZE    = 0.2

# Features to use for training (drop non-numeric / metadata cols)
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

ACCENT   = "#58a6ff"   # blue
SUCCESS  = "#3fb950"   # green
DANGER   = "#f85149"   # red
WARNING  = "#d29922"   # yellow
PURPLE   = "#bc8cff"

# ──────────────────────────────────────────────
# STEP 1 — LOAD & CLEAN DATA
# ──────────────────────────────────────────────

def load_data(path):
    print(f"\n{'─'*55}")
    print(f"  📂 Loading dataset: {path}")
    print(f"{'─'*55}")

    df = pd.read_csv(path)
    print(f"  Rows       : {len(df)}")
    print(f"  Columns    : {len(df.columns)}")
    print(f"  Label dist : {dict(df['label'].value_counts().sort_index())}")

    # Drop rows with all-NaN features
    df.dropna(how="all", inplace=True)

    # Fill remaining NaN with column median
    num_cols = df.select_dtypes(include=[np.number]).columns
    df[num_cols] = df[num_cols].fillna(df[num_cols].median())

    # Drop CPU temp if mostly -1 (unavailable in VM)
    if "cpu_temp_celsius" in df.columns:
        invalid = (df["cpu_temp_celsius"] == -1).sum()
        if invalid / len(df) > 0.5:
            print(f"  ⚠️  cpu_temp_celsius mostly unavailable in VM — dropping")
            df.drop(columns=["cpu_temp_celsius"], inplace=True)

    print(f"  Clean rows : {len(df)}")
    return df


# ──────────────────────────────────────────────
# STEP 2 — PREPARE FEATURES
# ──────────────────────────────────────────────

def prepare_features(df):
    # Drop metadata columns (keep only numeric features)
    drop = [c for c in DROP_COLS if c in df.columns]
    X = df.drop(columns=drop)
    y = df["label"]

    # Keep only numeric columns
    X = X.select_dtypes(include=[np.number])

    print(f"\n  Features used ({len(X.columns)}):")
    for col in X.columns:
        print(f"    • {col}")

    return X, y


# ──────────────────────────────────────────────
# STEP 3 — HANDLE CLASS IMBALANCE WITH SMOTE
# ──────────────────────────────────────────────

def apply_smote(X_train, y_train):
    counts = dict(y_train.value_counts())
    print(f"\n  Before SMOTE : {counts}")

    sm = SMOTE(random_state=RANDOM_STATE)
    X_res, y_res = sm.fit_resample(X_train, y_train)

    counts_after = dict(pd.Series(y_res).value_counts().sort_index())
    print(f"  After SMOTE  : {counts_after}")
    return X_res, y_res


# ──────────────────────────────────────────────
# STEP 4 — TRAIN RANDOM FOREST
# ──────────────────────────────────────────────

def train_model(X_train, y_train):
    print(f"\n{'─'*55}")
    print(f"  🤖 Training Random Forest...")
    print(f"{'─'*55}")

    model = RandomForestClassifier(
        n_estimators      = 200,      # 200 trees
        max_depth         = None,     # grow full trees
        min_samples_split = 2,
        min_samples_leaf  = 1,
        max_features      = "sqrt",   # sqrt(n_features) per split
        class_weight      = "balanced",
        random_state      = RANDOM_STATE,
        n_jobs            = -1        # use all CPU cores
    )

    model.fit(X_train, y_train)
    print(f"  ✅ Training complete — {model.n_estimators} trees built")
    return model


# ──────────────────────────────────────────────
# STEP 5 — EVALUATE
# ──────────────────────────────────────────────

def evaluate(model, X_train, y_train, X_test, y_test, feature_names):
    print(f"\n{'─'*55}")
    print(f"  📊 Evaluation Results")
    print(f"{'─'*55}")

    y_pred      = model.predict(X_test)
    y_prob      = model.predict_proba(X_test)[:, 1]

    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec  = recall_score(y_test, y_pred)
    f1   = f1_score(y_test, y_pred)

    print(f"  Accuracy  : {acc*100:.2f}%")
    print(f"  Precision : {prec*100:.2f}%")
    print(f"  Recall    : {rec*100:.2f}%")
    print(f"  F1 Score  : {f1*100:.2f}%")

    # Cross-validation
    print(f"\n  Running 5-fold cross-validation...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
    cv_scores = cross_val_score(model, X_train, y_train, cv=cv, scoring="f1")
    print(f"  CV F1 scores : {[f'{s:.3f}' for s in cv_scores]}")
    print(f"  CV F1 mean   : {cv_scores.mean():.3f} ± {cv_scores.std():.3f}")

    report = classification_report(y_test, y_pred,
                                   target_names=["Normal", "Cryptojacking"])
    print(f"\n{report}")

    return y_pred, y_prob, acc, prec, rec, f1, report


# ──────────────────────────────────────────────
# STEP 6 — CONFUSION MATRIX PLOT
# ──────────────────────────────────────────────

def plot_confusion_matrix(y_test, y_pred):
    cm = confusion_matrix(y_test, y_pred)
    fig, ax = plt.subplots(figsize=(7, 6))
    fig.patch.set_facecolor("#0d1117")

    sns.heatmap(
        cm, annot=True, fmt="d", cmap="Blues",
        xticklabels=["Normal", "Cryptojacking"],
        yticklabels=["Normal", "Cryptojacking"],
        linewidths=1, linecolor="#21262d",
        annot_kws={"size": 18, "weight": "bold", "color": "white"},
        ax=ax
    )

    ax.set_title("Confusion Matrix", fontsize=16, color=ACCENT,
                 fontweight="bold", pad=15)
    ax.set_xlabel("Predicted Label", fontsize=12, labelpad=10)
    ax.set_ylabel("True Label", fontsize=12, labelpad=10)

    tn, fp, fn, tp = cm.ravel()
    stats = f"TN={tn}  FP={fp}  FN={fn}  TP={tp}"
    fig.text(0.5, 0.01, stats, ha="center", color="#8b949e", fontsize=10)

    plt.tight_layout()
    path = os.path.join(RESULTS_DIR, "confusion_matrix.png")
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  ✅ Saved: {path}")


# ──────────────────────────────────────────────
# STEP 7 — ROC CURVE PLOT
# ──────────────────────────────────────────────

def plot_roc_curve(y_test, y_prob):
    fpr, tpr, _ = roc_curve(y_test, y_prob)
    roc_auc      = auc(fpr, tpr)

    fig, ax = plt.subplots(figsize=(8, 6))

    # Fill under curve
    ax.fill_between(fpr, tpr, alpha=0.15, color=ACCENT)
    ax.plot(fpr, tpr, color=ACCENT, lw=2.5,
            label=f"Random Forest (AUC = {roc_auc:.4f})")
    ax.plot([0, 1], [0, 1], color="#8b949e", lw=1.5,
            linestyle="--", label="Random Classifier (AUC = 0.50)")

    # Optimal threshold point
    optimal_idx = np.argmax(tpr - fpr)
    ax.scatter(fpr[optimal_idx], tpr[optimal_idx],
               color=SUCCESS, s=100, zorder=5,
               label=f"Optimal point ({fpr[optimal_idx]:.3f}, {tpr[optimal_idx]:.3f})")

    ax.set_xlim([0.0, 1.0])
    ax.set_ylim([0.0, 1.05])
    ax.set_xlabel("False Positive Rate", fontsize=12, labelpad=10)
    ax.set_ylabel("True Positive Rate", fontsize=12, labelpad=10)
    ax.set_title("ROC Curve — Cryptojacking Detection",
                 fontsize=15, color=ACCENT, fontweight="bold", pad=15)
    ax.legend(loc="lower right", fontsize=10,
              facecolor="#161b22", edgecolor="#30363d")
    ax.grid(True, alpha=0.3)

    auc_text = f"AUC = {roc_auc:.4f}"
    ax.text(0.6, 0.15, auc_text, fontsize=22, color=SUCCESS,
            fontweight="bold", transform=ax.transAxes)

    plt.tight_layout()
    path = os.path.join(RESULTS_DIR, "roc_curve.png")
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  ✅ Saved: {path}")
    return roc_auc


# ──────────────────────────────────────────────
# STEP 8 — FEATURE IMPORTANCE PLOT
# ──────────────────────────────────────────────

def plot_feature_importance(model, feature_names):
    importances = model.feature_importances_
    indices     = np.argsort(importances)[::-1]
    sorted_names = [feature_names[i] for i in indices]
    sorted_vals  = importances[indices]

    # Color bars by importance tier
    colors = []
    for v in sorted_vals:
        if v >= 0.10:
            colors.append(DANGER)
        elif v >= 0.05:
            colors.append(WARNING)
        else:
            colors.append(ACCENT)

    fig, ax = plt.subplots(figsize=(10, max(6, len(feature_names) * 0.45)))

    bars = ax.barh(sorted_names[::-1], sorted_vals[::-1],
                   color=colors[::-1], edgecolor="#21262d", height=0.7)

    # Value labels on bars
    for bar, val in zip(bars, sorted_vals[::-1]):
        ax.text(bar.get_width() + 0.002, bar.get_y() + bar.get_height() / 2,
                f"{val:.4f}", va="center", ha="left",
                color="#8b949e", fontsize=9)

    ax.set_title("Feature Importance — Random Forest",
                 fontsize=15, color=ACCENT, fontweight="bold", pad=15)
    ax.set_xlabel("Importance Score (Gini)", fontsize=12, labelpad=10)
    ax.set_xlim(0, max(sorted_vals) * 1.2)
    ax.grid(True, axis="x", alpha=0.3)

    # Legend
    legend = [
        mpatches.Patch(color=DANGER,  label="High (≥10%)"),
        mpatches.Patch(color=WARNING, label="Medium (5–10%)"),
        mpatches.Patch(color=ACCENT,  label="Low (<5%)"),
    ]
    ax.legend(handles=legend, loc="lower right",
              facecolor="#161b22", edgecolor="#30363d", fontsize=9)

    plt.tight_layout()
    path = os.path.join(RESULTS_DIR, "feature_importance.png")
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  ✅ Saved: {path}")

    print(f"\n  Top 5 most important features:")
    for i in range(min(5, len(sorted_names))):
        bar = "█" * int(sorted_vals[i] * 100)
        print(f"    {i+1}. {sorted_names[i]:<35} {sorted_vals[i]:.4f}  {bar}")


# ──────────────────────────────────────────────
# STEP 9 — SAVE MODEL
# ──────────────────────────────────────────────

def save_model(model, scaler, feature_names):
    with open(MODEL_PATH, "wb") as f:
        pickle.dump({"model": model, "features": feature_names}, f)
    with open(SCALER_PATH, "wb") as f:
        pickle.dump(scaler, f)
    print(f"\n  ✅ Model saved  : {MODEL_PATH}")
    print(f"  ✅ Scaler saved : {SCALER_PATH}")


# ──────────────────────────────────────────────
# STEP 10 — SAVE REPORT
# ──────────────────────────────────────────────

def save_report(report, acc, prec, rec, f1, roc_auc, feature_names, importances):
    path = os.path.join(RESULTS_DIR, "classification_report.txt")
    with open(path, "w") as f:
        f.write("=" * 55 + "\n")
        f.write("  CRYPTOJACKING DETECTION — MODEL REPORT\n")
        f.write("=" * 55 + "\n\n")
        f.write(f"  Accuracy  : {acc*100:.2f}%\n")
        f.write(f"  Precision : {prec*100:.2f}%\n")
        f.write(f"  Recall    : {rec*100:.2f}%\n")
        f.write(f"  F1 Score  : {f1*100:.2f}%\n")
        f.write(f"  ROC AUC   : {roc_auc:.4f}\n\n")
        f.write("Classification Report:\n")
        f.write(report + "\n")
        f.write("Feature Importances:\n")
        idx = np.argsort(importances)[::-1]
        for i in idx:
            f.write(f"  {feature_names[i]:<35} {importances[i]:.4f}\n")
    print(f"  ✅ Report saved : {path}")


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
    print(f"\n  Train samples : {len(X_train)}")
    print(f"  Test samples  : {len(X_test)}")

    # 4. Scale
    scaler  = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test  = scaler.transform(X_test)

    # 5. SMOTE
    X_train, y_train = apply_smote(X_train, y_train)

    # 6. Train
    model = train_model(X_train, y_train)

    # 7. Evaluate
    y_pred, y_prob, acc, prec, rec, f1, report = evaluate(
    model, X_train, y_train, X_test, y_test, feature_names
    )

    # 8. Plots
    print(f"\n{'─'*55}")
    print(f"  📈 Generating plots...")
    print(f"{'─'*55}")
    plot_confusion_matrix(y_test, y_pred)
    roc_auc = plot_roc_curve(y_test, y_prob)
    plot_feature_importance(model, feature_names)

    # 9. Save model
    save_model(model, scaler, feature_names)

    # 10. Save report
    save_report(report, acc, prec, rec, f1, roc_auc,
                feature_names, model.feature_importances_)

    print(f"\n{'─'*55}")
    print(f"  🎉 All done! Check the results/ folder.")
    print(f"{'─'*55}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Train Random Forest for cryptojacking detection"
    )
    parser.add_argument(
        "--dataset", type=str, required=True,
        help="Path to merged CSV dataset (e.g. full_dataset.csv)"
    )
    args = parser.parse_args()
    main(args.dataset)
