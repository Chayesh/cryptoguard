"""
CryptoGuard — SHAP Explainability Module
=========================================
Author  : CK (FYP / Portfolio Project)

SETUP:
    pip3 install shap matplotlib

USAGE:
    python3 shap_explainer.py --model cryptojacking_model.pkl \
                               --scaler scaler.pkl \
                               --dataset full_dataset.csv
"""

import pickle
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import argparse
import os
import warnings
warnings.filterwarnings("ignore")

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False
    print("⚠️  SHAP not installed. Run: pip3 install shap")

OUTPUT_DIR  = "shap_output"
CLASS_NAMES = {0: "Normal", 1: "RandomX", 2: "RandomARQ", 3: "Argon2"}
BINARY_NAMES = {0: "Normal", 1: "Cryptojacking"}

plt.rcParams.update({
    "figure.facecolor" : "#0d1117",
    "axes.facecolor"   : "#161b22",
    "axes.edgecolor"   : "#30363d",
    "axes.labelcolor"  : "#e6edf3",
    "text.color"       : "#e6edf3",
    "xtick.color"      : "#8b949e",
    "ytick.color"      : "#8b949e",
    "grid.color"       : "#21262d",
    "font.family"      : "monospace",
})

# ──────────────────────────────────────────────
# LIVE EXPLAINER — used by dashboard
# ──────────────────────────────────────────────

class LiveExplainer:
    """Lightweight SHAP explainer for real-time use in dashboard.py"""

    def __init__(self, model_path, scaler_path):
        self.ready         = False
        self.feature_names = []
        self._explainer    = None
        self.scaler        = None
        self.model         = None

        if not SHAP_AVAILABLE:
            print("⚠️  SHAP not installed")
            return

        try:
            with open(model_path, "rb") as f:
                bundle = pickle.load(f)
            with open(scaler_path, "rb") as f:
                self.scaler = pickle.load(f)

            self.model         = bundle["model"]
            self.feature_names = bundle["features"]
            print(f"[SHAP] Model loaded — {len(self.feature_names)} features")

        except Exception as e:
            print(f"[SHAP] Load error: {e}")

    def _init_explainer(self, X_background):
        """Build TreeExplainer with background data."""
        try:
            self._explainer = shap.TreeExplainer(
                self.model,
                data=X_background,
                feature_perturbation="interventional"
            )
            self.ready = True
            print(f"[SHAP] Explainer ready (background={len(X_background)} samples)")
        except Exception as e:
            print(f"[SHAP] Explainer init error: {e}")
            self.ready = False

    def explain(self, features: dict) -> list:
        """
        Given a features dict, return ranked SHAP explanations.
        Returns list of dicts: [{ feature, shap_value, direction, magnitude }]
        """
        if not SHAP_AVAILABLE:
            return []
        if not self.ready or self._explainer is None:
            return []
        if not self.feature_names:
            return []

        try:
            # Build scaled feature vector
            vec        = np.array([[features.get(f, 0) for f in self.feature_names]])
            vec_scaled = self.scaler.transform(vec)

            # Get SHAP values
            sv_raw = self._explainer.shap_values(vec_scaled)

            # Debug shape
            if isinstance(sv_raw, list):
                print(f"[SHAP debug] list of {len(sv_raw)} arrays, each shape {np.array(sv_raw[0]).shape}")
            else:
                print(f"[SHAP debug] array shape {np.array(sv_raw).shape}")

            # Extract 1D array of SHAP values for attack class
            if isinstance(sv_raw, list):
                # list[class_idx] → each is (n_samples, n_features)
                # use index 1 for binary (attack class)
                idx = min(1, len(sv_raw) - 1)
                sv  = np.array(sv_raw[idx]).flatten()
            else:
                sv_arr = np.array(sv_raw)
                if sv_arr.ndim == 3:
                    # (n_samples, n_features, n_classes) — take class 1
                    sv = sv_arr[0, :, 1]
                elif sv_arr.ndim == 2:
                    # (n_samples, n_features)
                    sv = sv_arr[0]
                else:
                    sv = sv_arr.flatten()

            print(f"[SHAP debug] final sv: shape={sv.shape} sample={sv[:3]}")

            # Rank by absolute magnitude
            ranked = np.argsort(np.abs(sv))[::-1][:8]
            results = []
            for i in ranked:
                val = float(sv[i])
                results.append({
                    "feature"   : self.feature_names[i],
                    "shap_value": round(val, 4),
                    "direction" : "attack" if val > 0 else "safe",
                    "magnitude" : round(abs(val), 4),
                })
            return results

        except Exception as e:
            import traceback
            print(f"[SHAP explain error] {e}")
            traceback.print_exc()
            return []


# ──────────────────────────────────────────────
# STANDALONE — batch plots for FYP report
# ──────────────────────────────────────────────

def load_model_and_data(model_path, scaler_path, dataset_path):
    with open(model_path, "rb") as f:
        bundle = pickle.load(f)
    with open(scaler_path, "rb") as f:
        scaler = pickle.load(f)

    model         = bundle["model"]
    feature_names = bundle["features"]

    df   = pd.read_csv(dataset_path)
    drop = ["timestamp", "session", "label", "cpu_temp_celsius"]
    X    = df.drop(columns=[c for c in drop if c in df.columns])
    X    = X.select_dtypes(include=[np.number])
    X    = X[feature_names]
    y    = df["label"]

    X_scaled = scaler.transform(X)
    print(f"  Model    : {model_path} ({len(feature_names)} features)")
    print(f"  Dataset  : {len(X)} rows")
    return model, scaler, feature_names, X, X_scaled, y


def plot_shap_bar(explainer, X_scaled, feature_names, is_multi=False):
    print("  Computing SHAP values for bar chart...")
    np.random.seed(42)
    idx      = np.random.choice(len(X_scaled), min(150, len(X_scaled)), replace=False)
    X_sample = X_scaled[idx]

    sv_raw   = explainer.shap_values(X_sample)

    if isinstance(sv_raw, list):
        vals_idx = min(1, len(sv_raw) - 1)
        sv       = np.array(sv_raw[vals_idx])
    else:
        sv_arr = np.array(sv_raw)
        if sv_arr.ndim == 3:
            sv = sv_arr[:, :, 1]
        else:
            sv = sv_arr

    mean_abs = np.abs(sv).mean(axis=0)
    idx_sort = np.argsort(mean_abs)
    names    = [feature_names[i] for i in idx_sort]
    values   = mean_abs[idx_sort]
    colors   = ["#f85149" if v >= 0.10 else "#d29922" if v >= 0.05 else "#58a6ff"
                for v in values]

    fig, ax = plt.subplots(figsize=(10, max(6, len(feature_names) * 0.45)))
    bars    = ax.barh(names, values, color=colors, edgecolor="#21262d", height=0.7)

    for bar, val in zip(bars, values):
        ax.text(bar.get_width() + 0.001,
                bar.get_y() + bar.get_height()/2,
                f"{val:.4f}", va="center", ha="left",
                color="#8b949e", fontsize=9)

    ax.set_title("SHAP Feature Importance — Mean |SHAP Value|",
                 fontsize=13, color="#58a6ff", fontweight="bold", pad=15)
    ax.set_xlabel("Mean |SHAP value|", fontsize=11)
    ax.grid(True, axis="x", alpha=0.3)

    legend = [
        mpatches.Patch(color="#f85149", label="High (≥0.10)"),
        mpatches.Patch(color="#d29922", label="Medium (0.05–0.10)"),
        mpatches.Patch(color="#58a6ff", label="Low (<0.05)"),
    ]
    ax.legend(handles=legend, loc="lower right",
              facecolor="#161b22", edgecolor="#30363d", fontsize=9)

    plt.tight_layout()
    path = os.path.join(OUTPUT_DIR, "shap_bar.png")
    plt.savefig(path, dpi=150, bbox_inches="tight", facecolor="#0d1117")
    plt.close()
    print(f"  ✅ {path}")

    top_idx = np.argsort(mean_abs)[::-1][:5]
    return [(feature_names[i], mean_abs[i]) for i in top_idx]


def save_shap_report(top_features, is_multi=False):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    path = os.path.join(OUTPUT_DIR, "shap_report.txt")
    with open(path, "w") as f:
        f.write("=" * 55 + "\n")
        f.write("  CRYPTOGUARD — SHAP EXPLAINABILITY REPORT\n")
        f.write("=" * 55 + "\n\n")
        f.write(f"  Model: {'Multi-class' if is_multi else 'Binary'}\n\n")
        f.write("  Top 5 Features by Mean |SHAP Value|:\n\n")
        f.write(f"  {'Feature':<35} {'Mean |SHAP|':>12}\n")
        f.write("  " + "─" * 50 + "\n")
        for name, val in top_features:
            bar = "█" * int(val * 100)
            f.write(f"  {name:<35} {val:>12.4f}  {bar}\n")
        f.write("\n\n  Positive SHAP → pushed toward ATTACK\n")
        f.write("  Negative SHAP → pushed toward SAFE\n")
    print(f"  ✅ {path}")


def main(model_path, scaler_path, dataset_path, is_multi=False):
    if not SHAP_AVAILABLE:
        print("❌ Install SHAP: pip3 install shap")
        return

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print(f"\n{'═'*55}")
    print(f"  CryptoGuard — SHAP Explainability")
    print(f"{'═'*55}\n")

    model, scaler, feature_names, X, X_scaled, y = load_model_and_data(
        model_path, scaler_path, dataset_path
    )

    explainer = shap.TreeExplainer(model, data=X_scaled[:100],
                                   feature_perturbation="interventional")

    top_features = plot_shap_bar(explainer, X_scaled, feature_names, is_multi)
    save_shap_report(top_features, is_multi)

    print(f"\n  Top 5 by SHAP:")
    for name, val in top_features:
        print(f"    {name:<35} {val:.4f}  {'█'*int(val*100)}")

    print(f"\n{'═'*55}")
    print(f"  🎉 Done! Check shap_output/")
    print(f"{'═'*55}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--model",   required=True)
    parser.add_argument("--scaler",  required=True)
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--multi",   action="store_true")
    args = parser.parse_args()
    main(args.model, args.scaler, args.dataset, args.multi)
