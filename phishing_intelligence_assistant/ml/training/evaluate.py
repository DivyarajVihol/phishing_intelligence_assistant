"""Model evaluation metrics, threshold selection, and error analysis."""
from collections import Counter
from typing import Any

import numpy as np
from sklearn.metrics import (
    accuracy_score, average_precision_score, confusion_matrix, f1_score,
    precision_recall_curve, precision_score, recall_score, roc_auc_score,
)

SANITY_DOMAINS = [
    "google.com", "youtube.com", "pinterest.com", "microsoft.com", "amazon.com", "wikipedia.org", "github.com",
    "apple.com", "linkedin.com", "flipkart.com", "irctc.co.in", "sbi.co.in", "hdfcbank.com", "paytm.com",
]

LIMITATIONS_MD = """## Limitations
1. **Domain-only model**: Operates strictly on registered domains to prevent structural shortcut learning.
2. **Multi-source 2024-2026 data**: Trained on PhiUSIIL (benign + phishing) and PhishTank (verified phishing); benign set lacks timestamps.
3. **Shared hosting excluded**: Private-PSL shared hosting domains are excluded because domain alone is non-informative.
4. **Optimistic performance**: Test scores likely overestimate real-world performance against novel attacks."""


def find_best_threshold(y_true: list[int], y_scores: list[float]) -> tuple[float, float]:
    """Find decision threshold maximizing F1 on validation split."""
    precisions, recalls, thresholds = precision_recall_curve(y_true, y_scores)
    f1s = 2 * (precisions[:-1] * recalls[:-1]) / np.maximum(precisions[:-1] + recalls[:-1], 1e-9)
    idx = int(np.argmax(f1s))
    return float(thresholds[idx]), float(f1s[idx])


def find_precision_threshold(y_true: list[int], y_scores: list[float], target_precision: float = 0.90) -> tuple[float, bool]:
    """Return lowest threshold achieving target_precision on validation, or highest-precision fallback (recall >= 0.05)."""
    precisions, recalls, thresholds = precision_recall_curve(y_true, y_scores)
    pts = [(float(t), float(p), float(r)) for p, r, t in zip(precisions[:-1], recalls[:-1], thresholds)]
    hits = [pt for pt in pts if pt[1] >= target_precision]
    if hits:
        return min(hits, key=lambda x: x[0])[0], True
    fb = [pt for pt in pts if pt[2] >= 0.05] or pts
    return max(fb, key=lambda x: (x[1], -x[0]))[0], False


def compute_metrics(y_true: list[int], y_scores: list[float], threshold: float) -> dict[str, Any]:
    """Calculate classification metrics at the specified threshold."""
    y_pred = [1 if s >= threshold else 0 for s in y_scores]
    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    if f1 > 0.98:
        print("WARNING: investigate leakage before trusting this (F1 > 0.98)")
    has_both = len(set(y_true)) > 1
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": f1,
        "pr_auc": float(average_precision_score(y_true, y_scores)) if has_both else 0.0,
        "roc_auc": float(roc_auc_score(y_true, y_scores)) if has_both else 0.0,
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=[0, 1]).tolist(),
    }


def ml_points(score: float, threshold: float) -> float:
    """Compute app ML points: 30 * (score - t) / (1 - t) if score >= t else 0."""
    if score < threshold:
        return 0.0
    if threshold >= 1.0:
        return 30.0
    return min(30.0, 30.0 * (score - threshold) / (1.0 - threshold))


def compute_sanity_rows(model: Any, threshold: float, domains: list[str] = SANITY_DOMAINS) -> list[dict[str, Any]]:
    """Score benchmark domains with a model and compute flagged status and app points."""
    if model is None:
        return []
    idx = list(model.classes_).index(1)
    probs = model.predict_proba(domains)[:, idx]
    return [{"domain": d, "score": float(probs[i]), "flagged": float(probs[i]) >= threshold, "points": ml_points(float(probs[i]), threshold)}
            for i, d in enumerate(domains)]


def get_top_ngrams(pipeline: Any, top_n: int = 20) -> tuple[list[tuple[str, float]], list[tuple[str, float]]]:
    """Extract top positive and negative character n-grams from LogisticRegression pipeline."""
    names, coefs = pipeline.named_steps["tfidf"].get_feature_names_out(), pipeline.named_steps["clf"].coef_[0]
    pos_idx, neg_idx = np.argsort(coefs)[-top_n:][::-1], np.argsort(coefs)[:top_n]
    return [(str(names[i]), float(coefs[i])) for i in pos_idx], [(str(names[i]), float(coefs[i])) for i in neg_idx]


def compute_tld_breakdown(domains: list[str], y_true: list[int], scores: list[float], threshold: float, top_n: int = 10) -> list[dict[str, Any]]:
    """Compute test metrics broken down for top most common domain endings."""
    tlds = [d.rsplit(".", 1)[-1].lower() if "." in d else d for d in domains]
    return [{"tld": t, "count": len(idx := [i for i, x in enumerate(tlds) if x == t]),
             **compute_metrics([y_true[i] for i in idx], [scores[i] for i in idx], threshold)}
            for t, _ in Counter(tlds).most_common(top_n)]


def get_top_errors(domains: list[str], y_true: list[int], scores: list[float], threshold: float, top_n: int = 10) -> tuple[list[tuple[str, float]], list[tuple[str, float]]]:
    """Extract highest-scoring false positives and lowest-scoring false negatives."""
    fps = sorted(((domains[i], float(scores[i])) for i in range(len(domains)) if y_true[i] == 0 and scores[i] >= threshold), key=lambda x: x[1], reverse=True)
    fns = sorted(((domains[i], float(scores[i])) for i in range(len(domains)) if y_true[i] == 1 and scores[i] < threshold), key=lambda x: x[1])
    return fps[:top_n], fns[:top_n]


def compute_source_recall(y_true: list[int], scores: list[float], sources: list[str], threshold: float) -> dict[str, dict[str, Any]]:
    """Compute phishing recall separately for PhiUSIIL and PhishTank on test split."""
    res: dict[str, dict[str, Any]] = {}
    for src in ("phiusiil", "phishtank"):
        idx = [i for i, (y, s) in enumerate(zip(y_true, sources)) if y == 1 and s == src]
        tp = sum(1 for i in idx if scores[i] >= threshold)
        res[src] = {"count": len(idx), "tp": tp, "recall": (tp / len(idx)) if idx else 0.0}
    return res


def format_ngram_table(pos: list[tuple[str, float]], neg: list[tuple[str, float]]) -> str:
    """Format top positive and negative n-grams side by side."""
    lines = ["| Rank | Top Phishing N-grams | Coef | Top Benign N-grams | Coef |", "|---|---|---|---|---|"]
    for i in range(max(len(pos), len(neg))):
        pn, pv = pos[i] if i < len(pos) else ("", 0.0)
        nn, nv = neg[i] if i < len(neg) else ("", 0.0)
        lines.append(f"| {i+1} | `{pn}` | {pv:+.4f} | `{nn}` | {nv:+.4f} |")
    return "\n".join(lines)


def format_error_table(errors: list[tuple[str, float]], err_type: str) -> str:
    """Format false positive or false negative table with likely causes."""
    cause = "High-risk TLD or pseudo-random tokens" if err_type == "FP" else "Reputable TLD / natural English tokens"
    lines = [f"| Rank | Domain | Score | Likely Cause ({err_type}) |", "|---|---|---|---|"]
    lines.extend(f"| {i} | `{dom}` | {sc:.4f} | {cause} |" for i, (dom, sc) in enumerate(errors, 1))
    return "\n".join(lines)


def format_tld_table(tlds: list[dict[str, Any]]) -> str:
    """Format test metrics table broken down by domain ending."""
    lines = ["| TLD | Count | Accuracy | Precision | Recall | F1 | PR-AUC |", "|---|---|---|---|---|---|---|"]
    lines.extend(f"| `.{t['tld']}` | {t['count']} | {t['accuracy']:.4f} | {t['precision']:.4f} | {t['recall']:.4f} | {t['f1']:.4f} | {t['pr_auc']:.4f} |" for t in tlds)
    return "\n".join(lines)


def format_comparison_table(all_val: dict[str, dict[str, Any]]) -> str:
    """Format validation comparison table across all candidate models and baseline."""
    lines = ["| Model | Val PR-AUC | Val ROC-AUC | Val Accuracy | Val F1 |", "|---|---|---|---|---|"]
    for key, disp in [("logistic_regression", "Logistic Regression (Char TF-IDF)"), ("random_forest", "Random Forest (Domain Features)"), ("dummy_baseline", "DummyClassifier (Most Frequent)")]:
        m = all_val.get(key, {})
        lines.append(f"| {disp} | {m.get('pr_auc', 0.0):.4f} | {m.get('roc_auc', 0.0):.4f} | {m.get('accuracy', 0.0):.4f} | {m.get('f1', 0.0):.4f} |")
    return "\n".join(lines)


def format_options_table_md(options: list[dict[str, Any]]) -> str:
    """Format threshold options table across target precisions."""
    lines = ["## Threshold Options Table (Validation Precision Targets)",
             "| Target Prec | Reached | Threshold | Val Prec | Val Rec | Test Prec | Test Rec | Test FP | Test FPR | Recent Rec | Sanity Flagged |",
             "|---|---|---|---|---|---|---|---|---|---|---|"]
    for o in options:
        lines.append(f"| {o['target']:.2f} | {'Yes' if o['reached'] else 'Fallback'} | {o['threshold']:.4f} | {o['val_prec']:.4f} | {o['val_rec']:.4f} | "
                     f"{o['test_prec']:.4f} | {o['test_rec']:.4f} | {o['test_fp']} | {o['test_fpr']:.4f} | {o['recent_rec']:.4f} | {o['sanity_flagged']}/14 |")
    return "\n".join(lines)


def format_sanity_table_md(rows: list[dict[str, Any]], heading: str) -> str:
    """Format sanity table with score, flagged yes/no, and app ML points."""
    lines = [heading, "| Domain | Score | Flagged | App Points |", "|---|---|---|---|"]
    for r in rows:
        lines.append(f"| `{r['domain']}` | {r['score']:.4f} | {'Yes' if r['flagged'] else 'No'} | {r['points']:.2f} |")
    return "\n".join(lines)


def format_dataset_and_drops_md(summary: dict[str, Any], prep_stats: dict[str, int]) -> str:
    """Format dataset counts per source/label/split and dropped-domain counts."""
    lines = ["## Dataset Summary & Dropped Domains", "| Source | Label | Split | Count |", "|---|---|---|---|"]
    for (src, lbl, spl), cnt in sorted(summary.get("counts_by_source_label_split", {}).items()):
        lines.append(f"| {src} | {lbl} | {spl} | {cnt} |")
    lines.append(f"\n- **Parse failures dropped**: {prep_stats.get('parse_failures', 0)}\n"
                 f"- **Shared hosting rows excluded**: {prep_stats.get('shared_hosting_excluded', 0)}\n"
                 f"- **Conflicted domains dropped**: {prep_stats.get('conflicts_dropped', 0)}")
    return "\n".join(lines)


def build_evaluation_markdown(
    chosen: str, thresh: float, target_reached: bool, all_val: dict, v_m: dict, t_m: dict, r_m: dict,
    v1_recent_rec: Any, options: list[dict], v1_sanity: list[dict], v2_sanity: list[dict],
    pos_ng: list, neg_ng: list, tlds: list, fps: list, fns: list, summary: dict, prep_stats: dict, src_recall: dict,
) -> str:
    """Assemble complete v2 evaluation report markdown document."""
    cm = t_m["confusion_matrix"]
    note = "" if target_reached else " *(target precision 0.90 unreachable; used highest-precision fallback with recall >= 0.05)*"
    v1_rec_str = f"{v1_recent_rec:.4f}" if v1_recent_rec is not None else "N/A"
    sec1 = f"# Model Evaluation (v2)\n\n{format_dataset_and_drops_md(summary, prep_stats)}\n\n"
    sec1 += f"## Candidate Models Comparison (Validation Set)\n{format_comparison_table(all_val)}\n\n"
    sec1 += f"## Selected Model & Threshold\n- **Chosen Model**: `{chosen}`\n- **Decision Threshold**: `{thresh:.4f}`{note}\n\n"
    sec1 += f"{format_options_table_md(options)}\n\n## Metrics Summary\n| Split | Accuracy | Precision | Recall | F1 | PR-AUC | ROC-AUC |\n|---|---|---|---|---|---|---|\n"
    for name, m in (("Validation", v_m), ("Test", t_m), ("Recent PhishTank (10%)", r_m)):
        sec1 += f"| {name} | {m['accuracy']:.4f} | {m['precision']:.4f} | {m['recall']:.4f} | {m['f1']:.4f} | {m['pr_auc']:.4f} | {m['roc_auc']:.4f} |\n"
    sec1 += f"\n- **Recent PhishTank Recall (v1 vs v2)**: v1 = `{v1_rec_str}` (never saw PhishTank) | v2 = `{r_m['recall']:.4f}`\n\n"
    sec1 += f"### Test Confusion Matrix\n`[[TN={cm[0][0]}, FP={cm[0][1]}], [FN={cm[1][0]}, TP={cm[1][1]}]]`\n\n"
    sec2 = "## Phishing Recall by Source (Test Split)\n| Source | Phishing Count | TP | Recall |\n|---|---|---|---|\n"
    sec2 += "\n".join(f"| {s} | {src_recall.get(s, {}).get('count', 0)} | {src_recall.get(s, {}).get('tp', 0)} | {src_recall.get(s, {}).get('recall', 0.0):.4f} |" for s in ("phiusiil", "phishtank"))
    sec2 += f"\n\n{format_sanity_table_md(v1_sanity, '## Sanity Table: v1')}\n\n{format_sanity_table_md(v2_sanity, '## Sanity Table: v2')}\n\n"
    sec2 += f"## Top 20 Character N-grams\n{format_ngram_table(pos_ng, neg_ng)}\n\n## Top 10 TLD Performance Breakdown\n{format_tld_table(tlds)}\n\n"
    sec2 += f"## Error Analysis (Test Split)\n### Top 10 False Positives\n{format_error_table(fps, 'FP')}\n\n### Top 10 False Negatives\n{format_error_table(fns, 'FN')}\n\n{LIMITATIONS_MD}\n"
    return sec1 + sec2
