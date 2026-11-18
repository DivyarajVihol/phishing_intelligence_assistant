"""Model evaluation metrics, threshold selection, and error analysis."""
from collections import Counter
from typing import Any

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)

LIMITATIONS_MD = """## Limitations
1. **Domain-only model**: Operates strictly on registered domains to prevent structural shortcut learning.
2. **Single 2024 dataset**: Model was trained on PhiUSIIL (2024).
3. **No time-based test**: Dataset lacks temporal timestamps; longitudinal resilience is unverified.
4. **Dropped conflicted domains**: Shared hosting and multi-label domains were dropped during cleaning.
5. **Optimistic performance**: Test scores likely overestimate real-world performance against novel attacks."""


def find_best_threshold(y_true: list[int], y_scores: list[float]) -> tuple[float, float]:
    """Find decision threshold maximizing F1 on validation split."""
    precisions, recalls, thresholds = precision_recall_curve(y_true, y_scores)
    f1s = 2 * (precisions[:-1] * recalls[:-1]) / np.maximum(precisions[:-1] + recalls[:-1], 1e-9)
    best_idx = int(np.argmax(f1s))
    return float(thresholds[best_idx]), float(f1s[best_idx])


def compute_metrics(y_true: list[int], y_scores: list[float], threshold: float) -> dict[str, Any]:
    """Calculate classification metrics at the specified threshold."""
    y_pred = [1 if s >= threshold else 0 for s in y_scores]
    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    if f1 > 0.98:
        print("WARNING: investigate leakage before trusting this (F1 > 0.98)")

    has_both_classes = len(set(y_true)) > 1
    roc = float(roc_auc_score(y_true, y_scores)) if has_both_classes else 0.0
    pr = float(average_precision_score(y_true, y_scores)) if has_both_classes else 0.0
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1]).tolist()

    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": f1,
        "pr_auc": pr,
        "roc_auc": roc,
        "confusion_matrix": cm,
    }


def get_top_ngrams(pipeline: Any, top_n: int = 20) -> tuple[list[tuple[str, float]], list[tuple[str, float]]]:
    """Extract top positive and negative character n-grams from LogisticRegression pipeline."""
    tfidf = pipeline.named_steps["tfidf"]
    clf = pipeline.named_steps["clf"]
    names = tfidf.get_feature_names_out()
    coefs = clf.coef_[0]
    pos_idx = np.argsort(coefs)[-top_n:][::-1]
    neg_idx = np.argsort(coefs)[:top_n]
    top_pos = [(str(names[i]), float(coefs[i])) for i in pos_idx]
    top_neg = [(str(names[i]), float(coefs[i])) for i in neg_idx]
    return top_pos, top_neg


def compute_tld_breakdown(
    domains: list[str], y_true: list[int], scores: list[float], threshold: float, top_n: int = 10
) -> list[dict[str, Any]]:
    """Compute test metrics broken down for top most common domain endings."""
    tlds = [d.rsplit(".", 1)[-1].lower() if "." in d else d for d in domains]
    common_tlds = [tld for tld, _ in Counter(tlds).most_common(top_n)]
    breakdown: list[dict[str, Any]] = []

    for tld in common_tlds:
        idx = [i for i, t in enumerate(tlds) if t == tld]
        sub_y = [y_true[i] for i in idx]
        sub_scores = [scores[i] for i in idx]
        m = compute_metrics(sub_y, sub_scores, threshold)
        breakdown.append({"tld": tld, "count": len(idx), **m})
    return breakdown


def get_top_errors(
    domains: list[str], y_true: list[int], scores: list[float], threshold: float, top_n: int = 20
) -> tuple[list[tuple[str, float]], list[tuple[str, float]]]:
    """Extract highest-scoring false positives and lowest-scoring false negatives."""
    fps = [(domains[i], float(scores[i])) for i in range(len(domains)) if y_true[i] == 0 and scores[i] >= threshold]
    fns = [(domains[i], float(scores[i])) for i in range(len(domains)) if y_true[i] == 1 and scores[i] < threshold]
    fps.sort(key=lambda x: x[1], reverse=True)
    fns.sort(key=lambda x: x[1])
    return fps[:top_n], fns[:top_n]


def format_ngram_table(pos: list[tuple[str, float]], neg: list[tuple[str, float]]) -> str:
    """Format top positive and negative n-grams side by side."""
    lines = ["| Rank | Top Phishing N-grams | Coef | Top Benign N-grams | Coef |", "|---|---|---|---|---|"]
    for i in range(max(len(pos), len(neg))):
        p_name, p_val = pos[i] if i < len(pos) else ("", 0.0)
        n_name, n_val = neg[i] if i < len(neg) else ("", 0.0)
        lines.append(f"| {i+1} | `{p_name}` | {p_val:+.4f} | `{n_name}` | {n_val:+.4f} |")
    return "\n".join(lines)


def format_error_table(errors: list[tuple[str, float]], err_type: str) -> str:
    """Format false positive or false negative table with likely causes."""
    lines = [f"| Rank | Domain | Score | Likely Cause ({err_type}) |", "|---|---|---|---|"]
    for i, (dom, score) in enumerate(errors, 1):
        cause = "High-risk TLD or pseudo-random tokens" if err_type == "FP" else "Reputable TLD / natural English tokens"
        lines.append(f"| {i} | `{dom}` | {score:.4f} | {cause} |")
    return "\n".join(lines)


def format_tld_table(tlds: list[dict[str, Any]]) -> str:
    """Format test metrics table broken down by domain ending."""
    lines = ["| TLD | Count | Accuracy | Precision | Recall | F1 | PR-AUC |", "|---|---|---|---|---|---|---|"]
    for t in tlds:
        lines.append(f"| `.{t['tld']}` | {t['count']} | {t['accuracy']:.4f} | {t['precision']:.4f} | "
                     f"{t['recall']:.4f} | {t['f1']:.4f} | {t['pr_auc']:.4f} |")
    return "\n".join(lines)


def format_comparison_table(all_val: dict[str, dict[str, Any]]) -> str:
    """Format validation comparison table across all candidate models and baseline."""
    lines = ["| Model | Val PR-AUC | Val ROC-AUC | Val Accuracy | Val F1 |", "|---|---|---|---|---|"]
    labels = [
        ("logistic_regression", "Logistic Regression (Char TF-IDF)"),
        ("random_forest", "Random Forest (Domain Features)"),
        ("dummy_baseline", "DummyClassifier (Most Frequent)"),
    ]
    for key, display in labels:
        m = all_val.get(key, {})
        lines.append(f"| {display} | {m.get('pr_auc', 0.0):.4f} | {m.get('roc_auc', 0.0):.4f} | "
                     f"{m.get('accuracy', 0.0):.4f} | {m.get('f1', 0.0):.4f} |")
    return "\n".join(lines)


def build_evaluation_markdown(
    chosen: str, thresh: float, all_val: dict, v_m: dict, t_m: dict, pos_ng: list, neg_ng: list, tlds: list, fps: list, fns: list
) -> str:
    """Assemble complete evaluation report markdown document."""
    sec1 = f"# Model Evaluation (v1)\n\n## Candidate Models Comparison (Validation Set)\n{format_comparison_table(all_val)}\n\n"
    sec1 += f"## Selected Model & Threshold\n- **Chosen Model**: `{chosen}` (selected by higher validation PR-AUC)\n"
    sec1 += f"- **Decision Threshold**: `{thresh:.4f}` (tuned on validation split to maximize F1)\n\n## Metrics Summary\n"
    sec1 += "| Split | Accuracy | Precision | Recall | F1 | PR-AUC | ROC-AUC |\n|---|---|---|---|---|---|---|\n"
    sec1 += f"| Validation | {v_m['accuracy']:.4f} | {v_m['precision']:.4f} | {v_m['recall']:.4f} | {v_m['f1']:.4f} | {v_m['pr_auc']:.4f} | {v_m['roc_auc']:.4f} |\n"
    sec1 += f"| Test | {t_m['accuracy']:.4f} | {t_m['precision']:.4f} | {t_m['recall']:.4f} | {t_m['f1']:.4f} | {t_m['pr_auc']:.4f} | {t_m['roc_auc']:.4f} |\n\n"
    sec1 += f"### Test Confusion Matrix\n`[[TN={t_m['confusion_matrix'][0][0]}, FP={t_m['confusion_matrix'][0][1]}], [FN={t_m['confusion_matrix'][1][0]}, TP={t_m['confusion_matrix'][1][1]}]]`\n\n"
    sec2 = f"## Sanity Check 1: Top Character N-grams\n{format_ngram_table(pos_ng, neg_ng)}\n\n"
    sec2 += f"## Sanity Check 2: Top 10 TLD Performance Breakdown\n{format_tld_table(tlds)}\n\n"
    sec2 += f"## Sanity Check 3: Error Analysis (Test Split)\n### Top 20 False Positives\n{format_error_table(fps, 'FP')}\n\n"
    sec2 += f"### Top 20 False Negatives\n{format_error_table(fns, 'FN')}\n\n{LIMITATIONS_MD}\n"
    return sec1 + sec2
