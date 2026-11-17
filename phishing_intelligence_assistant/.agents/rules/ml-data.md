---
trigger: model_decision
description: Use when working on dataset preparation, feature extraction, model training, evaluation, model artifacts, or the ml/ folder.
---

# ML and data rules (full spec: `docs/04_ML_DATA_SPEC.md`)

- Binary task: 1 = phishing, 0 = benign, URL text and structure only.
- PhishTank (verified) = phishing positives. A separate documented dataset = benign. URLhaus is never a phishing label.
- Keep `ml/data/raw/` untouched. Log row counts at every cleaning step. Fixed `random_state=42`.
- Split grouped by registered domain; add a time-based test. Choose the threshold on validation only, never on test.
- One feature path for training and the website: `url_analyzer.features.extract_features` and `ml_engine.predict.build_row`. Save the whole sklearn `Pipeline` with joblib plus a metadata JSON.
- Report accuracy, precision, recall, F1, confusion matrix, PR-AUC, ROC-AUC, and an error analysis. Near-perfect scores mean investigate leakage. Promise no accuracy target.
- Call the output "model score", not "probability".
