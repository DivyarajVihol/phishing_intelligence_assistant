# 04. ML and data spec

## Task
Binary classifier on **URL text and structure only**: label `1` = phishing, `0` = benign. No HTML, screenshots, JavaScript or file content.

## Data sources and labels
| Source | Role | Rule |
|---|---|---|
| PhishTank | Phishing positives | Verified records only. Keep source ID, status, submission time. Access per PhishTank's current terms. |
| Separate benign dataset | Benign negatives | A documented source. Never infer "benign" from absence in a threat feed. Check its licence. |
| URLhaus | Malware intelligence only | **Never** used as a phishing label in v1. |

**Structure-leak warning:** if benign data is only bare domains and phishing data has long paths, the model just learns "has a path". The benign set must contain full URLs comparable to the phishing set. If it cannot, say so in `evaluation.md` and evaluate with host-only features as a second run.

## Files
- `ml/data/raw/` untouched downloads (never edited). `ml/data/processed/` cleaned output. Both git-ignored.
- Cleaned CSV columns: `url, label, source, source_id, collected_at, registered_domain, split`.
- `ml/data/README.md` records, for each raw file: source, URL, download date, licence/terms, row count.

## Preparation (`ml/training/prepare_data.py`, reproducible, fixed `random_state=42`)
1. Load raw, keep original URL, drop empty/malformed rows (log the counts).
2. Parse each URL with `url_analyzer.parser`; drop failures (log count).
3. Remove exact duplicates, then duplicates after normalisation.
4. Print class balance. Use `class_weight="balanced"` if skewed.
5. Split **grouped by registered domain** (`GroupShuffleSplit`): train 70 / validation 15 / test 15. No domain appears in two splits.
6. Also build a **time-based test**: newest phishing records (by `collected_at`) held out. Report it separately.

## Features (one definition, used by training AND the website)
- Numeric: from `url_analyzer.features.extract_features` in the fixed order of `FEATURE_NAMES` (length, host length, registered-domain length, dot/hyphen/digit/special-character counts and ratios, subdomain count, IP host, HTTPS, path depth and length, query length and parameter count, `@`/`%` counts, suspicious-token count, non-ASCII/punycode flag, hostname entropy).
- Text: the `normalized` URL string, for character n-gram TF-IDF.
- `ml_engine.predict.build_row(parsed)` returns a one-row DataFrame with `url_text` + all numeric columns. Training imports this same function. **Training and prediction must never build features separately.**

## Models (compare, pick, record why)
1. Baseline: Logistic Regression on character TF-IDF (`analyzer="char"`, `ngram_range=(3,5)`, capped `max_features`).
2. Random Forest on the numeric features.
Optional comparison: HistGradientBoosting. Each is a full `sklearn.pipeline.Pipeline` taking the DataFrame row, so preprocessing is saved inside it.

## Evaluation (`ml/training/evaluate.py`)
Report on validation, test, and time-based test: accuracy, precision, recall, F1, confusion matrix, PR-AUC, ROC-AUC. Pick the decision **threshold on validation only**, never on test. Then:
- List the top false positives and false negatives with the likely cause.
- Do not claim any accuracy target. Very high scores on a first run are a **red flag** (duplicates, leakage), investigate before celebrating.

## Artifacts
- `ml/artifacts/model-v1.joblib` is the complete pipeline.
- `ml/artifacts/model-v1.json` has: model_name, version, trained_at, sklearn/pandas versions, FEATURE_NAMES, threshold, dataset summary (rows per class and split, source files with SHA-256), metrics.
- `ml/artifacts/evaluation.md` has the human-readable metrics and error analysis.
- Commit the model and JSON only if the model is small (about 25 MB or less); otherwise git-ignore it and document how to regenerate.

## Presenting the score
Call it "model score". Do not present it as a calibrated probability unless calibration was evaluated.

## Decisions made on 18-Nov-2026
- **Standard library `csv` instead of pandas**: pandas 3.x is blocked by machine application-control policies, so data preparation uses the standard library `csv.DictReader` and `csv.DictWriter`.
- **Registered-domain-only model**: Leakage analysis of raw PhiUSIIL URLs revealed structural leakage: 100.0% of legitimate URLs are bare homepages (`https://www.<domain>`) with 0.0% paths, 100.0% HTTPS, and 100.0% `www.`, whereas phishing URLs vary (27.2% path, 48.7% HTTPS, 41.4% `www.`, 54.4% non-www subdomain). Training on full URLs would result in shortcut learning on structural artifacts rather than domain reputation. The model is trained on lowercase `registered_domain` only.
- **Hash-based domain split**: Domains are split deterministically via SHA-256 hash of the registered domain (first 8 hex digits as an integer modulo 100: < 70 train [70%], 70–84 validation [15%], >= 85 test [15%]), guaranteeing zero cross-split domain overlap.
- **No time-based test**: The PhiUSIIL dataset contains no collection dates or timestamps; the time-based holdout evaluation is skipped.
- **PhishTank not used**: PhishTank developer account registration was disabled on 18-Nov-2026, so only the documented PhiUSIIL dataset was utilized.
