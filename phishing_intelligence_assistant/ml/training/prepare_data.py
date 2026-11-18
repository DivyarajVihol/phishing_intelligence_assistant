"""Prepare and clean the dataset for model training."""
import csv
import hashlib
from pathlib import Path
from typing import Optional

from apps.url_analyzer.parser import InvalidURLError, parse_url

SOURCE_NAME = "phiusiil"
FIELDNAMES = ["url", "label", "source", "source_id", "collected_at", "registered_domain", "model_text", "split"]


def convert_label(raw_label: str) -> Optional[int]:
    """Convert raw dataset label (1=legitimate, 0=phishing) to 0=benign, 1=phishing."""
    clean = raw_label.strip()
    if clean == "1":
        return 0
    if clean == "0":
        return 1
    return None


def assign_split(registered_domain: str) -> str:
    """Deterministically assign domain to train, validation, or test split."""
    h = hashlib.sha256(registered_domain.lower().encode("utf-8")).hexdigest()
    val = int(h[:8], 16) % 100
    if val < 70:
        return "train"
    if val < 85:
        return "validation"
    return "test"


def load_raw_rows(filepath: Path) -> list[dict]:
    """Load raw dataset rows, converting labels and dropping malformed entries."""
    rows: list[dict] = []
    with open(filepath, mode="r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            raw_url = (row.get("URL") or "").strip()
            raw_label = row.get("label") or ""
            label = convert_label(raw_label)
            if not raw_url or label is None:
                continue
            rows.append({
                "url": raw_url, "label": label, "source": SOURCE_NAME,
                "source_id": str(reader.line_num), "collected_at": "",
            })
    return rows


def parse_rows(rows: list[dict]) -> tuple[list[dict], int]:
    """Parse URLs, attach registered domain and model_text, dropping failures."""
    parsed_rows: list[dict] = []
    failures = 0
    for item in rows:
        try:
            p = parse_url(item["url"])
            if not p.registered_domain:
                failures += 1
                continue
            reg_dom = p.registered_domain.lower()
            item["parsed"] = p
            item["registered_domain"] = reg_dom
            item["model_text"] = reg_dom
            parsed_rows.append(item)
        except (InvalidURLError, ValueError, Exception):
            failures += 1
    return parsed_rows, failures


def compute_leakage_stats(parsed_rows: list[dict]) -> dict[int, dict[str, float]]:
    """Compute structural leakage metrics per class on raw URLs."""
    counts: dict[int, dict[str, int]] = {
        0: {"total": 0, "path": 0, "https": 0, "www": 0, "subdomain": 0},
        1: {"total": 0, "path": 0, "https": 0, "www": 0, "subdomain": 0},
    }
    for item in parsed_rows:
        lbl, p = item["label"], item["parsed"]
        counts[lbl]["total"] += 1
        counts[lbl]["path"] += 1 if (p.path and p.path != "/") else 0
        counts[lbl]["https"] += 1 if p.scheme == "https" else 0
        counts[lbl]["www"] += 1 if p.hostname.startswith("www.") else 0
        counts[lbl]["subdomain"] += 1 if (p.subdomain and p.subdomain != "www") else 0

    stats: dict[int, dict[str, float]] = {}
    for lbl in (0, 1):
        tot = counts[lbl]["total"] or 1
        stats[lbl] = {k: (v / tot) * 100.0 for k, v in counts[lbl].items()}
    return stats


def print_leakage_report(stats: dict[int, dict[str, float]]) -> None:
    """Print leakage metrics comparing benign and phishing classes."""
    print("\n--- Leakage Report (Raw URLs) ---")
    for lbl, name in ((0, "Benign"), (1, "Phishing")):
        s = stats[lbl]
        print(f"Class {lbl} ({name}): path={s['path']:.1f}%, https={s['https']:.1f}%, "
              f"www={s['www']:.1f}%, sub_not_www={s['subdomain']:.1f}%")


def remove_duplicate_urls(rows: list[dict]) -> list[dict]:
    """Remove exact duplicate raw URLs preserving first occurrence."""
    seen: set[str] = set()
    unique: list[dict] = []
    for r in rows:
        if r["url"] not in seen:
            seen.add(r["url"])
            unique.append(r)
    return unique


def deduplicate_domain_labels(rows: list[dict]) -> list[dict]:
    """Keep one row per (registered_domain, label) pair."""
    seen: set[tuple[str, int]] = set()
    deduped: list[dict] = []
    for r in rows:
        pair = (r["registered_domain"], r["label"])
        if pair not in seen:
            seen.add(pair)
            deduped.append(r)
    return deduped


def remove_conflicted_domains(rows: list[dict]) -> tuple[list[dict], int]:
    """Drop registered domains appearing with both benign and phishing labels."""
    labels: dict[str, set[int]] = {}
    for r in rows:
        labels.setdefault(r["registered_domain"], set()).add(r["label"])
    conflicts = {dom for dom, lbls in labels.items() if len(lbls) > 1}
    clean = [r for r in rows if r["registered_domain"] not in conflicts]
    return clean, len(conflicts)


def write_dataset(rows: list[dict], output_path: Path) -> None:
    """Write processed records to CSV using DictWriter."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, mode="w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r[k] for k in FIELDNAMES})


def print_counts(label: str, rows: list[dict]) -> None:
    """Print row counts per class for a list of rows."""
    b = sum(1 for r in rows if r["label"] == 0)
    p = sum(1 for r in rows if r["label"] == 1)
    print(f"{label}: Total={len(rows)} (Benign={b}, Phishing={p})")


def print_split_sizes(rows: list[dict]) -> None:
    """Print row counts per split and per class."""
    for split_name in ("train", "validation", "test"):
        s_rows = [r for r in rows if r["split"] == split_name]
        b = sum(1 for r in s_rows if r["label"] == 0)
        p = sum(1 for r in s_rows if r["label"] == 1)
        print(f"Split {split_name:10s}: Total={len(s_rows):6d} (Benign={b:6d}, Phishing={p:6d})")


def prepare_dataset(raw_path: Path, output_path: Path) -> list[dict]:
    """Execute end-to-end dataset preparation and write output CSV."""
    rows = load_raw_rows(raw_path)
    print_counts("Step 1 - Loaded raw valid rows", rows)
    parsed_rows, failures = parse_rows(rows)
    print(f"Step 2 - Dropped parse failures: {failures}")
    print_counts("After URL parsing", parsed_rows)
    print_leakage_report(compute_leakage_stats(parsed_rows))
    rows_u = remove_duplicate_urls(parsed_rows)
    print_counts("Step 3 - After duplicate URL removal", rows_u)
    rows_dl = deduplicate_domain_labels(rows_u)
    print_counts("Step 4 - After (domain, label) deduplication", rows_dl)
    clean_rows, dropped = remove_conflicted_domains(rows_dl)
    print(f"Dropped conflicted domains with both labels: {dropped}")
    print_counts("Step 5 - Class balance after conflict removal", clean_rows)
    for r in clean_rows:
        r["split"] = assign_split(r["registered_domain"])
    print("\nStep 6 - Split sizes per class:")
    print_split_sizes(clean_rows)
    print("\nStep 7 - Time-based test: SKIPPED (no date column in PhiUSIIL dataset)")
    write_dataset(clean_rows, output_path)
    print(f"Wrote processed dataset to: {output_path} ({len(clean_rows)} rows)")
    return clean_rows


def main() -> None:
    """Entry point for python -m ml.training.prepare_data."""
    base_dir = Path(__file__).resolve().parent.parent
    raw_file = base_dir / "data" / "raw" / "PhiUSIIL_Phishing_URL_Dataset.csv"
    processed_file = base_dir / "data" / "processed" / "dataset.csv"
    prepare_dataset(raw_file, processed_file)


if __name__ == "__main__":
    main()
