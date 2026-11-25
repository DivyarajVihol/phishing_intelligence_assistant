"""Prepare and clean the dataset for model training."""
import csv
import hashlib
import json
from pathlib import Path
from typing import Optional

import tldextract

from apps.url_analyzer.parser import InvalidURLError, parse_url

FIELDNAMES = ["url", "label", "source", "source_id", "collected_at", "registered_domain", "model_text", "split"]
_PRIVATE_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)


def convert_label(raw_label: str) -> Optional[int]:
    """Convert raw dataset label (1=legitimate, 0=phishing) to 0=benign, 1=phishing."""
    clean = raw_label.strip()
    return 0 if clean == "1" else (1 if clean == "0" else None)


def assign_split(registered_domain: str) -> str:
    """Deterministically assign domain to train, validation, or test split."""
    h = hashlib.sha256(registered_domain.lower().encode("utf-8")).hexdigest()
    val = int(h[:8], 16) % 100
    return "train" if val < 70 else ("validation" if val < 85 else "test")


def load_raw_rows(filepath: Path) -> list[dict]:
    """Load PhiUSIIL raw rows, converting labels and dropping malformed entries."""
    rows: list[dict] = []
    with open(filepath, mode="r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            raw_url, label = (row.get("URL") or "").strip(), convert_label(row.get("label") or "")
            if raw_url and label is not None:
                rows.append({"url": raw_url, "label": label, "source": "phiusiil", "source_id": str(reader.line_num), "collected_at": ""})
    return rows


def load_phishtank_rows(filepath: Path) -> list[dict]:
    """Load verified online PhishTank rows as label=1 phishing records."""
    rows: list[dict] = []
    with open(filepath, mode="r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            raw_url = (row.get("url") or "").strip()
            if raw_url and (row.get("verified") or "").strip().lower() == "yes" and (row.get("online") or "").strip().lower() == "yes":
                rows.append({
                    "url": raw_url, "label": 1, "source": "phishtank",
                    "source_id": (row.get("phish_id") or "").strip(), "collected_at": (row.get("submission_time") or "").strip(),
                })
    return rows


def parse_rows(rows: list[dict]) -> tuple[list[dict], int]:
    """Parse URLs, attach registered domain and model_text, dropping failures."""
    parsed_rows, failures = [], 0
    for item in rows:
        try:
            p = parse_url(item["url"])
            if not p.registered_domain:
                failures += 1
                continue
            reg_dom = p.registered_domain.lower()
            item["parsed"], item["registered_domain"], item["model_text"] = p, reg_dom, reg_dom
            parsed_rows.append(item)
        except (InvalidURLError, ValueError, Exception):
            failures += 1
    return parsed_rows, failures


def exclude_shared_hosting(parsed_rows: list[dict]) -> tuple[list[dict], int]:
    """Exclude domains whose private-aware PSL suffix differs from public suffix."""
    kept, excluded = [], 0
    for item in parsed_rows:
        p = item["parsed"]
        if not p.is_ip_host and _PRIVATE_EXTRACTOR(p.hostname).suffix != p.suffix:
            excluded += 1
            continue
        kept.append(item)
    return kept, excluded


def compute_leakage_stats(parsed_rows: list[dict]) -> dict[int, dict[str, float]]:
    """Compute structural leakage metrics per class on raw URLs."""
    stats: dict[int, dict[str, float]] = {}
    for lbl in (0, 1):
        sub = [r["parsed"] for r in parsed_rows if r["label"] == lbl]
        tot = len(sub) or 1
        stats[lbl] = {
            "path": sum(1 for p in sub if p.path and p.path != "/") * 100.0 / tot,
            "https": sum(1 for p in sub if p.scheme == "https") * 100.0 / tot,
            "www": sum(1 for p in sub if p.hostname.startswith("www.")) * 100.0 / tot,
            "subdomain": sum(1 for p in sub if p.subdomain and p.subdomain != "www") * 100.0 / tot,
        }
    return stats


def print_leakage_report(stats: dict[int, dict[str, float]]) -> None:
    """Print leakage metrics comparing benign and phishing classes."""
    print("\n--- Leakage Report (Raw URLs) ---")
    for lbl, name in ((0, "Benign"), (1, "Phishing")):
        s = stats[lbl]
        print(f"Class {lbl} ({name}): path={s['path']:.1f}%, https={s['https']:.1f}%, www={s['www']:.1f}%, sub_not_www={s['subdomain']:.1f}%")


def remove_duplicate_urls(rows: list[dict]) -> list[dict]:
    """Remove exact duplicate raw URLs preserving first occurrence."""
    seen: set[str] = set()
    return [r for r in rows if not (r["url"] in seen or seen.add(r["url"]))]


def deduplicate_domain_labels(rows: list[dict]) -> list[dict]:
    """Keep one row per (registered_domain, label) pair."""
    seen: set[tuple[str, int]] = set()
    return [r for r in rows if not ((r["registered_domain"], r["label"]) in seen or seen.add((r["registered_domain"], r["label"])))]


def remove_conflicted_domains(rows: list[dict]) -> tuple[list[dict], int]:
    """Drop registered domains appearing with both benign and phishing labels."""
    labels: dict[str, set[int]] = {}
    for r in rows:
        labels.setdefault(r["registered_domain"], set()).add(r["label"])
    conflicts = {dom for dom, lbls in labels.items() if len(lbls) > 1}
    return [r for r in rows if r["registered_domain"] not in conflicts], len(conflicts)


def assign_splits_with_recent(rows: list[dict], recent_frac: float = 0.10) -> set[str]:
    """Hold out newest PhishTank domains as recent_test and hash-split the rest."""
    pt_rows = sorted((r for r in rows if r["source"] == "phishtank" and r["collected_at"]), key=lambda r: r["collected_at"])
    n_recent = max(1, int(len(pt_rows) * recent_frac)) if pt_rows else 0
    recent_domains = {r["registered_domain"] for r in pt_rows[-n_recent:]} if n_recent else set()
    for r in rows:
        r["split"] = "recent_test" if r["registered_domain"] in recent_domains else assign_split(r["registered_domain"])
    return recent_domains


def write_dataset(rows: list[dict], output_path: Path) -> None:
    """Write processed records to CSV."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, mode="w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r[k] for k in FIELDNAMES})


def print_counts(label: str, rows: list[dict]) -> None:
    """Print row counts per class for a list of rows."""
    b = sum(1 for r in rows if r["label"] == 0)
    print(f"{label}: Total={len(rows)} (Benign={b}, Phishing={len(rows) - b})")


def print_split_sizes(rows: list[dict]) -> None:
    """Print row counts per split and per class."""
    for s in ("train", "validation", "test", "recent_test"):
        sr = [r for r in rows if r["split"] == s]
        b = sum(1 for r in sr if r["label"] == 0)
        print(f"Split {s:11s}: Total={len(sr):6d} (Benign={b:6d}, Phishing={len(sr) - b:6d})")


def prepare_dataset(raw_path: Path, output_path: Path, phishtank_path: Optional[Path] = None) -> list[dict]:
    """Execute end-to-end dataset preparation and write output CSV."""
    rows = load_raw_rows(raw_path)
    if phishtank_path is not None and phishtank_path.is_file():
        rows.extend(load_phishtank_rows(phishtank_path))
    print_counts("Step 1 - Loaded raw valid rows", rows)
    parsed_rows, failures = parse_rows(rows)
    kept_rows, shared_excluded = exclude_shared_hosting(parsed_rows)
    print(f"Step 2 - Parse failures={failures}, Shared hosting excluded={shared_excluded}")
    print_counts("After URL parsing & shared-hosting filter", kept_rows)
    print_leakage_report(compute_leakage_stats(kept_rows))
    rows_dl = deduplicate_domain_labels(remove_duplicate_urls(kept_rows))
    print_counts("Step 3-4 - After URL & (domain, label) dedup", rows_dl)
    clean_rows, dropped = remove_conflicted_domains(rows_dl)
    print(f"Step 5 - Dropped conflicted domains: {dropped}")
    print_counts("Class balance after conflict removal", clean_rows)
    recent_domains = assign_splits_with_recent(clean_rows)
    print(f"\nStep 6 - Split sizes (recent_test domains={len(recent_domains)}):")
    print_split_sizes(clean_rows)
    write_dataset(clean_rows, output_path)
    (output_path.parent / "prep_stats.json").write_text(
        json.dumps({"parse_failures": failures, "shared_hosting_excluded": shared_excluded, "conflicts_dropped": dropped}, indent=2),
        encoding="utf-8",
    )
    print(f"Wrote processed dataset to: {output_path} ({len(clean_rows)} rows)")
    return clean_rows


def main() -> None:
    """Entry point for python -m ml.training.prepare_data."""
    b = Path(__file__).resolve().parent.parent
    prepare_dataset(b / "data" / "raw" / "PhiUSIIL_Phishing_URL_Dataset.csv", b / "data" / "processed" / "dataset.csv", b / "data" / "raw" / "phishtank_online-valid.csv")


if __name__ == "__main__":
    main()
