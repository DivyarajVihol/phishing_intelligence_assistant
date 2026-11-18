"""Unit tests for dataset preparation pipeline."""
import csv
import tempfile
import unittest
from pathlib import Path

from ml.training.prepare_data import (
    assign_split,
    convert_label,
    deduplicate_domain_labels,
    parse_rows,
    prepare_dataset,
    remove_conflicted_domains,
    remove_duplicate_urls,
)


class TestPrepareData(unittest.TestCase):
    """Test suite for data preparation, cleaning, deduplication, and splitting."""

    def test_label_conversion(self) -> None:
        """Assert raw label 1 becomes 0, 0 becomes 1, and invalid inputs return None."""
        self.assertEqual(convert_label("1"), 0)
        self.assertEqual(convert_label("0"), 1)
        self.assertEqual(convert_label("  1  "), 0)
        self.assertEqual(convert_label("  0  "), 1)
        self.assertIsNone(convert_label(""))
        self.assertIsNone(convert_label("2"))
        self.assertIsNone(convert_label("malicious"))

    def test_model_text_is_only_registered_domain(self) -> None:
        """Assert model_text extracts only lowercase registered domain without path or subdomains."""
        rows = [
            {"url": "https://sub.portal.example.com:8443/login/verify?token=123", "label": 1},
            {"url": "http://www.google.co.uk/search?q=test", "label": 0},
            {"url": "not a valid url at all :::", "label": 1},
        ]
        parsed, failures = parse_rows(rows)
        self.assertEqual(failures, 1)
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0]["model_text"], "example.com")
        self.assertEqual(parsed[0]["registered_domain"], "example.com")
        self.assertEqual(parsed[0]["url"], "https://sub.portal.example.com:8443/login/verify?token=123")
        self.assertEqual(parsed[1]["model_text"], "google.co.uk")
        self.assertEqual(parsed[1]["registered_domain"], "google.co.uk")

    def test_exact_duplicates_removed(self) -> None:
        """Assert exact duplicate raw URLs are removed, retaining first occurrence."""
        rows = [
            {"url": "https://example.com/a", "label": 0},
            {"url": "https://example.com/b", "label": 0},
            {"url": "https://example.com/a", "label": 0},
        ]
        unique = remove_duplicate_urls(rows)
        self.assertEqual(len(unique), 2)
        self.assertEqual([r["url"] for r in unique], ["https://example.com/a", "https://example.com/b"])

    def test_deduplicate_domain_labels(self) -> None:
        """Assert one row kept per (registered_domain, label) pair."""
        rows = [
            {"url": "https://example.com/1", "registered_domain": "example.com", "label": 0},
            {"url": "https://example.com/2", "registered_domain": "example.com", "label": 0},
            {"url": "https://sample.com/1", "registered_domain": "sample.com", "label": 1},
        ]
        deduped = deduplicate_domain_labels(rows)
        self.assertEqual(len(deduped), 2)
        self.assertEqual(deduped[0]["url"], "https://example.com/1")
        self.assertEqual(deduped[1]["url"], "https://sample.com/1")

    def test_domain_with_both_labels_dropped(self) -> None:
        """Assert registered domain appearing with both benign and phishing labels is dropped."""
        rows = [
            {"registered_domain": "conflicted.com", "label": 0},
            {"registered_domain": "conflicted.com", "label": 1},
            {"registered_domain": "benign-only.com", "label": 0},
            {"registered_domain": "phish-only.com", "label": 1},
        ]
        clean, dropped_count = remove_conflicted_domains(rows)
        self.assertEqual(dropped_count, 1)
        self.assertEqual(len(clean), 2)
        remaining_domains = {r["registered_domain"] for r in clean}
        self.assertEqual(remaining_domains, {"benign-only.com", "phish-only.com"})

    def test_split_is_deterministic(self) -> None:
        """Assert split assignment produces identical results across repeated runs."""
        domain = "secure-banking-portal.org"
        split_1 = assign_split(domain)
        split_2 = assign_split(domain)
        self.assertEqual(split_1, split_2)
        self.assertIn(split_1, {"train", "validation", "test"})

    def test_no_registered_domain_appears_in_two_splits(self) -> None:
        """Assert every registered domain maps to exactly one split."""
        domains = [f"domain-{i}.com" for i in range(100)]
        split_map: dict[str, set[str]] = {}
        for d in domains:
            s = assign_split(d)
            split_map.setdefault(d, set()).add(s)
        for d, splits in split_map.items():
            self.assertEqual(len(splits), 1, f"Domain {d} assigned multiple splits: {splits}")

    def test_end_to_end_synthetic_data(self) -> None:
        """Assert end-to-end prepare_dataset executes correctly on synthetic CSV."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            raw_csv = tmp_path / "raw.csv"
            out_csv = tmp_path / "dataset.csv"

            # Synthetic raw CSV with header matching raw file
            with open(raw_csv, mode="w", encoding="utf-8-sig", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["URL", "label"])
                writer.writerow(["https://www.clean-site.org", "1"])  # benign -> label 0
                writer.writerow(["https://www.clean-site.org", "1"])  # exact duplicate
                writer.writerow(["https://phishing-site.xyz/login", "0"])  # phishing -> label 1
                writer.writerow(["https://both-site.com/benign", "1"])  # conflict benign
                writer.writerow(["https://both-site.com/evil", "0"])  # conflict phishing
                writer.writerow(["ftp://invalid-scheme.org", "1"])  # parse failure (unsupported scheme)
                writer.writerow(["", "0"])  # empty url

            result = prepare_dataset(raw_csv, out_csv)
            self.assertEqual(len(result), 2)
            self.assertTrue(out_csv.exists())

            with open(out_csv, mode="r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                rows = list(reader)

            self.assertEqual(len(rows), 2)
            domains = {r["registered_domain"] for r in rows}
            self.assertEqual(domains, {"clean-site.org", "phishing-site.xyz"})
            self.assertNotIn("both-site.com", domains)
            for r in rows:
                self.assertIn(r["split"], {"train", "validation", "test"})
                self.assertEqual(r["source"], "phiusiil")
                self.assertEqual(r["model_text"], r["registered_domain"])
