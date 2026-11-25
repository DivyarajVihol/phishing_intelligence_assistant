# ML Data Sources

## Raw Data Files

| File | Source | Licence / Terms | Date / Range | Row Count |
|---|---|---|---|---|
| `PhiUSIIL_Phishing_URL_Dataset.csv` | UCI Machine Learning Repository (Dataset 967, PhiUSIIL Phishing URL Dataset) | CC BY 4.0 (Credit: Prasad and Chandra, 2024) | Downloaded 18-Nov-2026 | 235,795 |
| `phishtank_online-valid.csv` | PhishTank verified online phishing feed (local snapshot) | PhishTank terms of service | 2013-05-28 to 2026-11-19 | 43,638 |

## Threat Feed Notes

- **PhishTank**: Used as a second phishing source (`label=1`, `source="phishtank"`, `source_id=phish_id`, `collected_at=submission_time`) for model v2 using the local verified-online snapshot.
- **URLhaus**: Per project specification, URLhaus is malware intelligence and is not used as a phishing label source.
