# Test Report: Manual System Verification

This document provides structured manual verification test cases for the Phishing Intelligence and Investigation Assistant (Phase 16).

> **NEVER-OPEN Rule**: All URLs in this document are strictly defanged. Never visit, browse, or open raw URLs on an unprotected host.

> **Model Version Note**: The first recorded rows below were captured on 19-Nov-2026 using model v1. Model v2 became active on 25-Nov-2026 (for example, `hxxps://www[.]google[.]com/` now scores 12/100). The historical v1 results below are preserved unchanged.

---

## How to Run These Tests by Hand

1. Ensure your virtual environment is active:
   ```powershell
   .\.venv\Scripts\activate
   ```
2. Start the local server:
   ```powershell
   python manage.py runserver
   ```
3. Open `http://127.0.0.1:8000/` in your browser.
4. For each test case:
   - Enter the target URL in the submission input field.
   - Click **Investigate URL**.
   - Review the **Result** page (`/result/<id>/`), **Report** page (`/report/<id>/`), and **History** page (`/history/`).
   - Fill in the actual result columns (`Actual Level`, `Actual Score`, `Intel Result`, `ML Result`, and `Notes`) in the tables below.
5. For service-failure test cases:
   - Apply the scenario condition (e.g. clear `URLHAUS_AUTH_KEY` in `.env` or temporarily rename `ml/artifacts/model-v1.joblib`).
   - Restart `python manage.py runserver` when changing environment variables.
   - Execute the test and verify that the system handles the failure gracefully with "Unavailable" or "Not configured" states without a 500 server error.
   - Restore the original setting or artifact when finished.

---

## 1. Benign URLs

Legitimate, well-known domains and institutional websites.

| # | Defanged URL | Expected Result | Actual Level | Actual Score | Intel Result | ML Result | Notes |
| :-: | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | `hxxps://www[.]google[.]com/` | Low observed risk (score < 30, no matches) | Low observed risk | 15 | PhishTank no match, URLhaus no match | Phishing-like (0.7757) | False positive on a popular domain; contributes 15 points. Note: before the fix on 19 Nov this URL wrongly showed High 90 because the PhishTank rule ignored the "valid" field; fixed and covered by a test. |
| 2 | `www[.]google[.]com` (no scheme) | Low observed risk (score < 30, scheme assumed) | Low observed risk | 15 | PhishTank no match, URLhaus no match | Phishing-like (0.7757) | Same intel and ML result; scheme shown as assumed. |
| 3 | `hxxps://www[.]youtube[.]com/` | Low observed risk (score < 30, no matches) | Low observed risk | 2 | No matches | — | Score 2 from lexical heuristics; no intel matches. |
| 4 | `hxxps://in[.]pinterest[.]com/` | Low observed risk (score 0, clean) | Low observed risk | 0 | No matches | Not phishing-like | Clean benign domain; ML not phishing-like. |
| 5 | `hxxps://en[.]wikipedia[.]org/wiki/Phishing` | Low observed risk (score < 30, clear heuristics) | | | | | |
| 6 | `hxxps://github[.]com/` | Low observed risk (score < 30, no matches) | | | | | |
| 7 | `hxxp://cern[.]ch/` | Low observed risk or Medium risk (HTTP scheme heuristic) | | | | | |

---

## 2. Suspicious-but-Benign URLs

Legitimate domains featuring sensitive keywords, subdomains, or brand terms.

| # | Defanged URL | Expected Result | Actual Level | Actual Score | Intel Result | ML Result | Notes |
| :-: | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 8 | `hxxps://login[.]microsoftonline[.]com/` | Low observed risk (benign domain, keyword point only) | | | | | |
| 9 | `hxxps://signin[.]aws[.]amazon[.]com/` | Low observed risk (score < 30, no feed matches) | | | | | |
| 10 | `hxxps://accounts[.]google[.]com/signin` | Low observed risk (score < 30, no feed matches) | | | | | |
| 11 | `hxxps://secure[.]chase[.]com/` | Low observed risk (score < 30, no feed matches) | | | | | |
| 12 | `hxxps://paypal[.]me/` | Low observed risk (score < 30, no feed matches) | | | | | |

---

## 3. Suspicious & Known Phishing URLs (PhishTank)

Confirmed or active phishing mimicry patterns and reported lures.

| # | Defanged URL | Expected Result | Actual Level | Actual Score | Intel Result | ML Result | Notes |
| :-: | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 13 | `hxxps://secure-login-verify-83921[.]xyz/account/update` | High/Medium risk (multiple heuristics + ML phishing-like) | Medium risk | 35 | No matches | Phishing-like (0.9978, 30 pts) | Lexical 5 + ML 30; suspicious-looking made-up domain. |
| 14 | `hxxps://paypal[.]com[.]example-login[.]com/verify` | High/Medium risk (mimicry heuristic flagged) | Medium risk | 43 | No matches | Phishing-like (0.8980, 23 pts) | Obfuscation + brand 15, lexical 5, ML 23. Suspicious brand in subdomain. |
| 15 | `hxxps://orange-1[.]vercel[.]app/` | High risk (PhishTank match, score ≥ 90) | High risk | 90 | PhishTank match (record 9487360) | Not phishing-like (0.3036) | Known phishing from PhishTank. Miss caused by the domain-only v1 model on a shared hosting platform (vercel.app). |
| 16 | `hxxp://apple-id-verification-security[.]top/login` | High risk (brand keyword, suspicious TLD, HTTP) | | | | | |
| 17 | `hxxps://netflix-account-billing-update[.]club/signin` | High risk (brand keyword, suspicious TLD) | | | | | |
| 18 | `hxxps://bofa-online-banking-auth[.]info/login` | High risk (brand mimicry, suspicious TLD) | | | | | |

---

## 4. URLhaus Malware URLs

Malware distribution URLs (intelligence reported strictly as malware, never as phishing).

| # | Defanged URL | Expected Result | Actual Level | Actual Score | Intel Result | ML Result | Notes |
| :-: | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 19 | `hxxp://185[.]220[.]101[.]5/malware[.]exe` | High risk (IP host + executable path; URLhaus match if active) | | | | | |
| 20 | `hxxps://hostile-payload-dist[.]biz/dropper[.]bin` | High/Medium risk (binary extension heuristic) | | | | | |
| 21 | `hxxp://malicious-loader-c2[.]cc/payload[.]dll` | High/Medium risk (suspicious TLD, executable path) | | | | | |
| 22 | `hxxps://infected-document-host[.]site/invoice[.]iso` | High/Medium risk (suspicious container extension) | | | | | |

---

## 5. Unseen URLs

Newly observed or synthetic domains not present in public intelligence feeds.

| # | Defanged URL | Expected Result | Actual Level | Actual Score | Intel Result | ML Result | Notes |
| :-: | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 23 | `hxxps://recently-registered-fake-domain[.]top/auth` | Medium or High risk (heuristic indicators + ML score) | | | | | |
| 24 | `hxxps://unknown-subdomain-mimic[.]online/portal` | Medium or Low observed risk based on lexical rules | | | | | |
| 25 | `hxxps://new-crypto-wallet-verify[.]link/seed` | High/Medium risk (credential/crypto keyword, suspicious TLD) | | | | | |
| 26 | `hxxps://unseen-test-domain-99214[.]xyz/account` | Medium risk (numeric/hyphen domain on .xyz) | | | | | |

---

## 6. Service-Failure Cases

Resilience and fault-tolerance scenarios.

| # | Scenario / Defanged URL | Expected Result | Actual Level | Actual Score | Intel Result | ML Result | Notes |
| :-: | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 27 | **Network Off / Timeout**<br>`hxxps://network-off-test[.]com/login` | HTTP 200, Inconclusive/Sensible level, intel Unavailable | | | | | Disconnect network or set `EXTERNAL_TIMEOUT_SECONDS=0` |
| 28 | **Missing URLhaus Key**<br>`hxxps://missing-key-test[.]com/path` | HTTP 200, URLhaus marked "Not configured" | | | | | Set `URLHAUS_AUTH_KEY=""` in `.env` |
| 29 | **ML Model Missing**<br>`hxxps://missing-model-test[.]org/auth` | HTTP 200, ML marked "Unavailable", analysis saves | | | | | Temporarily rename `ml/artifacts/model-v1.joblib` |
| 30 | **All Feeds & ML Down**<br>`hxxps://all-down-test[.]net/verify` | HTTP 200, no 500 error, assessment renders cleanly | | | | | Combine network failure and missing model file |

---

## Test Execution Summary

| Test Category | Total Cases | Completed | Remaining | Tester | Date |
| :--- | :-: | :-: | :-: | :--- | :--- |
| 1. Benign URLs | 7 | 4 | 3 | Manual verification | 19-Nov-2026 |
| 2. Suspicious-but-Benign URLs | 5 | 0 | 5 | — | — |
| 3. Suspicious & Known Phishing URLs | 6 | 3 | 3 | Manual verification | 19-Nov-2026 |
| 4. URLhaus Malware URLs | 4 | 0 | 4 | — | — |
| 5. Unseen URLs | 4 | 0 | 4 | — | — |
| 6. Service-Failure Cases | 4 | 0 | 4 | — | — |
| **Total** | **30** | **7** | **23** | | |
