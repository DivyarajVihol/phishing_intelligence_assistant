# Model Evaluation (v2)

## Dataset Summary & Dropped Domains
| Source | Label | Split | Count |
|---|---|---|---|
| phishtank | 1 | recent_test | 499 |
| phishtank | 1 | test | 694 |
| phishtank | 1 | train | 3117 |
| phishtank | 1 | validation | 680 |
| phiusiil | 0 | test | 19851 |
| phiusiil | 0 | train | 92262 |
| phiusiil | 0 | validation | 19815 |
| phiusiil | 1 | test | 6346 |
| phiusiil | 1 | train | 29944 |
| phiusiil | 1 | validation | 6582 |

- **Parse failures dropped**: 20
- **Shared hosting rows excluded**: 35097
- **Conflicted domains dropped**: 149

## Candidate Models Comparison (Validation Set)
| Model | Val PR-AUC | Val ROC-AUC | Val Accuracy | Val F1 |
|---|---|---|---|---|
| Logistic Regression (Char TF-IDF) | 0.7363 | 0.8358 | 0.7890 | 0.6315 |
| Random Forest (Domain Features) | 0.4901 | 0.6616 | 0.6865 | 0.4451 |
| DummyClassifier (Most Frequent) | 0.2682 | 0.5000 | 0.7318 | 0.0000 |

## Selected Model & Threshold
- **Chosen Model**: `logistic_regression`
- **Decision Threshold**: `0.7771`

## Threshold Options Table (Validation Precision Targets)
| Target Prec | Reached | Threshold | Val Prec | Val Rec | Test Prec | Test Rec | Test FP | Test FPR | Recent Rec | Sanity Flagged |
|---|---|---|---|---|---|---|---|---|---|---|
| 0.80 | Yes | 0.6807 | 0.8001 | 0.4822 | 0.8017 | 0.4922 | 857 | 0.0432 | 0.7836 | 3/14 |
| 0.90 | Yes | 0.7771 | 0.9001 | 0.3872 | 0.8967 | 0.4006 | 325 | 0.0164 | 0.7174 | 1/14 |
| 0.95 | Yes | 0.8444 | 0.9501 | 0.3202 | 0.9404 | 0.3294 | 147 | 0.0074 | 0.6493 | 1/14 |

## Metrics Summary
| Split | Accuracy | Precision | Recall | F1 | PR-AUC | ROC-AUC |
|---|---|---|---|---|---|---|
| Validation | 0.8241 | 0.9001 | 0.3872 | 0.5415 | 0.7363 | 0.8358 |
| Test | 0.8310 | 0.8967 | 0.4006 | 0.5538 | 0.7354 | 0.8385 |
| Recent PhishTank (10%) | 0.7174 | 1.0000 | 0.7174 | 0.8355 | 0.0000 | 0.0000 |

- **Recent PhishTank Recall (v1 vs v2)**: v1 = `0.8437` (never saw PhishTank) | v2 = `0.7174`

### Test Confusion Matrix
`[[TN=19526, FP=325], [FN=4220, TP=2820]]`

## Phishing Recall by Source (Test Split)
| Source | Phishing Count | TP | Recall |
|---|---|---|---|
| phiusiil | 6346 | 2472 | 0.3895 |
| phishtank | 694 | 348 | 0.5014 |

## Sanity Table: v1
| Domain | Score | Flagged | App Points |
|---|---|---|---|
| `google.com` | 0.7757 | Yes | 14.78 |
| `youtube.com` | 0.5872 | Yes | 1.99 |
| `pinterest.com` | 0.4177 | No | 0.00 |
| `microsoft.com` | 0.6659 | Yes | 7.33 |
| `amazon.com` | 0.6829 | Yes | 8.49 |
| `wikipedia.org` | 0.1400 | No | 0.00 |
| `github.com` | 0.4741 | No | 0.00 |
| `apple.com` | 0.4516 | No | 0.00 |
| `linkedin.com` | 0.7140 | Yes | 10.59 |
| `flipkart.com` | 0.4246 | No | 0.00 |
| `irctc.co.in` | 0.7719 | Yes | 14.53 |
| `sbi.co.in` | 0.6667 | Yes | 7.39 |
| `hdfcbank.com` | 0.3398 | No | 0.00 |
| `paytm.com` | 0.5895 | Yes | 2.15 |

## Sanity Table: v2
| Domain | Score | Flagged | App Points |
|---|---|---|---|
| `google.com` | 0.8637 | Yes | 11.66 |
| `youtube.com` | 0.5782 | No | 0.00 |
| `pinterest.com` | 0.4067 | No | 0.00 |
| `microsoft.com` | 0.6377 | No | 0.00 |
| `amazon.com` | 0.6494 | No | 0.00 |
| `wikipedia.org` | 0.1450 | No | 0.00 |
| `github.com` | 0.4208 | No | 0.00 |
| `apple.com` | 0.5018 | No | 0.00 |
| `linkedin.com` | 0.6811 | No | 0.00 |
| `flipkart.com` | 0.5081 | No | 0.00 |
| `irctc.co.in` | 0.7086 | No | 0.00 |
| `sbi.co.in` | 0.6603 | No | 0.00 |
| `hdfcbank.com` | 0.3466 | No | 0.00 |
| `paytm.com` | 0.6275 | No | 0.00 |

## Top 20 Character N-grams
| Rank | Top Phishing N-grams | Coef | Top Benign N-grams | Coef |
|---|---|---|---|---|
| 1 | `.cf` | +9.2092 | `.go` | -7.1281 |
| 2 | `.ga` | +9.0058 | `.ie` | -5.8542 |
| 3 | `.ml` | +7.0681 | `.gov` | -5.5028 |
| 4 | `.top` | +6.0031 | `.se` | -5.3340 |
| 5 | `cf` | +5.0100 | `.ca` | -4.9996 |
| 6 | `gq` | +4.9751 | `.gr` | -4.8681 |
| 7 | `.gq` | +4.9683 | `.or` | -4.4516 |
| 8 | `.to` | +4.9494 | `.it` | -4.4499 |
| 9 | `.ir` | +4.6162 | `.org` | -4.4450 |
| 10 | `ml` | +4.6049 | `.ed` | -4.3798 |
| 11 | `.cc` | +4.4709 | `.edu` | -4.3682 |
| 12 | `.sh` | +4.3396 | `.be` | -4.3199 |
| 13 | `xy` | +4.0092 | `.jp` | -4.2335 |
| 14 | `dns` | +3.8247 | `.nl` | -3.8615 |
| 15 | `.t` | +3.6864 | `.no` | -3.7549 |
| 16 | `.tk` | +3.6833 | `.cz` | -3.7458 |
| 17 | `host` | +3.6384 | `gov` | -3.6997 |
| 18 | `mail` | +3.4870 | `.tv` | -3.6410 |
| 19 | `.sit` | +3.4354 | `.ch` | -3.5980 |
| 20 | `.site` | +3.4354 | `.e` | -3.5730 |

## Top 10 TLD Performance Breakdown
| TLD | Count | Accuracy | Precision | Recall | F1 | PR-AUC |
|---|---|---|---|---|---|---|
| `.com` | 13621 | 0.7982 | 0.8399 | 0.2066 | 0.3316 | 0.5743 |
| `.org` | 2685 | 0.9285 | 0.9091 | 0.0498 | 0.0943 | 0.3385 |
| `.uk` | 927 | 0.9493 | 1.0000 | 0.0408 | 0.0784 | 0.2008 |
| `.net` | 866 | 0.7448 | 0.8202 | 0.2626 | 0.3978 | 0.6301 |
| `.de` | 543 | 0.8490 | 0.8889 | 0.0899 | 0.1633 | 0.4057 |
| `.au` | 449 | 0.9131 | 0.0000 | 0.0000 | 0.0000 | 0.1943 |
| `.it` | 300 | 0.9200 | 1.0000 | 0.0769 | 0.1429 | 0.2266 |
| `.jp` | 291 | 0.9656 | 1.0000 | 0.1667 | 0.2857 | 0.4535 |
| `.nl` | 289 | 0.8858 | 1.0000 | 0.0571 | 0.1081 | 0.2856 |
| `.ru` | 268 | 0.6828 | 0.7802 | 0.5221 | 0.6256 | 0.7633 |

## Error Analysis (Test Split)
### Top 10 False Positives
| Rank | Domain | Score | Likely Cause (FP) |
|---|---|---|---|
| 1 | `iatuc0e2xz.ga` | 0.9858 | High-risk TLD or pseudo-random tokens |
| 2 | `website999.in` | 0.9809 | High-risk TLD or pseudo-random tokens |
| 3 | `myip.com` | 0.9762 | High-risk TLD or pseudo-random tokens |
| 4 | `elmot.xyz` | 0.9745 | High-risk TLD or pseudo-random tokens |
| 5 | `geocode.xyz` | 0.9719 | High-risk TLD or pseudo-random tokens |
| 6 | `onlinecoin.club` | 0.9713 | High-risk TLD or pseudo-random tokens |
| 7 | `dete.shop` | 0.9696 | High-risk TLD or pseudo-random tokens |
| 8 | `bng.gal` | 0.9669 | High-risk TLD or pseudo-random tokens |
| 9 | `anzhuo.cn` | 0.9659 | High-risk TLD or pseudo-random tokens |
| 10 | `topleft.shop` | 0.9633 | High-risk TLD or pseudo-random tokens |

### Top 10 False Negatives
| Rank | Domain | Score | Likely Cause (FN) |
|---|---|---|---|
| 1 | `amurt.org.uk` | 0.0146 | Reputable TLD / natural English tokens |
| 2 | `agus.org` | 0.0228 | Reputable TLD / natural English tokens |
| 3 | `tvad.org` | 0.0259 | Reputable TLD / natural English tokens |
| 4 | `tuns.org` | 0.0308 | Reputable TLD / natural English tokens |
| 5 | `weps.org` | 0.0372 | Reputable TLD / natural English tokens |
| 6 | `eduscore.org` | 0.0373 | Reputable TLD / natural English tokens |
| 7 | `ordinarymagazine.org` | 0.0380 | Reputable TLD / natural English tokens |
| 8 | `frontierairlines.org` | 0.0399 | Reputable TLD / natural English tokens |
| 9 | `junkielondon.co.uk` | 0.0404 | Reputable TLD / natural English tokens |
| 10 | `ddo.jp` | 0.0405 | Reputable TLD / natural English tokens |

## Limitations
1. **Domain-only model**: Operates strictly on registered domains to prevent structural shortcut learning.
2. **Multi-source 2024-2026 data**: Trained on PhiUSIIL (benign + phishing) and PhishTank (verified phishing); benign set lacks timestamps.
3. **Shared hosting excluded**: Private-PSL shared hosting domains are excluded because domain alone is non-informative.
4. **Optimistic performance**: Test scores likely overestimate real-world performance against novel attacks.
