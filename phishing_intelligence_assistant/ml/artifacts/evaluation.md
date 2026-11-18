# Model Evaluation (v1)

## Candidate Models Comparison (Validation Set)
| Model | Val PR-AUC | Val ROC-AUC | Val Accuracy | Val F1 |
|---|---|---|---|---|
| Logistic Regression (Char TF-IDF) | 0.7188 | 0.8325 | 0.7917 | 0.6177 |
| Random Forest (Domain Features) | 0.4614 | 0.6592 | 0.6854 | 0.4287 |
| DummyClassifier (Most Frequent) | 0.2518 | 0.5000 | 0.7482 | 0.0000 |

## Selected Model & Threshold
- **Chosen Model**: `logistic_regression` (selected by higher validation PR-AUC)
- **Decision Threshold**: `0.5579` (tuned on validation split to maximize F1)

## Metrics Summary
| Split | Accuracy | Precision | Recall | F1 | PR-AUC | ROC-AUC |
|---|---|---|---|---|---|---|
| Validation | 0.8166 | 0.6436 | 0.6085 | 0.6256 | 0.7188 | 0.8325 |
| Test | 0.8181 | 0.6315 | 0.6104 | 0.6208 | 0.7144 | 0.8349 |

### Test Confusion Matrix
`[[TN=17579, FP=2282], [FN=2496, TP=3911]]`

## Sanity Check 1: Top Character N-grams
| Rank | Top Phishing N-grams | Coef | Top Benign N-grams | Coef |
|---|---|---|---|---|
| 1 | `.cf` | +9.4986 | `.go` | -6.7803 |
| 2 | `.ga` | +9.0606 | `.ie` | -5.2858 |
| 3 | `.ml` | +7.4325 | `.gov` | -5.2498 |
| 4 | `.top` | +6.1291 | `.ca` | -4.9011 |
| 5 | `cf` | +5.4702 | `.se` | -4.7412 |
| 6 | `.gq` | +5.0157 | `.gr` | -4.5358 |
| 7 | `.to` | +4.8954 | `.it` | -4.4881 |
| 8 | `gq` | +4.8236 | `.ed` | -4.2145 |
| 9 | `ml` | +4.8089 | `.or` | -4.2046 |
| 10 | `.ir` | +4.6428 | `.edu` | -4.2025 |
| 11 | `xy` | +4.5070 | `.jp` | -4.1857 |
| 12 | `dns` | +4.3805 | `gov` | -4.1732 |
| 13 | `.sh` | +4.1613 | `.org` | -4.1216 |
| 14 | `.t` | +4.0763 | `.be` | -4.0731 |
| 15 | `.cc` | +4.0514 | `.cz` | -3.8607 |
| 16 | `.tk` | +3.9057 | `.nl` | -3.6722 |
| 17 | `.cn` | +3.7688 | `.no` | -3.4448 |
| 18 | `yz` | +3.7446 | `.tv` | -3.4240 |
| 19 | `host` | +3.5533 | `.e` | -3.3895 |
| 20 | `site` | +3.4712 | `.ch` | -3.3650 |

## Sanity Check 2: Top 10 TLD Performance Breakdown
| TLD | Count | Accuracy | Precision | Recall | F1 | PR-AUC |
|---|---|---|---|---|---|---|
| `.com` | 13392 | 0.7813 | 0.5254 | 0.4677 | 0.4949 | 0.5582 |
| `.org` | 2683 | 0.9385 | 0.8269 | 0.2161 | 0.3426 | 0.3691 |
| `.uk` | 924 | 0.9535 | 0.7143 | 0.1087 | 0.1887 | 0.2159 |
| `.net` | 853 | 0.7011 | 0.5154 | 0.6302 | 0.5671 | 0.6221 |
| `.de` | 538 | 0.8587 | 0.5789 | 0.2683 | 0.3667 | 0.4046 |
| `.au` | 449 | 0.9042 | 0.1667 | 0.0256 | 0.0444 | 0.1928 |
| `.it` | 294 | 0.9286 | 0.4000 | 0.1000 | 0.1600 | 0.1987 |
| `.jp` | 291 | 0.9691 | 0.8000 | 0.3333 | 0.4706 | 0.4134 |
| `.nl` | 288 | 0.8715 | 0.3333 | 0.0882 | 0.1395 | 0.2824 |
| `.ru` | 261 | 0.5900 | 0.5524 | 0.8992 | 0.6844 | 0.7608 |

## Sanity Check 3: Error Analysis (Test Split)
### Top 20 False Positives
| Rank | Domain | Score | Likely Cause (FP) |
|---|---|---|---|
| 1 | `iatuc0e2xz.ga` | 0.9858 | High-risk TLD or pseudo-random tokens |
| 2 | `website999.in` | 0.9853 | High-risk TLD or pseudo-random tokens |
| 3 | `bng.gal` | 0.9835 | High-risk TLD or pseudo-random tokens |
| 4 | `elmot.xyz` | 0.9817 | High-risk TLD or pseudo-random tokens |
| 5 | `myip.com` | 0.9758 | High-risk TLD or pseudo-random tokens |
| 6 | `onlinecoin.club` | 0.9757 | High-risk TLD or pseudo-random tokens |
| 7 | `geocode.xyz` | 0.9748 | High-risk TLD or pseudo-random tokens |
| 8 | `dns.pl` | 0.9692 | High-risk TLD or pseudo-random tokens |
| 9 | `n-s.cn` | 0.9675 | High-risk TLD or pseudo-random tokens |
| 10 | `anzhuo.cn` | 0.9664 | High-risk TLD or pseudo-random tokens |
| 11 | `financeupdates.net` | 0.9630 | High-risk TLD or pseudo-random tokens |
| 12 | `dnsbl.info` | 0.9620 | High-risk TLD or pseudo-random tokens |
| 13 | `dmbi.online` | 0.9590 | High-risk TLD or pseudo-random tokens |
| 14 | `update.ph` | 0.9589 | High-risk TLD or pseudo-random tokens |
| 15 | `dete.shop` | 0.9586 | High-risk TLD or pseudo-random tokens |
| 16 | `saddns.net` | 0.9585 | High-risk TLD or pseudo-random tokens |
| 17 | `starship.xyz` | 0.9563 | High-risk TLD or pseudo-random tokens |
| 18 | `spaceprof.xyz` | 0.9539 | High-risk TLD or pseudo-random tokens |
| 19 | `topleft.shop` | 0.9526 | High-risk TLD or pseudo-random tokens |
| 20 | `club386.com` | 0.9515 | High-risk TLD or pseudo-random tokens |

### Top 20 False Negatives
| Rank | Domain | Score | Likely Cause (FN) |
|---|---|---|---|
| 1 | `amurt.org.uk` | 0.0143 | Reputable TLD / natural English tokens |
| 2 | `tvad.org` | 0.0308 | Reputable TLD / natural English tokens |
| 3 | `valleylibrary.org` | 0.0354 | Reputable TLD / natural English tokens |
| 4 | `frontierairlines.org` | 0.0371 | Reputable TLD / natural English tokens |
| 5 | `eduscore.org` | 0.0371 | Reputable TLD / natural English tokens |
| 6 | `tuns.org` | 0.0393 | Reputable TLD / natural English tokens |
| 7 | `junkielondon.co.uk` | 0.0405 | Reputable TLD / natural English tokens |
| 8 | `ddo.jp` | 0.0442 | Reputable TLD / natural English tokens |
| 9 | `ordinarymagazine.org` | 0.0444 | Reputable TLD / natural English tokens |
| 10 | `busanopen.org` | 0.0450 | Reputable TLD / natural English tokens |
| 11 | `guideofgeorgia.org` | 0.0480 | Reputable TLD / natural English tokens |
| 12 | `agus.org` | 0.0486 | Reputable TLD / natural English tokens |
| 13 | `penninejuniors.co.uk` | 0.0508 | Reputable TLD / natural English tokens |
| 14 | `librarycollection.org` | 0.0512 | Reputable TLD / natural English tokens |
| 15 | `worldfoodstory.co.uk` | 0.0563 | Reputable TLD / natural English tokens |
| 16 | `defensenews.org` | 0.0569 | Reputable TLD / natural English tokens |
| 17 | `grandages.org.my` | 0.0572 | Reputable TLD / natural English tokens |
| 18 | `mixpools.org` | 0.0591 | Reputable TLD / natural English tokens |
| 19 | `green5news.org` | 0.0601 | Reputable TLD / natural English tokens |
| 20 | `cmfoods.co.uk` | 0.0662 | Reputable TLD / natural English tokens |

## Limitations
1. **Domain-only model**: Operates strictly on registered domains to prevent structural shortcut learning.
2. **Single 2024 dataset**: Model was trained on PhiUSIIL (2024).
3. **No time-based test**: Dataset lacks temporal timestamps; longitudinal resilience is unverified.
4. **Dropped conflicted domains**: Shared hosting and multi-label domains were dropped during cleaning.
5. **Optimistic performance**: Test scores likely overestimate real-world performance against novel attacks.
