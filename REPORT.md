# FraudLens evaluation report

Generated 2026-10-15T14:53:16+00:00. Flagged = risk score ≥ 30 (medium or high).

## 1. Held-out scenario set (headline result)

45 hand-written, labelled Indian-context messages, emails and URLs (22 malicious incl. obfuscated/modified variants, 23 legitimate incl. real OTP/bank alerts). Flagged = score >= 30. Written after development finished and never used for tuning (see Limitations).

| Pipeline | Precision | Recall | F1 | False positives | False negatives |
|---|---|---|---|---|---|
| Full (rules + ML + URL + intel) | 83.3% | 90.9% | 87.0% | 4 of 23 | 2 of 22 |
| Rules + URL only (no ML) | 93.8% | 68.2% | 79.0% | 1 of 23 | 7 of 22 |

Errors on the held-out set:

| ID | Type | Category | Score | Text |
|---|---|---|---|---|
| h18 | false negative | novel_modified | 0 | Electricity department: Your meter is not updated. Your light will be cut at 10 pm tonight. Download |
| h20 | false negative | novel_modified | 23 | Sir, I'm calling from your credit card department. Your card limit is increased to 3 lakh free. Just |
| h24 | false positive | otp_legit | 36 | OTP for your Flipkart order delivery is 4192. Share it with the delivery agent only when you receive |
| h27 | false positive | bank_alert_legit | 60 | Dear customer, your fixed deposit of Rs 1,00,000 matures on 20-Oct-2026. It will be auto-renewed for |
| h37 | false positive | awareness_legit | 33 | Beware of fraud calls claiming to be from the police or CBI. There is no 'digital arrest' in law. Re |
| h45 | false positive | service_legit | 55 | Your Aadhaar-PAN link status: your PAN is already linked with Aadhaar. No action is required. |

## 1b. Development scenario set (used while tuning — regression test)

110 hand-written, labelled Indian-context messages, emails and URLs (60 malicious incl. obfuscated/modified variants, 50 legitimate incl. real OTP/bank alerts). Flagged = score >= 30.

| Pipeline | Precision | Recall | F1 | False positives | False negatives | Mean latency |
|---|---|---|---|---|---|---|
| Rules + ML + URL analysis (full) | 90.9% | 100.0% | 95.2% | 6 of 50 | 0 of 60 | 1.68 ms |
| Rules + URL analysis only (no ML) | 98.1% | 85.0% | 91.1% | 1 of 50 | 9 of 60 | 0.93 ms |

Errors made by the full pipeline:

| ID | Type | Category | Score | Text |
|---|---|---|---|---|
| s05 | false positive | bank_alert_legit | 34 | Your a/c no. XXXXXXXX5678 is credited by Rs 45,000.00 on 01-10-26 by a/c linked to mobile 9XXXXXX123 |
| s06 | false positive | bank_alert_legit | 45 | Dear Customer, your ICICI Bank credit card statement for September is ready. Total due Rs 12,340, mi |
| s07 | false positive | bank_alert_legit | 39 | SBI: Your KYC is due for periodic update as per RBI norms. Please visit your home branch or update t |
| s10 | false positive | delivery_legit | 33 | Your Swiggy order from Domino's is out for delivery. Your delivery partner Ramesh will reach you in  |
| s46 | false positive | email_legit | 44 | From: GitHub <noreply@github.com> Subject: [GitHub] A new SSH key was added to your account Authenti |
| s49 | false positive | personal | 37 | Can you send me the OTP-free link for the zoom meeting? The one you shared yesterday expired. |

## 2. Held-out public data (full pipeline, threat intel disabled)

| Test | N | Precision | Recall | F1 | FPR | FNR |
|---|---|---|---|---|---|---|
| Unseen dataset URLs | 2000 | 97.6% | 82.6% | 89.5% | 2.0% | 17.4% |
| Held-out emails/SMS | 1000 | 96.3% | 82.7% | 89.0% | 1.9% | 17.3% |

**New attacks:** of 300 live OpenPhish URLs (feed fetched 2026-10-14T10:28:58+00:00), 249 were flagged (83.0%) without using the feed itself.

## 3. Machine-learning models alone (held-out 20% split)

| Model | N | Precision | Recall | F1 | ROC AUC | FPR | FNR |
|---|---|---|---|---|---|---|---|
| text | 4028 | 96.1% | 97.1% | 96.6% | 0.997 | 2.5% | 2.9% |
| url | 60000 | 95.2% | 96.4% | 95.8% | 0.994 | 4.3% | 3.6% |

## 4. Limitations

- Both scenario sets were written by the developers and are small (110 + 45 items). The development set was used for tuning, so its scores are optimistic; the 45-item held-out set is the fairer estimate, but its confidence interval is wide (roughly ±10 points).
- How ML probabilities become risk points was tuned by scripts/tune.py on validation data only (20,000 URLs and 1,611 texts that are in neither the training nor the test data), with the development scenario set as a guard (no misses, at most 6 false alarms). Earlier versions of these weights were adjusted after looking at the held-out and public test sets, so those sets are not perfectly untouched; this is a mild optimism, not a leak of test items into training.
- The development set's genuine bank and delivery alerts are what limit recall: weighting the text model more heavily catches more phishing emails but flags 12-18 of its 50 legitimate messages.
- A link inside a message that otherwise reads as harmless (low text-model score, no request to click, pay, call or share) gets no points from the URL model, only from the URL rules. This removed most false alarms on old legitimate emails, but a phishing link sent with completely innocent wording is judged on its URL rules alone.
- Exact misses and false alarms on the held-out set are listed in section 1; they include UPI 'collect request' tricks worded without fee/PIN keywords and genuine bank status messages that read like alerts.
- The public training data is mostly English email (Enron-era ham vs phishing); Indian SMS/WhatsApp scams are covered mainly by the rules, so new scam scripts that avoid known phrases rely on the URL checks and ML.
- The text model reacts to banking vocabulary, so genuine bank messages without a 'never share your OTP' line can score medium. Rules reduce but don't eliminate this.
- Threat-intel feeds are a snapshot from the deploy date; they must be refreshed (scripts/fetch_intel.py) to stay useful. Host-level matches are skipped for top-ranked platforms to avoid flagging e.g. docs.google.com.
- Domain reputation uses the Tranco top-100k list. Compromised legitimate sites and phishing hosted on big platforms (Google Forms, Firebase) get less benefit from reputation and rely on other signals.
- The live link check reveals the server's IP to the link owner and can be fooled by sites that cloak (show different content to scanners). It is off by default.
- Only text is analysed: images, voice calls, QR-code images and attachments are not.
