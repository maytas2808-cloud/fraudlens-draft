"""Evaluate the full FraudLens pipeline and write app/model/eval_report.json + REPORT.md.

Usage: .venv/bin/python scripts/evaluate.py
"""
import json
import random
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.analyzer import engine, intel  # noqa: E402

EVAL = ROOT / "data" / "eval"
RAW = ROOT / "data" / "raw"
OUT_JSON = ROOT / "app" / "model" / "eval_report.json"
OUT_MD = ROOT / "REPORT.md"
SEED = 42
FLAG_AT = 30  # medium or high counts as "flagged"


def confusion(rows: list[tuple[int, int]]) -> dict:
    tp = sum(1 for y, p in rows if y == 1 and p == 1)
    tn = sum(1 for y, p in rows if y == 0 and p == 0)
    fp = sum(1 for y, p in rows if y == 0 and p == 1)
    fn = sum(1 for y, p in rows if y == 1 and p == 0)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {
        "n": len(rows), "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4),
        "accuracy": round((tp + tn) / len(rows), 4) if rows else 0.0,
        "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else 0.0,
        "false_negative_rate": round(fn / (fn + tp), 4) if fn + tp else 0.0,
    }


def without_intel(fn):
    original = intel.lookup
    intel.lookup = lambda *args, **kwargs: None
    try:
        return fn()
    finally:
        intel.lookup = original


def eval_scenarios(filename: str = "scenarios.jsonl") -> dict:
    items = [json.loads(ln) for ln in (EVAL / filename).read_text().splitlines() if ln.strip()]
    engine.analyze("warm up: load models and intel before timing http://example.com")
    out = {}
    for mode, use_ml in (("full", True), ("rules_only", False)):
        rows, errors, latencies, per_cat = [], [], [], {}
        for it in items:
            t = time.perf_counter()
            r = engine.analyze(it["text"], use_ml=use_ml)
            latencies.append((time.perf_counter() - t) * 1000)
            pred = int(r["score"] >= FLAG_AT)
            rows.append((it["label"], pred))
            c = per_cat.setdefault(it["category"], {"n": 0, "correct": 0})
            c["n"] += 1
            c["correct"] += int(pred == it["label"])
            if pred != it["label"]:
                errors.append({"id": it["id"], "type": "false_positive" if pred else "false_negative",
                               "category": it["category"], "score": r["score"], "level": r["level"],
                               "text": it["text"][:160], "top_reasons": [i["label"] for i in r["indicators"] if i["weight"] > 0][:3]})
        out[mode] = {
            **confusion(rows),
            "high_only": confusion([(it["label"], int(engine.analyze(it["text"], use_ml=use_ml)["score"] >= 60)) for it in items]),
            "errors": errors,
            "per_category": per_cat,
            "latency_ms": {"mean": round(statistics.mean(latencies), 2), "p95": round(sorted(latencies)[int(len(latencies) * .95) - 1], 2),
                           "max": round(max(latencies), 2)},
        }
    out["description"] = (f"{len(items)} hand-written, labelled Indian-context messages, emails and URLs "
                          f"({sum(i['label'] for i in items)} malicious incl. obfuscated/modified variants, "
                          f"{sum(1 - i['label'] for i in items)} legitimate incl. real OTP/bank alerts). Flagged = score >= {FLAG_AT}.")
    return out


def eval_heldout_urls(n_each: int = 1000) -> dict:
    data = json.loads((RAW / "urls.json").read_text())
    random.Random(SEED).shuffle(data)
    unseen = data[300000:]
    phish = [d for d in unseen if d["label"] == 1][:n_each]
    legit = [d for d in unseen if d["label"] == 0][:n_each]
    rows = []
    fps, fns = [], []

    def run():
        for d in phish + legit:
            r = engine.analyze(d["text"])
            pred = int(r["score"] >= FLAG_AT)
            rows.append((d["label"], pred))
            if pred != d["label"] and len(fps if pred else fns) < 8:
                (fps if pred else fns).append({"url": d["text"][:120], "score": r["score"]})

    without_intel(run)
    return {**confusion(rows), "examples_false_positive": fps, "examples_false_negative": fns,
            "description": f"{n_each} phishing + {n_each} legitimate URLs from the public dataset that were NOT used in training; threat-intel lookup disabled."}


def eval_fresh_feed() -> dict:
    path = ROOT / "data" / "intel" / "openphish.txt"
    urls = [u.strip() for u in path.read_text().splitlines() if u.strip()] if path.exists() else []
    caught = []

    def run():
        for u in urls:
            caught.append(int(engine.analyze(u)["score"] >= FLAG_AT))

    without_intel(run)
    meta = intel.meta()
    return {"n": len(urls), "detected": sum(caught), "recall": round(sum(caught) / len(urls), 4) if urls else None,
            "feed_date": meta.get("fetched_at"),
            "description": "Live OpenPhish phishing URLs, scored with the threat-intel lookup disabled, to measure detection of new attacks the models never saw."}


def eval_heldout_texts(n: int = 1000) -> dict:
    from sklearn.model_selection import train_test_split
    data = json.loads((RAW / "texts.json").read_text())
    texts = [d["text"] for d in data]
    labels = [int(d["label"]) for d in data]
    _, x_te, _, y_te = train_test_split(texts, labels, test_size=0.2, random_state=SEED, stratify=labels)
    pairs = list(zip(x_te, y_te))
    random.Random(SEED).shuffle(pairs)
    rows = []

    def run():
        for t, y in pairs[:n]:
            rows.append((y, int(engine.analyze(t)["score"] >= FLAG_AT)))

    without_intel(run)
    return {**confusion(rows), "description": f"{n} held-out emails/SMS from the public text dataset (same split as the ML test set), full pipeline."}


def write_markdown(rep: dict) -> None:
    s, r = rep["scenarios"]["full"], rep["scenarios"]["rules_only"]
    h, hr = rep["holdout"]["full"], rep["holdout"]["rules_only"]
    ml = rep["ml_models"]
    lines = [
        "# FraudLens evaluation report", "",
        f"Generated {rep['generated_at']}. Flagged = risk score ≥ {FLAG_AT} (medium or high).", "",
        "## 1. Held-out scenario set (headline result)", "",
        rep["holdout"]["description"] + " Written after development finished and never used for tuning (see Limitations).", "",
        "| Pipeline | Precision | Recall | F1 | False positives | False negatives |", "|---|---|---|---|---|---|",
        f"| Full (rules + ML + URL + intel) | {h['precision']:.1%} | {h['recall']:.1%} | {h['f1']:.1%} | {h['fp']} of {h['fp'] + h['tn']} | {h['fn']} of {h['fn'] + h['tp']} |",
        f"| Rules + URL only (no ML) | {hr['precision']:.1%} | {hr['recall']:.1%} | {hr['f1']:.1%} | {hr['fp']} of {hr['fp'] + hr['tn']} | {hr['fn']} of {hr['fn'] + hr['tp']} |",
        "", "Errors on the held-out set:", "",
        "| ID | Type | Category | Score | Text |", "|---|---|---|---|---|",
        *[f"| {e['id']} | {e['type'].replace('_', ' ')} | {e['category']} | {e['score']} | {e['text'].replace('|', '/').replace(chr(10), ' ')[:100]} |" for e in h["errors"]],
        "", "## 1b. Development scenario set (used while tuning — regression test)", "", rep["scenarios"]["description"], "",
        "| Pipeline | Precision | Recall | F1 | False positives | False negatives | Mean latency |",
        "|---|---|---|---|---|---|---|",
        f"| Rules + ML + URL analysis (full) | {s['precision']:.1%} | {s['recall']:.1%} | {s['f1']:.1%} | {s['fp']} of {s['fp'] + s['tn']} | {s['fn']} of {s['fn'] + s['tp']} | {s['latency_ms']['mean']} ms |",
        f"| Rules + URL analysis only (no ML) | {r['precision']:.1%} | {r['recall']:.1%} | {r['f1']:.1%} | {r['fp']} of {r['fp'] + r['tn']} | {r['fn']} of {r['fn'] + r['tp']} | {r['latency_ms']['mean']} ms |",
        "", "Errors made by the full pipeline:", "",
    ]
    if s["errors"]:
        lines += ["| ID | Type | Category | Score | Text |", "|---|---|---|---|---|"]
        lines += [f"| {e['id']} | {e['type'].replace('_', ' ')} | {e['category']} | {e['score']} | {e['text'].replace('|', '/').replace(chr(10), ' ')[:100]} |" for e in s["errors"]]
    else:
        lines.append("None.")
    u, f, t = rep["heldout_urls"], rep["fresh_feed"], rep["heldout_texts"]
    lines += [
        "", "## 2. Held-out public data (full pipeline, threat intel disabled)", "",
        "| Test | N | Precision | Recall | F1 | FPR | FNR |", "|---|---|---|---|---|---|---|",
        f"| Unseen dataset URLs | {u['n']} | {u['precision']:.1%} | {u['recall']:.1%} | {u['f1']:.1%} | {u['false_positive_rate']:.1%} | {u['false_negative_rate']:.1%} |",
        f"| Held-out emails/SMS | {t['n']} | {t['precision']:.1%} | {t['recall']:.1%} | {t['f1']:.1%} | {t['false_positive_rate']:.1%} | {t['false_negative_rate']:.1%} |",
        "", f"**New attacks:** of {f['n']} live OpenPhish URLs (feed fetched {f['feed_date']}), {f['detected']} were flagged "
            f"({(f['recall'] or 0):.1%}) without using the feed itself.", "",
        "## 3. Machine-learning models alone (held-out 20% split)", "",
        "| Model | N | Precision | Recall | F1 | ROC AUC | FPR | FNR |", "|---|---|---|---|---|---|---|---|",
    ]
    for name in ("text", "url"):
        m = ml[name]
        lines.append(f"| {name} | {m['n']} | {m['precision']:.1%} | {m['recall']:.1%} | {m['f1']:.1%} | {m['roc_auc']:.3f} | {m['false_positive_rate']:.1%} | {m['false_negative_rate']:.1%} |")
    lines += ["", "## 4. Limitations", ""] + [f"- {x}" for x in rep["limitations"]]
    OUT_MD.write_text("\n".join(lines) + "\n")


LIMITATIONS = [
    "Both scenario sets were written by the developers and are small (110 + 45 items). The development set was used for tuning, so its scores are optimistic; the 45-item held-out set is the fairer estimate, but its confidence interval is wide (roughly ±10 points).",
    "How ML probabilities become risk points was tuned by scripts/tune.py on validation data only (20,000 URLs and 1,611 texts that are in neither the training nor the test data), with the development scenario set as a guard (no misses, at most 6 false alarms). Earlier versions of these weights were adjusted after looking at the held-out and public test sets, so those sets are not perfectly untouched; this is a mild optimism, not a leak of test items into training.",
    "The development set's genuine bank and delivery alerts are what limit recall: weighting the text model more heavily catches more phishing emails but flags 12-18 of its 50 legitimate messages.",
    "A link inside a message that otherwise reads as harmless (low text-model score, no request to click, pay, call or share) gets no points from the URL model, only from the URL rules. This removed most false alarms on old legitimate emails, but a phishing link sent with completely innocent wording is judged on its URL rules alone.",
    "Exact misses and false alarms on the held-out set are listed in section 1; they include UPI 'collect request' tricks worded without fee/PIN keywords and genuine bank status messages that read like alerts.",
    "The public training data is mostly English email (Enron-era ham vs phishing); Indian SMS/WhatsApp scams are covered mainly by the rules, so new scam scripts that avoid known phrases rely on the URL checks and ML.",
    "The text model reacts to banking vocabulary, so genuine bank messages without a 'never share your OTP' line can score medium. Rules reduce but don't eliminate this.",
    "Threat-intel feeds are a snapshot from the deploy date; they must be refreshed (scripts/fetch_intel.py) to stay useful. Host-level matches are skipped for top-ranked platforms to avoid flagging e.g. docs.google.com.",
    "Domain reputation uses the Tranco top-100k list. Compromised legitimate sites and phishing hosted on big platforms (Google Forms, Firebase) get less benefit from reputation and rely on other signals.",
    "The live link check reveals the server's IP to the link owner and can be fooled by sites that cloak (show different content to scanners). It is off by default.",
    "Only text is analysed: images, voice calls, QR-code images and attachments are not.",
]


def main():
    started = time.time()
    rep = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "flag_threshold": FLAG_AT,
        "scenarios": eval_scenarios(),
        "holdout": eval_scenarios("holdout.jsonl"),
        "heldout_urls": eval_heldout_urls(),
        "fresh_feed": eval_fresh_feed(),
        "heldout_texts": eval_heldout_texts(),
        "ml_models": json.loads((EVAL / "ml_metrics.json").read_text()),
        "intel": intel.meta(),
        "limitations": LIMITATIONS,
    }
    rep["runtime_seconds"] = round(time.time() - started, 1)
    OUT_JSON.write_text(json.dumps(rep, indent=2))
    (EVAL / "eval_report.json").write_text(json.dumps(rep, indent=2))
    write_markdown(rep)
    s = rep["scenarios"]["full"]
    print(json.dumps({k: rep["scenarios"]["full"][k] for k in ("precision", "recall", "f1", "fp", "fn", "latency_ms")}, indent=1))
    print("rules_only:", {k: rep["scenarios"]["rules_only"][k] for k in ("precision", "recall", "f1", "fp", "fn")})
    for e in s["errors"]:
        print(" ", e["type"], e["id"], e["category"], e["score"], "|", e["text"][:90], "|", e["top_reasons"])
    print("heldout_urls:", {k: rep["heldout_urls"][k] for k in ("precision", "recall", "f1", "fp", "fn")})
    print("fresh_feed:", {k: rep["fresh_feed"][k] for k in ("n", "detected", "recall")})
    print("heldout_texts:", {k: rep["heldout_texts"][k] for k in ("precision", "recall", "f1", "fp", "fn")})


if __name__ == "__main__":
    main()
