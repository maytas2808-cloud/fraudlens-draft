"""Tune how ML probabilities turn into risk points, using validation data only.

Runs the pipeline once on the validation URLs and texts (see splits.py) and on the development
scenario set, records each score's parts, then re-scores every weight combination in a grid.
Picks the combination with the best mean recall whose false-positive rates stay within budget.

Usage: .venv/bin/python scripts/tune.py   (prints the result; copy it into engine.TEXT_ML / URL_ML)
"""
import itertools
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from app.analyzer import engine, intel  # noqa: E402
from splits import text_splits, url_splits  # noqa: E402

FLAG_AT = 30
BUDGET = {"url_fpr": 0.02, "text_fpr": 0.045, "dev_fp": 6, "dev_fn": 0}


def record(text: str, label: int) -> dict:
    r = engine.analyze(text)
    b = r["breakdown"]
    urls = []
    for u in r["urls"]:
        rule_pts = sum(i["weight"] for i in u["indicators"])
        urls.append((rule_pts, u["ml"]["probability"] if u["ml"] else None, any(i["id"] == "reputation" for i in u["indicators"])))
    return {"y": label, "base": b["wording"] + b["email_headers"] + b["combinations"], "benign": b["benign_context"],
            "p_text": r["ml"]["text"]["probability"] if r["ml"]["text"] else None, "urls": urls, "intel": b["threat_intel"]}


def score(item: dict, text_cfg: dict, url_cfg: dict) -> int:
    pts = item["base"]
    if item["p_text"] is not None:
        pts += engine._ml_points(item["p_text"], text_cfg)
    best = 0
    for rule_pts, p, rep in item["urls"]:
        ml_pts = engine._ml_points(p, url_cfg) if p is not None else 0
        if rep and ml_pts > 0:
            ml_pts //= 3
        if item["benign"] and ml_pts > 0:
            ml_pts = round(ml_pts * url_cfg["benign_context_factor"])
        best = max(best, rule_pts + ml_pts)
    s = max(0, min(100, pts + best))
    return max(s, 90) if item["intel"] else s


def rates(items, text_cfg, url_cfg):
    tp = fp = fn = tn = 0
    for it in items:
        flagged = score(it, text_cfg, url_cfg) >= FLAG_AT
        tp += it["y"] and flagged
        fn += it["y"] and not flagged
        fp += (not it["y"]) and flagged
        tn += (not it["y"]) and not flagged
    return {"recall": tp / max(tp + fn, 1), "fpr": fp / max(fp + tn, 1), "fp": fp, "fn": fn}


def main():
    original = intel.lookup
    intel.lookup = lambda *a, **k: None
    val_urls = url_splits()["val"]
    phish = [d for d in val_urls if d["label"] == 1][:2500]
    legit = [d for d in val_urls if d["label"] == 0][:2500]
    urls = [record(d["text"], d["label"]) for d in phish + legit]
    texts = [record(t, y) for t, y in text_splits()["val"]]
    intel.lookup = original
    dev = [record(it["text"], it["label"]) for it in
           (json.loads(ln) for ln in (ROOT / "data/eval/scenarios.jsonl").read_text().splitlines() if ln.strip())]
    print(f"recorded {len(urls)} URLs, {len(texts)} texts, {len(dev)} dev scenarios", flush=True)

    def evaluate(tc, uc):
        return rates(urls, tc, uc), rates(texts, tc, uc), rates(dev, tc, uc)

    current = evaluate(engine.TEXT_ML, engine.URL_ML)
    print("current:", engine.TEXT_ML, engine.URL_ML, current)
    if "--explore" in sys.argv:
        explore(evaluate)
        return
    best = None
    for tp, ts, up, us, bf in itertools.product((0.4, 0.5, 0.6), (80, 96, 110, 130),
                                                 (0.4, 0.5, 0.6, 0.7, 0.8), (60, 80, 100, 130, 170, 200), (1.0, 0.5, 0.25, 0.0)):
        tc = {**engine.TEXT_ML, "pivot": tp, "slope": ts}
        uc = {**engine.URL_ML, "pivot": up, "slope": us, "low": min(up, engine.URL_ML["low"]), "benign_context_factor": bf}
        u, t, d = evaluate(tc, uc)
        if u["fpr"] > BUDGET["url_fpr"] or t["fpr"] > BUDGET["text_fpr"] or d["fp"] > BUDGET["dev_fp"] or d["fn"] > BUDGET["dev_fn"]:
            continue
        key = (u["recall"] + t["recall"]) / 2 - (u["fpr"] + t["fpr"]) / 2 - 0.001 * d["fp"]
        if best is None or key > best[0]:
            best = (key, tc, uc, u, t, d)
    if best is None:
        print("no combination meets the budget", BUDGET)
        return
    _, tc, uc, u, t, d = best
    print("best:", json.dumps({"TEXT_ML": tc, "URL_ML": uc}), "\n urls", u, "\n texts", t, "\n dev", d)


def explore(evaluate):
    rows = []
    for tp, ts, up, us, bf in itertools.product((0.4, 0.5, 0.6), (80, 96, 130),
                                                 (0.5, 0.6, 0.7, 0.8), (80, 130, 200), (1.0, 0.5, 0.0)):
        tc = {**engine.TEXT_ML, "pivot": tp, "slope": ts}
        uc = {**engine.URL_ML, "pivot": up, "slope": us, "benign_context_factor": bf}
        u, t, d = evaluate(tc, uc)
        rows.append((tp, ts, up, us, bf, u, t, d))
    for name, ok in (("url only", lambda u, t, d: u["fpr"] <= .02), ("text only", lambda u, t, d: t["fpr"] <= .045),
                     ("both", lambda u, t, d: u["fpr"] <= .02 and t["fpr"] <= .045),
                     ("both+dev<=6fp", lambda u, t, d: u["fpr"] <= .02 and t["fpr"] <= .045 and d["fp"] <= 6)):
        for bf in (1.0, 0.5, 0.0):
            c = [r for r in rows if r[4] == bf and ok(*r[5:])]
            if c:
                r = max(c, key=lambda r: r[5]["recall"] + r[6]["recall"])
                print(name, r[:5], "url %.3f/%.4f text %.3f/%.4f dev fp%d fn%d" % (
                    r[5]["recall"], r[5]["fpr"], r[6]["recall"], r[6]["fpr"], r[7]["fp"], r[7]["fn"]))


if __name__ == "__main__":
    main()
