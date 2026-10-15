"""Train the text and URL models and export them as JSON for dependency-free inference.

Usage: .venv/bin/python scripts/train.py [text] [url]
Splits are defined in scripts/splits.py; the validation and test parts are never trained on.
"""
import json
import sys
import time
from pathlib import Path

import numpy as np
from scipy.sparse import hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support, roc_auc_score, roc_curve

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from app.analyzer.ml import url_for_model, url_parts  # noqa: E402
from splits import text_splits, url_splits  # noqa: E402

MODEL_DIR = ROOT / "app" / "model"
EVAL_DIR = ROOT / "data" / "eval"


def metrics(y_true, prob, threshold=0.5) -> dict:
    pred = (prob >= threshold).astype(int)
    p, r, f, _ = precision_recall_fscore_support(y_true, pred, average="binary")
    tn, fp, fn, tp = confusion_matrix(y_true, pred).ravel()
    fpr, tpr, _ = roc_curve(y_true, prob)
    return {
        "n": int(len(y_true)), "precision": round(float(p), 4), "recall": round(float(r), 4), "f1": round(float(f), 4),
        "roc_auc": round(float(roc_auc_score(y_true, prob)), 4), "accuracy": round(float((tp + tn) / len(y_true)), 4),
        "tp": int(tp), "tn": int(tn), "fp": int(fp), "fn": int(fn),
        "false_positive_rate": round(float(fp / (fp + tn)), 4), "false_negative_rate": round(float(fn / (fn + tp)), 4),
        "recall_at_1pct_fpr": round(float(tpr[fpr <= 0.01].max()), 4),
    }


def export_group(vec: TfidfVectorizer, coef: np.ndarray, analyzer: str, ngram_range=None) -> dict:
    idf = vec.idf_
    group = {"analyzer": analyzer,
             "features": {term: [round(float(idf[i]), 4), round(float(coef[i]), 5)] for term, i in vec.vocabulary_.items()}}
    if ngram_range:
        group["ngram_range"] = list(ngram_range)
    return group


def fit(vecs, x_tr, y_tr, x_te, C):
    xtr = hstack([v.fit_transform(x_tr) for v, _ in vecs]).tocsr()
    clf = LogisticRegression(C=C, max_iter=3000, class_weight="balanced").fit(xtr, y_tr)
    prob = clf.predict_proba(hstack([v.transform(x_te) for v, _ in vecs]).tocsr())[:, 1]
    groups, start = [], 0
    for v, (analyzer, ngram) in vecs:
        n = len(v.vocabulary_)
        groups.append(export_group(v, clf.coef_[0][start:start + n], analyzer, ngram))
        start += n
    return {"intercept": float(clf.intercept_[0]), "groups": groups}, prob


def train_text():
    s = text_splits()
    x_tr, y_tr = [t for t, _ in s["train"]], np.array([y for _, y in s["train"]])
    x_te, y_te = [t for t, _ in s["test"]], np.array([y for _, y in s["test"]])
    vec = TfidfVectorizer(lowercase=True, ngram_range=(1, 2), min_df=3, max_df=0.9, max_features=40000,
                          sublinear_tf=True, token_pattern=r"(?u)\b\w\w+\b")
    model, prob = fit([(vec, ("word", (1, 2)))], x_tr, y_tr, x_te, C=4.0)
    m = metrics(y_te, prob)
    m["dataset"] = ("ealvaradob/phishing-dataset texts.json (emails + SMS); 80/20 stratified split (seed 42), "
                    f"10% of the train part held back for score tuning; trained on {len(x_tr)}")
    return {"kind": "text", **model}, m


def train_url():
    s = url_splits()
    x_tr, y_tr = [url_for_model(d["text"]) for d in s["train"]], np.array([d["label"] for d in s["train"]])
    x_te, y_te = [url_for_model(d["text"]) for d in s["test"]], np.array([d["label"] for d in s["test"]])
    chars = TfidfVectorizer(lowercase=True, analyzer="char", ngram_range=(3, 5), min_df=5, max_features=150000, sublinear_tf=True)
    parts = TfidfVectorizer(lowercase=False, preprocessor=url_parts, token_pattern=r"\S+", min_df=3, max_features=80000, sublinear_tf=True)
    model, prob = fit([(chars, ("char", (3, 5))), (parts, ("url_parts", None))], x_tr, y_tr, x_te, C=4.0)
    m = metrics(y_te, prob)
    m["dataset"] = (f"ealvaradob/phishing-dataset urls.json; trained on {len(x_tr)} URLs, tested on {len(x_te)} never-seen URLs; "
                    "scheme and www. stripped; character 3-5-grams + host/path word tokens")
    return {"kind": "url", **model}, m


def main():
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    EVAL_DIR.mkdir(parents=True, exist_ok=True)
    which = sys.argv[1:] or ["text", "url"]
    path = EVAL_DIR / "ml_metrics.json"
    report = json.loads(path.read_text()) if path.exists() else {}
    for name, fn in (("text", train_text), ("url", train_url)):
        if name not in which:
            continue
        t = time.time()
        model, m = fn()
        m["train_seconds"] = round(time.time() - t, 1)
        (MODEL_DIR / f"{name}_model.json").write_text(json.dumps(model, separators=(",", ":")))
        report[name] = m
        print(name, json.dumps(m, indent=1), flush=True)
    path.write_text(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
