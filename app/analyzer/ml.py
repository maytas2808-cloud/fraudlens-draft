"""Dependency-free inference for the exported TF-IDF + logistic-regression models.

Reproduces scikit-learn's TfidfVectorizer (lowercase, sublinear tf, l2 norm) so the
deployed app needs no numpy/scikit-learn. A model is one or more feature groups (one per
vectoriser, each normalised separately) sharing a single logistic-regression intercept.
"""
import json
import math
import re
from collections import Counter
from functools import lru_cache
from pathlib import Path

MODEL_DIR = Path(__file__).resolve().parents[1] / "model"
_TOKEN = re.compile(r"(?u)\b\w\w+\b")
_WS = re.compile(r"\s\s+")
_ALNUM = re.compile(r"[a-z0-9]+")
_ALNUM2 = re.compile(r"[a-z0-9]{2,}")


def url_for_model(url: str) -> str:
    u = url.strip().lower()
    u = re.sub(r"^[a-z][a-z0-9+.-]*://", "", u)
    if u.startswith("www."):
        u = u[4:]
    return u.rstrip("/")


def url_parts(u: str) -> str:
    """Tokens that keep host and path apart, plus a few shape tokens, for the URL model."""
    host, _, path = u.partition("/")
    host_tokens = _ALNUM.findall(host.split(":")[0])
    out = ["h" + t for t in host_tokens] + ["p" + t for t in _ALNUM2.findall(path)]
    if host_tokens:
        out.append("tld" + host_tokens[-1])
    out.append("nh%d" % min(len(host_tokens), 6))
    out.append("np%d" % min(path.count("/"), 6))
    out.append("nd" + ("1" if re.search(r"\d", host) else "0"))
    return " ".join(out)


@lru_cache(maxsize=2)
def _load(kind: str) -> dict | None:
    path = MODEL_DIR / f"{kind}_model.json"
    if not path.exists():
        return None
    return json.loads(path.read_text())


def _word_terms(text: str, ngram: list[int]) -> list[str]:
    tokens = _TOKEN.findall(text.lower())
    terms = []
    for n in range(ngram[0], ngram[1] + 1):
        if n == 1:
            terms.extend(tokens)
        else:
            terms.extend(" ".join(tokens[i:i + n]) for i in range(len(tokens) - n + 1))
    return terms


def _char_terms(text: str, ngram: list[int]) -> list[str]:
    t = _WS.sub(" ", text.lower())
    terms = []
    for n in range(ngram[0], ngram[1] + 1):
        terms.extend(t[i:i + n] for i in range(len(t) - n + 1))
    return terms


def _terms(group: dict, text: str) -> list[str]:
    kind = group["analyzer"]
    if kind == "word":
        return _word_terms(text, group["ngram_range"])
    if kind == "char":
        return _char_terms(text, group["ngram_range"])
    if kind == "url_parts":
        return url_parts(text).split()
    raise ValueError(kind)


def _score(model: dict, text: str) -> tuple[float, list[tuple[str, float]]]:
    z = model["intercept"]
    contrib: dict[str, float] = {}
    for group in model["groups"]:
        feats = group["features"]
        counts = Counter(t for t in _terms(group, text) if t in feats)
        if not counts:
            continue
        weights = {t: (1 + math.log(c)) * feats[t][0] for t, c in counts.items()}
        norm = math.sqrt(sum(w * w for w in weights.values())) or 1.0
        parts = group["analyzer"] == "url_parts"
        for t, w in weights.items():
            c = (w / norm) * feats[t][1]
            z += c
            if parts and t[0] not in "hp":
                continue
            label = t[1:] if parts else t
            contrib[label] = contrib.get(label, 0.0) + c
    prob = 1 / (1 + math.exp(-max(min(z, 50), -50)))
    top = sorted(((t, c) for t, c in contrib.items() if c > 0), key=lambda x: -x[1])[:6]
    return prob, top


def predict_text(text: str) -> dict | None:
    model = _load("text")
    if model is None or not text.strip():
        return None
    prob, top = _score(model, text)
    return {"probability": round(prob, 4), "top_terms": [t for t, _ in top]}


def predict_url(url: str) -> dict | None:
    model = _load("url")
    if model is None or not url.strip():
        return None
    prob, top = _score(model, url_for_model(url))
    return {"probability": round(prob, 4), "top_terms": [t.strip() for t, _ in top if t.strip()]}
