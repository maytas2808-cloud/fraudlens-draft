"""Fixed data splits shared by train.py, tune.py and evaluate.py.

URLs (shuffled with seed 42):  [0, 300k) train | [300k, 360k) test | [360k, 380k) validation | [380k, end) train
Texts: 80/20 stratified train/test (seed 42); 10% of the train part is held back as validation (seed 7).
Validation is only used to tune score weights; test is only used for reporting.
"""
import json
import random
from functools import lru_cache
from pathlib import Path

from sklearn.model_selection import train_test_split

RAW = Path(__file__).resolve().parents[1] / "data" / "raw"
SEED = 42


@lru_cache(maxsize=1)
def _urls() -> list[dict]:
    data = json.loads((RAW / "urls.json").read_text())
    random.Random(SEED).shuffle(data)
    return data


def url_splits() -> dict[str, list[dict]]:
    d = _urls()
    return {"train": d[:300000] + d[380000:], "test": d[300000:360000], "val": d[360000:380000]}


@lru_cache(maxsize=1)
def text_splits() -> dict[str, list[tuple[str, int]]]:
    data = json.loads((RAW / "texts.json").read_text())
    texts = [d["text"] for d in data]
    labels = [int(d["label"]) for d in data]
    x_tr, x_te, y_tr, y_te = train_test_split(texts, labels, test_size=0.2, random_state=SEED, stratify=labels)
    x_fit, x_val, y_fit, y_val = train_test_split(x_tr, y_tr, test_size=0.1, random_state=7, stratify=y_tr)
    return {"train": list(zip(x_fit, y_fit)), "val": list(zip(x_val, y_val)), "test": list(zip(x_te, y_te))}
