"""Threat intelligence (OpenPhish, URLhaus) and domain reputation (Tranco top sites)."""
import gzip
import json
from functools import lru_cache
from pathlib import Path

INTEL_DIR = Path(__file__).resolve().parents[1] / "model" / "intel"


def _read(name: str) -> list[str]:
    path = INTEL_DIR / name
    if not path.exists():
        return []
    with gzip.open(path, "rt", encoding="utf-8") as f:
        return [ln for ln in f.read().splitlines() if ln]


@lru_cache(maxsize=1)
def feeds() -> dict:
    ranked = _read("top_domains_ranked.txt.gz")
    meta_path = INTEL_DIR / "meta.json"
    return {
        "phish_urls": set(_read("openphish_urls.txt.gz")),
        "malware_urls": set(_read("urlhaus_urls.txt.gz")),
        "bad_hosts": set(_read("bad_hosts.txt.gz")),
        "rank": {d: i + 1 for i, d in enumerate(ranked)},
        "meta": json.loads(meta_path.read_text()) if meta_path.exists() else {},
    }


def _url_keys(url: str) -> set[str]:
    u = url.strip().lower().rstrip("/")
    keys = {u}
    if "://" not in u:
        keys |= {"http://" + u, "https://" + u}
    else:
        rest = u.split("://", 1)[1]
        keys |= {"http://" + rest, "https://" + rest}
    return keys


def lookup(url: str, host: str, allow_host_match: bool = True) -> dict | None:
    """Exact-URL matches always count. Host matches are skipped for big shared platforms
    (e.g. docs.google.com), where one bad document would otherwise flag every user."""
    f = feeds()
    keys = _url_keys(url)
    if keys & f["phish_urls"]:
        return {"source": "OpenPhish", "match": "exact URL", "type": "phishing"}
    if keys & f["malware_urls"]:
        return {"source": "URLhaus (abuse.ch)", "match": "exact URL", "type": "malware distribution"}
    if allow_host_match and host and host in f["bad_hosts"]:
        return {"source": "OpenPhish / URLhaus", "match": "host", "type": "phishing or malware host"}
    return None


def rank(domain: str) -> int | None:
    return feeds()["rank"].get(domain)


def meta() -> dict:
    return feeds()["meta"]
