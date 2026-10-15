"""Download public threat feeds and the Tranco top-sites list into app/model/intel/.

Usage: .venv/bin/python scripts/fetch_intel.py [--offline]
  --offline  rebuild from files already in data/raw and data/intel (no network)
"""
import csv
import gzip
import io
import json
import sys
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
FEEDS_DIR = ROOT / "data" / "intel"
OUT = ROOT / "app" / "model" / "intel"

SOURCES = {
    "openphish": "https://openphish.com/feed.txt",
    "urlhaus": "https://urlhaus.abuse.ch/downloads/text_online/",
    "phishing_database": "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
    "tranco": "https://tranco-list.eu/top-1m.csv.zip",
}
TOP_N = 100_000


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "FraudLens-intel-fetch/1.0"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read()


def lines(raw: bytes) -> list[str]:
    return [ln.strip() for ln in raw.decode("utf-8", "ignore").splitlines() if ln.strip() and not ln.startswith("#")]


def host_of(url: str) -> str:
    u = url if "://" in url else "http://" + url
    try:
        return (urlsplit(u).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def write_gz(name: str, items) -> int:
    items = sorted(set(i for i in items if i))
    with gzip.open(OUT / name, "wt", encoding="utf-8") as f:
        f.write("\n".join(items))
    return len(items)


def main():
    offline = "--offline" in sys.argv
    OUT.mkdir(parents=True, exist_ok=True)
    FEEDS_DIR.mkdir(parents=True, exist_ok=True)
    data = {}
    for key, url in SOURCES.items():
        cache = (RAW / "tranco.zip") if key == "tranco" else FEEDS_DIR / f"{key}.txt"
        if not offline:
            cache.write_bytes(fetch(url))
        data[key] = cache.read_bytes() if cache.exists() else b""

    with zipfile.ZipFile(io.BytesIO(data["tranco"])) as z:
        name = z.namelist()[0]
        reader = csv.reader(io.TextIOWrapper(z.open(name), encoding="utf-8"))
        top = [row[1].lower() for _, row in zip(range(TOP_N), reader)]

    phish_urls = [u for u in lines(data["openphish"])]
    malware_urls = lines(data["urlhaus"])
    phish_domains = [d.lower() for d in lines(data["phishing_database"])]

    meta = {
        "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sources": {k: v for k, v in SOURCES.items()},
        "counts": {
            "openphish_urls": write_gz("openphish_urls.txt.gz", (u.lower().rstrip("/") for u in phish_urls)),
            "urlhaus_urls": write_gz("urlhaus_urls.txt.gz", (u.lower().rstrip("/") for u in malware_urls)),
            "bad_hosts": write_gz("bad_hosts.txt.gz", [host_of(u) for u in phish_urls + malware_urls] + phish_domains),
            "top_domains": len(top),
        },
    }
    with gzip.open(OUT / "top_domains_ranked.txt.gz", "wt", encoding="utf-8") as f:
        f.write("\n".join(top))
    (OUT / "meta.json").write_text(json.dumps(meta, indent=2))
    print(json.dumps(meta, indent=2))


if __name__ == "__main__":
    main()
