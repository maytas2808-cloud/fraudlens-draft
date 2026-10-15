"""End-to-end smoke test over HTTP.

    python scripts/smoke_test.py                      # starts a local server on :8765
    python scripts/smoke_test.py https://your.app     # checks a deployed instance
"""
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def get(base, path, data=None):
    req = urllib.request.Request(base + path, data=json.dumps(data).encode() if data else None,
                                 headers={"content-type": "application/json"})
    try:
        with opener.open(req, timeout=20) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read()


def check(base):
    failures = 0

    def expect(name, ok, detail=""):
        nonlocal failures
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {name}  {detail}")

    for path in ("/", "/report", "/static/app.js", "/static/styles.css", "/static/report.js", "/api/report"):
        status, _, body = get(base, path)
        expect(f"GET {path}", status == 200, f"{status} {len(body)}B")
    status, headers, body = get(base, "/api/health")
    health = json.loads(body)
    expect("health", status == 200 and all(health["models"].values()), json.dumps(health["intel_counts"]))
    expect("security headers", "default-src 'self'" in headers.get("content-security-policy", ""))
    status, headers, _ = get(base, "/docs")
    expect("API docs can load Swagger", status == 200 and "cdn.jsdelivr.net" in headers.get("content-security-policy", ""), str(status))
    status, _, _ = get(base, "/favicon.ico")
    expect("GET /favicon.ico", status == 200, str(status))
    _, _, css = get(base, "/static/styles.css")
    expect("hidden elements stay hidden", b"[hidden]" in css)

    cases = [
        ("Dear customer your HDFC account is suspended. Verify KYC now at http://hdfc-kyc-verify.top/login", "high"),
        ("482910 is your OTP for HDFC Bank NetBanking. Do not share this OTP with anyone.", "low"),
        ("https://paypa1-secure-login.com/signin", "high"),
        ("https://www.irctc.co.in/nget/train-search", "low"),
    ]
    for text, want in cases:
        start = time.perf_counter()
        status, _, body = get(base, "/api/analyze", {"content": text})
        r = json.loads(body)
        expect(f"analyze -> {want}", status == 200 and r["level"] == want,
               f"got {r.get('level')} score={r.get('score')} {1000 * (time.perf_counter() - start):.0f}ms round trip")
    status, _, _ = get(base, "/api/analyze", {"content": ""})
    expect("empty input rejected", status == 422, str(status))
    return failures


def main():
    if len(sys.argv) > 1:
        sys.exit(1 if check(sys.argv[1].rstrip("/")) else 0)
    server = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--port", "8765"], cwd=ROOT,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(60):
            try:
                opener.open("http://127.0.0.1:8765/api/health", timeout=1)
                break
            except OSError:
                time.sleep(0.5)
        failures = check("http://127.0.0.1:8765")
    finally:
        server.terminate()
        server.wait(timeout=10)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
