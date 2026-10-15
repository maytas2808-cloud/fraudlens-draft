"""FraudLens API + web UI."""
import json
import logging
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .analyzer import intel, ml
from .analyzer.engine import MAX_CHARS, analyze

BASE = Path(__file__).resolve().parent
STATIC = BASE / "static"
REPORT = BASE / "model" / "eval_report.json"
RATE_LIMIT = 30
RATE_WINDOW = 60

log = logging.getLogger("fraudlens")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


@asynccontextmanager
async def lifespan(_: FastAPI):
    ml._load("text"), ml._load("url"), intel.feeds()
    yield


CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
# FastAPI's Swagger page loads its bundle from jsDelivr and boots it with an inline script.
DOCS_CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https://fastapi.tiangolo.com; "
            "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")

app = FastAPI(title="FraudLens", version="1.0.0", lifespan=lifespan, redoc_url=None,
              description="Explainable phishing and digital-fraud detection for messages, emails and URLs.")
app.mount("/static", StaticFiles(directory=STATIC), name="static")
_hits: dict[str, deque] = defaultdict(deque)


class AnalyzeRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=MAX_CHARS, description="Message text, raw email or a URL")
    live: bool = Field(False, description="Follow redirects and look up domain age (contacts the link's server)")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = DOCS_CSP if request.url.path == "/docs" else CSP
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    # The deploy proxy appends the real client address; earlier entries are client-supplied and spoofable.
    return fwd.split(",")[-1].strip() if fwd else (request.client.host if request.client else "unknown")


def _rate_limited(ip: str) -> bool:
    now = time.monotonic()
    q = _hits[ip]
    while q and now - q[0] > RATE_WINDOW:
        q.popleft()
    if len(q) >= RATE_LIMIT:
        return True
    q.append(now)
    return False


@app.post("/api/analyze")
def api_analyze(body: AnalyzeRequest, request: Request):
    if _rate_limited(_client_ip(request)):
        raise HTTPException(status_code=429, detail="Too many requests. Please wait a minute and try again.")
    if not body.content.strip():
        raise HTTPException(status_code=422, detail="Paste a message, email or link to analyse.")
    try:
        result = analyze(body.content, live=body.live)
    except Exception:
        log.exception("analysis failed (content length %d)", len(body.content))
        raise HTTPException(status_code=500, detail="Analysis failed. Please try again.")
    log.info("analyzed type=%s level=%s score=%d ms=%.1f", result["input_type"], result["level"], result["score"], result["elapsed_ms"])
    return result


@app.get("/api/health")
def health():
    m = intel.meta()
    return {"status": "ok", "models": {"text": ml._load("text") is not None, "url": ml._load("url") is not None},
            "intel_fetched_at": m.get("fetched_at"), "intel_counts": m.get("counts")}


@app.get("/api/report")
def report():
    if not REPORT.exists():
        raise HTTPException(status_code=404, detail="Evaluation report not generated yet.")
    return JSONResponse(json.loads(REPORT.read_text()))


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return FileResponse(STATIC / "favicon.svg", media_type="image/svg+xml")


@app.get("/report", include_in_schema=False)
def report_page():
    return FileResponse(STATIC / "report.html")
