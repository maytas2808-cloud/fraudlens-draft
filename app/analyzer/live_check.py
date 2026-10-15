"""Optional network checks: follow redirects and look up domain age (RDAP).

Only public internet addresses are contacted (private, loopback and link-local
addresses are refused) and response bodies are never downloaded or stored.
"""
import http.client
import ipaddress
import json
import socket
import ssl
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

TIMEOUT = 4
MAX_HOPS = 5
UA = "Mozilla/5.0 (compatible; FraudLens-safety-check/1.0)"


class BlockedAddress(Exception):
    pass


def _check_public(host: str, port: int) -> None:
    for info in socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP):
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global or ip.is_multicast:
            raise BlockedAddress(f"{host} resolves to a non-public address")


def _one_request(url: str) -> tuple[int, str | None]:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("unsupported URL")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    _check_public(parts.hostname, port)
    conn_cls = http.client.HTTPSConnection if parts.scheme == "https" else http.client.HTTPConnection
    kwargs = {"timeout": TIMEOUT}
    if parts.scheme == "https":
        kwargs["context"] = ssl.create_default_context()
    conn = conn_cls(parts.hostname, port, **kwargs)
    try:
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        conn.request("GET", path, headers={"User-Agent": UA, "Accept": "text/html"})
        resp = conn.getresponse()
        return resp.status, resp.getheader("Location")
    finally:
        conn.close()


def follow_redirects(url: str) -> dict:
    chain, current = [], url if "://" in url else "https://" + url
    result = {"chain": chain, "final_url": None, "https_ok": None, "error": None}
    for _ in range(MAX_HOPS + 1):
        try:
            status, location = _one_request(current)
        except ssl.SSLError as e:
            result["https_ok"] = False
            result["error"] = f"TLS certificate problem: {e.reason or e}"
            return result
        except BlockedAddress as e:
            result["error"] = str(e)
            return result
        except (OSError, ValueError, http.client.HTTPException) as e:
            result["error"] = f"Could not reach the site ({type(e).__name__})"
            return result
        chain.append({"url": current, "status": status})
        if current.startswith("https://"):
            result["https_ok"] = True
        if status in (301, 302, 303, 307, 308) and location:
            current = urljoin(current, location)
            continue
        break
    result["final_url"] = chain[-1]["url"] if chain else None
    return result


def domain_age_days(registered_domain: str) -> int | None:
    req = urllib.request.Request(f"https://rdap.org/domain/{registered_domain}", headers={"User-Agent": UA, "Accept": "application/rdap+json"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            data = json.loads(r.read(500_000))
    except (OSError, ValueError):
        return None
    for ev in data.get("events", []):
        if ev.get("eventAction") == "registration" and ev.get("eventDate"):
            try:
                created = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
            except ValueError:
                return None
            return (datetime.now(timezone.utc) - created).days
    return None
