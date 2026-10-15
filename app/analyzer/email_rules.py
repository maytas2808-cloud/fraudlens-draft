"""Header checks for pasted raw emails (From / Reply-To / Return-Path / authentication results)."""
import re
from email import message_from_string, policy
from email.utils import parseaddr

from .text_rules import Hit
from .url_rules import BRANDS, _EXTRACT

FREE_MAIL = {"gmail.com", "yahoo.com", "yahoo.co.in", "outlook.com", "hotmail.com", "live.com", "rediffmail.com",
             "aol.com", "proton.me", "protonmail.com", "icloud.com", "mail.com", "gmx.com", "yandex.com", "zoho.com"}
_HEADER_START = re.compile(r"^(?:from|to|subject|date|received|return-path|reply-to|message-id|delivered-to|mime-version)\s*:", re.I | re.M)


def looks_like_raw_email(text: str) -> bool:
    head = text.lstrip()[:2000]
    return len(_HEADER_START.findall(head)) >= 2 and bool(re.search(r"^from\s*:", head, re.I | re.M))


def _domain(addr: str) -> str:
    addr = addr.strip().lower()
    if "@" not in addr:
        return ""
    host = addr.rsplit("@", 1)[1].strip(">").strip()
    ext = _EXTRACT(host)
    reg = ext.top_domain_under_public_suffix if hasattr(ext, "top_domain_under_public_suffix") else ext.registered_domain
    return reg or host


def _body_text(msg) -> str:
    if msg.is_multipart():
        parts = []
        for part in msg.walk():
            if part.get_content_type() in ("text/plain", "text/html") and not part.is_attachment():
                try:
                    parts.append(part.get_content())
                except (LookupError, ValueError):
                    parts.append(part.get_payload(decode=True).decode("utf-8", "ignore") if part.get_payload(decode=True) else "")
        return "\n".join(parts)
    try:
        return msg.get_content()
    except (LookupError, ValueError, KeyError):
        return msg.get_payload() or ""


def analyze_email(raw: str) -> tuple[dict, list[Hit], str]:
    """Return (header summary, header hits, body text) for a raw RFC 822 email."""
    msg = message_from_string(raw, policy=policy.default)
    from_name, from_addr = parseaddr(str(msg.get("From", "")))
    _, reply_addr = parseaddr(str(msg.get("Reply-To", "")))
    _, return_addr = parseaddr(str(msg.get("Return-Path", "")))
    subject = str(msg.get("Subject", ""))
    auth = " ".join(str(v) for v in msg.get_all("Authentication-Results", []) or [])
    from_dom = _domain(from_addr)
    hits: list[Hit] = []

    def add(id_, label, weight, explanation, evidence):
        hits.append(Hit(id_, label, weight, explanation, [evidence], "email"))

    name_l = (from_name + " " + subject).lower()
    claimed = [b for b in BRANDS if re.search(r"\b" + re.escape(b) + r"\b", name_l)]
    for brand in claimed:
        if from_dom and from_dom not in BRANDS[brand]:
            add("sender_brand_mismatch", f"Sender claims to be '{brand}' but writes from {from_dom}", 30,
                f"The display name or subject mentions '{brand}', whose real domain is {BRANDS[brand][0]}.", f"{from_name} <{from_addr}>")
            break
    if from_dom in FREE_MAIL and (claimed or re.search(r"\b(?:bank|support|security|team|department|official|helpdesk|service)\b", name_l)):
        add("free_mail_official", "Organisation writing from a free email account", 20,
            "Banks, companies and government offices don't send official mail from Gmail/Yahoo addresses.", from_addr)
    if reply_addr and _domain(reply_addr) and from_dom and _domain(reply_addr) != from_dom:
        add("reply_to_mismatch", "Replies go to a different domain", 15,
            f"Replies would go to {reply_addr} instead of the sender's domain {from_dom}.", f"Reply-To: {reply_addr}")
    if return_addr and _domain(return_addr) and from_dom and _domain(return_addr) != from_dom:
        add("return_path_mismatch", "Return-Path differs from sender", 5,
            "The technical sender differs from the visible one. Common with mailing services, but also with spoofing.", f"Return-Path: {return_addr}")
    for check in ("spf", "dkim", "dmarc"):
        m = re.search(check + r"\s*=\s*(\w+)", auth, re.I)
        if m and m.group(1).lower() in ("fail", "softfail", "none", "permerror"):
            add(f"{check}_fail", f"{check.upper()} check: {m.group(1).lower()}", 15 if check != "dkim" else 10,
                f"The receiving server's {check.upper()} check did not pass, so the sender address may be forged.", m.group(0))
    summary = {"from": f"{from_name} <{from_addr}>".strip(), "reply_to": reply_addr or None, "subject": subject,
               "from_domain": from_dom or None}
    return summary, hits, f"{subject}\n{_body_text(msg)}"
