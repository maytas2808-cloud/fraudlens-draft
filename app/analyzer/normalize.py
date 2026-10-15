"""Text normalisation and extraction of URLs, emails and phone numbers."""
import re
import unicodedata

import tldextract

_SUFFIXES = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

URL_RE = re.compile(
    r"""(?ix)
    \b(
      (?:https?://|hxxps?://|www\.)[^\s<>"'`]+
      |
      (?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24})(?:/[^\s<>"'`]*)?
    )"""
)
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
PHONE_RE = re.compile(r"(?<!\d)(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)")

# Domains the URL regex can confuse with file names or abbreviations.
_NOT_URL_SUFFIXES = (".jpg", ".png", ".pdf", ".doc", ".docx", ".xls", ".txt", ".exe", ".apk", ".py", ".js", ".md", ".sh", ".csv", ".json")
_COMMON_TLDS = {
    "com", "net", "org", "in", "co", "io", "info", "biz", "xyz", "top", "online", "site", "live", "app",
    "me", "us", "uk", "ru", "cn", "tk", "ml", "ga", "cf", "gq", "club", "shop", "store", "link", "click",
    "gov", "edu", "ly", "gl", "cc", "ws", "su", "pw", "icu", "vip", "work", "support", "help", "services",
    "website", "space", "fun", "buzz", "rest", "cyou", "sbs", "bond", "today", "page", "dev", "cloud",
    "ai", "id", "my", "ph", "pk", "bd", "lk", "np", "ae", "sa", "de", "fr", "es", "it", "nl", "br", "au",
}


def normalize_text(text: str) -> str:
    """NFKC-normalise and strip zero-width characters used to dodge filters."""
    text = unicodedata.normalize("NFKC", text or "")
    text = re.sub(r"[\u200b-\u200f\u2060\ufeff]", "", text)
    return text


def refang(text: str) -> str:
    """Undo link defanging: hxxp -> http, [.] / (dot) -> '.'."""
    t = re.sub(r"hxxp", "http", text, flags=re.I)
    return re.sub(r"\s*[\[\(]\s*(?:\.|dot)\s*[\]\)]\s*", ".", t, flags=re.I)


def deobfuscate(text: str) -> str:
    """Undo filter-evasion tricks in wording: K.Y.C, v-e-r-i-f-y, bl0cked, 0TP. Not for URLs."""
    t = refang(text)
    # Collapse single letters separated by . - _ or spaces: "K.Y.C" / "v-e-r-i-f-y" -> "KYC" / "verify"
    t = re.sub(r"\b(?:[A-Za-z][.\-_ ]){2,}[A-Za-z]\b", lambda m: re.sub(r"[.\-_ ]", "", m.group(0)), t)
    # Digits standing in for letters inside words: "bl0cked", "0TP", "upd8" stays (no letter after).
    t = re.sub(r"(?<=[A-Za-z])0(?=[A-Za-z])|\b0(?=[A-Za-z]{2})", "o", t)
    t = re.sub(r"(?<=[A-Za-z])1(?=[A-Za-z])", "l", t)
    return t


SCHEME_URL_RE = re.compile(r"(?i)\b(?:https?|hxxps?)://[^\s<>\"'`]+")


_WORD_TLDS = {"it", "me", "us", "my"}


def _is_bare_domain(candidate: str, whole_input: bool) -> bool:
    host = candidate.split("/")[0]
    ext = _SUFFIXES(host)
    if not ext.suffix or not ext.domain:
        return False
    if whole_input:
        return True
    # Inside running text, missing spaces ("enough.As", "message.it") look like ccTLD links.
    if ext.suffix in _WORD_TLDS:
        return "/" in candidate or bool(re.search(r"[-\d]", ext.domain)) or bool(ext.subdomain)
    return ext.suffix in _COMMON_TLDS or "." in ext.suffix


def extract_urls(text: str) -> list[str]:
    # Links with a scheme first, so 'http://google.com@evil.ru' isn't mistaken for an email address.
    urls = [m.group(0).rstrip(".,;:!?)]}>'\"") for m in SCHEME_URL_RE.finditer(text)]
    rest = SCHEME_URL_RE.sub(" ", text)
    without_emails = EMAIL_RE.sub(" ", rest)
    whole = text.strip()
    for m in URL_RE.finditer(without_emails):
        u = m.group(1).rstrip(".,;:!?)]}>'\"")
        low = u.lower()
        if low.endswith(_NOT_URL_SUFFIXES) and "/" not in low:
            continue
        if "://" not in low and not low.startswith("www.") and not _is_bare_domain(low, u == whole):
            continue
        if u not in urls:
            urls.append(u)
    return urls


def extract_emails(text: str) -> list[str]:
    return list(dict.fromkeys(EMAIL_RE.findall(text)))


def extract_phones(text: str) -> list[str]:
    return list(dict.fromkeys(m.group(0) for m in PHONE_RE.finditer(text)))


def redact(text: str) -> str:
    """Mask personal data before anything is logged."""
    t = EMAIL_RE.sub("[email]", text)
    t = PHONE_RE.sub("[phone]", t)
    t = re.sub(r"\b\d{4}\s?\d{4}\s?\d{4}\b", "[aadhaar?]", t)
    t = re.sub(r"\b\d{12,19}\b", "[number]", t)
    return t
