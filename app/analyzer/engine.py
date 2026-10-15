"""Combine rules, URL analysis, email headers, ML and threat intel into one explained verdict."""
import re
import time

from . import guidance, live_check, ml
from .email_rules import analyze_email, looks_like_raw_email
from .normalize import deobfuscate, extract_emails, extract_phones, extract_urls, normalize_text, refang
from .text_rules import Hit, run_text_rules
from .url_rules import analyze_url, parse

MAX_CHARS = 20000
MAX_URLS = 10
# Indicators that ask the reader to do something. A message with none of these and no link
# (e.g. a debit alert or statement notice) has no way to take money or credentials by itself.
ACTION_IDS = {
    "credential_request", "payment_request", "kyc", "link_cta", "remote_access", "unusual_payment", "prize", "job",
    "investment", "threat", "contact_switch", "family_impersonation", "delivery", "loan", "secrecy",
}
LEVELS = ((60, "high"), (30, "medium"), (0, "low"))


def _level(score: int) -> str:
    return next(name for cut, name in LEVELS if score >= cut)


# ML probability -> points: slope * (p - pivot) above the pivot, a small deduction below `low`.
# Tuned by scripts/tune.py on validation data only (never on the test sets).
TEXT_ML = {"pivot": 0.4, "slope": 80, "low": 0.3, "low_slope": 20}
URL_ML = {"pivot": 0.6, "slope": 130, "low": 0.5, "low_slope": 10, "benign_context_factor": 0.0}


def _ml_points(prob: float, cfg: dict) -> int:
    if prob >= cfg["pivot"]:
        return round((prob - cfg["pivot"]) * cfg["slope"])
    if prob < cfg["low"]:
        return -round((cfg["low"] - prob) * cfg["low_slope"])
    return 0


def _ml_text_points(prob: float) -> int:
    return _ml_points(prob, TEXT_ML)


def _ml_url_points(prob: float) -> int:
    return _ml_points(prob, URL_ML)


def _why_points(weight: int, explanation: str) -> str:
    if weight >= 25:
        band = f"{weight} points, in the top band (25 or more): a direct route to money, a password, or a copy of a real brand."
    elif weight >= 15:
        band = f"{weight} points, in the strong band (15–24): a common scam demand or a failed email check."
    elif weight >= 8:
        band = f"{weight} points, in the supporting band (8–14): pressure or a risky link detail, not proof on its own."
    elif weight > 0:
        band = f"{weight} points, in the context band (under 8): a brand name, a greeting, or a weak hint."
    elif weight < 0:
        band = f"{weight} points are taken off because this is a reassuring sign."
    else:
        band = "0 points."
    return f"{band} {explanation} On the 100-point scale, {weight} points is {weight}%."


def _why_text_ml(prob: float, points: int) -> str:
    shown = round(prob * 100)
    if prob >= TEXT_ML["pivot"]:
        return (f"The language model called this {shown}% phishing-like. "
                f"Points = round(({prob:.2f} − 0.40) × 80) = {points}. "
                f"Marks start only above 40%, and each extra hundredth of probability is worth 0.8 points. "
                f"{points} points is {points}% of the scale.")
    if prob < TEXT_ML["low"]:
        return (f"The language model called this {shown}% phishing-like, under 30%. "
                f"Points taken off = round((0.30 − {prob:.2f}) × 20) = {abs(points)}. "
                f"That is {points}% of the scale.")
    return f"The language model called this {shown}% phishing-like, between 30% and 40%, so it adds 0 points."


def _why_url_ml(prob: float, points: int, *, reputation: bool, benign: bool) -> str:
    uncut = _ml_url_points(prob)
    shown = round(prob * 100)
    formula = f"Points before any reduction = round(({prob:.2f} − 0.60) × 130) = {uncut}."
    if benign and uncut > 0 and points == 0:
        cut = " The rest of the message reads as harmless and asks for nothing, so these URL-model points are not counted."
    elif reputation and uncut > 0 and points == uncut // 3:
        cut = " The host is already a well-known site, so the model points are cut to a third."
    elif prob < URL_ML["pivot"] and prob >= URL_ML["low"]:
        formula = f"The model called this link {shown}% phishing-like, between 50% and 60%, so it adds 0 points."
        cut = ""
    elif prob < URL_ML["low"]:
        formula = f"The model called this link {shown}% phishing-like, under 50%, so {abs(points)} points are taken off."
        cut = ""
    else:
        cut = ""
    return (f"The URL model called this link {shown}% phishing-like. {formula}{cut} "
            f"{points} points is {points}% of the scale.")


def _grade_letter(score: int) -> tuple[str, str]:
    if score >= 60:
        return "C", "Likely scam"
    if score >= 30:
        return "B", "Be careful"
    return "A", "Low risk"


def _apply_shares(lines: list[dict], raw: int, target: int) -> None:
    if not lines or raw == 0:
        for line in lines:
            line["percent"] = float(line["points"])
            line["out_of_100"] = 0.0
        return
    for line in lines:
        line["percent"] = float(line["points"])
        line["out_of_100"] = round(line["points"] / raw * target, 1)
    drift = round(target - sum(line["out_of_100"] for line in lines), 1)
    if drift:
        lines[-1]["out_of_100"] = round(lines[-1]["out_of_100"] + drift, 1)


def _grade(lines: list[dict], raw: int, score: int, *, intel: bool, notes: list[str] | None = None) -> dict:
    measured = [dict(line) for line in lines if line["points"]]
    target = min(max(raw, 0), 100)
    _apply_shares(measured, raw, target)
    if score > target:
        lift = score - target
        measured.append({
            "label": "Threat-feed minimum",
            "group": "Threat intelligence",
            "points": lift,
            "percent": float(lift),
            "out_of_100": float(lift),
            "why": "A match on a public threat feed sets the grade to at least 90 out of 100, even when the other marks add up to less.",
        })
    elif score < target:
        drop = score - target
        measured.append({
            "label": "Scale stops at 0",
            "group": "Scale",
            "points": drop,
            "percent": float(drop),
            "out_of_100": float(drop),
            "why": "Reassuring marks would take the total below 0. The grade cannot go below 0, so those extra marks are not counted.",
        })
    letter, name = _grade_letter(score)
    if raw == score:
        summary = (f"{raw} points were assigned. Each point is 1% of the scale, so {raw} ÷ 100 = {score}%. "
                   f"The grade is {score} out of 100.")
    elif raw > 100:
        summary = (f"{raw} points were assigned, which is {raw}% and past the top of the scale. "
                   f"Each point is then worth {round(100 / raw, 2)} of a mark, and the grade stops at 100 out of 100.")
    elif intel and score > max(raw, 0):
        summary = (f"{max(raw, 0)} points were assigned ({max(raw, 0)}%). A threat-feed match raises the grade to at least 90, "
                   f"so this is {score} out of 100.")
    elif raw < 0:
        summary = (f"Reassuring signs removed {abs(raw)} points ({raw}%). The grade cannot go below 0, so this is 0 out of 100.")
    else:
        summary = f"{raw} points convert to {score}% and the grade is {score} out of 100."
    return {
        "letter": letter,
        "name": name,
        "score": score,
        "raw_points": raw,
        "percent": score,
        "summary": summary,
        "how": "One point is one percent. The points on this message are added, converted to a percentage, and shown out of 100. The total cannot go below 0 or above 100. Wording alone cannot pass 70.",
        "scale": [
            {"letter": "A", "range": "0–29", "name": "Low risk"},
            {"letter": "B", "range": "30–59", "name": "Be careful"},
            {"letter": "C", "range": "60–100", "name": "Likely scam"},
        ],
        "rubric": [
            {"marks": "25+", "text": "Direct route to money, a password, or a copy of a real brand."},
            {"marks": "15–24", "text": "A common scam demand, or an email check that failed."},
            {"marks": "8–14", "text": "Pressure, a push to click, or a risky detail in a link."},
            {"marks": "1–7", "text": "Context only: a brand name or a generic greeting."},
            {"marks": "Below 0", "text": "A reassuring sign. These points are subtracted."},
        ],
        "notes": notes or [],
        "lines": measured,
    }


def analyze(content: str, *, live: bool = False, use_ml: bool = True) -> dict:
    started = time.perf_counter()
    text = normalize_text(content)[:MAX_CHARS]
    email_summary, email_hits = None, []
    body = text
    if looks_like_raw_email(text):
        email_summary, email_hits, body = analyze_email(text)
    link_text = refang(body)
    clean = deobfuscate(body)
    urls = extract_urls(link_text)[:MAX_URLS]
    is_url_only = len(urls) == 1 and link_text.strip().rstrip("/") in (urls[0].rstrip("/"), "http://" + urls[0].rstrip("/"), "https://" + urls[0].rstrip("/"))

    text_hits = [] if is_url_only else run_text_rules(clean)
    ids = {h.id for h in text_hits}
    if not is_url_only and not urls and not (ids & ACTION_IDS) and not email_summary:
        text_hits.append(Hit("no_action", "No link and no request for action", -10,
                             "The message only informs you; it doesn't ask you to click, call, pay or share anything.", [], "reassurance"))
    if re.search(r"\bdigital arrest\b", clean, re.I):
        ids.add("digital_arrest")

    ml_text = ml.predict_text(clean) if (use_ml and not is_url_only and len(clean.split()) >= 3) else None
    # A link inside a message that reads as harmless and asks for nothing gets less weight from the URL model.
    benign_context = (ml_text is not None and ml_text["probability"] < 0.5 and not (ids & ACTION_IDS)
                      and sum(h.weight for h in email_hits) <= 0)

    url_reports, best_url_points, intel_types = [], 0, set()
    for u in urls:
        parsed, hits, intel_hit = analyze_url(u)
        ml_url = ml.predict_url(u) if use_ml else None
        pts = sum(h.weight for h in hits)
        ml_pts = 0
        if ml_url:
            ml_pts = _ml_url_points(ml_url["probability"])
            if any(h.id == "reputation" for h in hits) and ml_pts > 0:
                ml_pts //= 3
            if benign_context and ml_pts > 0:
                ml_pts = round(ml_pts * URL_ML["benign_context_factor"])
            ml_url["points"] = ml_pts
            pts += ml_pts
        live_info = None
        if live and parsed is not None and not parsed.is_ip:
            live_info = _live(u, parsed, hits)
            pts = sum(h.weight for h in hits) + ml_pts
        if intel_hit:
            intel_types.add(intel_hit["type"])
        ids |= {h.id for h in hits}
        url_score = max(0, min(100, pts))
        best_url_points = max(best_url_points, pts)
        url_reports.append({
            "url": u,
            "host": parsed.host if parsed else None,
            "registered_domain": parsed.registered_domain if parsed else None,
            "display_host": parsed.unicode_host if parsed else None,
            "score": url_score,
            "raw_points": pts,
            "level": _level(url_score) if not intel_hit else "high",
            "indicators": [h.as_dict() for h in sorted(hits, key=lambda h: -h.weight)],
            "ml": ml_url,
            "intel": intel_hit,
            "live": live_info,
        })
    ids |= {h.id for h in email_hits}

    text_sum = sum(h.weight for h in text_hits)
    lang_points = min(70, text_sum)
    email_points = sum(h.weight for h in email_hits)
    ml_points = _ml_text_points(ml_text["probability"]) if ml_text else 0
    combo = 0
    combos = []
    if "credential_request" in ids and urls:
        combo += 10
        combos.append(("Link plus a request for a secret", 10,
                       "10 points, because the message both asks for a secret and includes a link where that secret would be typed. 10 points is 10% of the scale."))
    if ids & {"threat", "urgency"} and ids & {"payment_request", "credential_request", "kyc"}:
        combo += 5
        combos.append(("Pressure plus a demand", 5,
                       "5 points, because a threat or a deadline is paired with a demand to pay, to update KYC, or to hand over a secret. 5 points is 5% of the scale."))
    if "threat" in ids and "contact_switch" in ids:
        combo += 10
        combos.append(("Threat plus a move off this chat", 10,
                       "10 points, because a threat is paired with a push onto a phone call or another chat app. 10 points is 10% of the scale."))
    if "payment_request" in ids and ids & {"job", "prize", "loan", "investment"}:
        combo += 10
        combos.append(("A payout that first asks you to pay", 10,
                       "10 points, because a job, prize, loan or investment offer also asks for a fee. 10 points is 10% of the scale."))
    link_points = best_url_points if urls else 0
    raw = lang_points + email_points + ml_points + combo + link_points
    score = max(0, min(100, raw))
    if intel_types:
        score = max(score, 90)
    level = _level(score)

    scenarios = guidance.detect_scenarios(ids, intel_types) if level != "low" else []
    reasons = sorted(text_hits + email_hits, key=lambda h: -h.weight)
    indicators = [h.as_dict() for h in reasons]
    if ml_text:
        indicators.append({
            "id": "ml_text", "label": f"Machine-learning model: {round(ml_text['probability'] * 100)}% phishing-like language",
            "weight": ml_points, "category": "ml",
            "explanation": "A model trained on ~14,500 labelled phishing and legitimate messages. Words that pushed the score up: "
                           + (", ".join(f"'{t}'" for t in ml_text["top_terms"][:5]) or "none") + ".",
            "evidence": [],
        })

    grade_lines = []
    for hit in sorted(text_hits, key=lambda h: -h.weight):
        if hit.weight:
            grade_lines.append({"label": hit.label, "group": "Wording", "points": hit.weight, "why": _why_points(hit.weight, hit.explanation)})
    if text_sum > 70:
        grade_lines.append({"label": "Wording cap", "group": "Wording", "points": 70 - text_sum,
                            "why": f"Wording is capped at 70 so a pile of mild phrases cannot fill the scale alone. {text_sum - 70} points above that cap were not counted. That removal is {70 - text_sum}% of the scale."})
    for hit in sorted(email_hits, key=lambda h: -h.weight):
        if hit.weight:
            grade_lines.append({"label": hit.label, "group": "Email headers", "points": hit.weight, "why": _why_points(hit.weight, hit.explanation)})
    if ml_text and ml_points:
        grade_lines.append({"label": "Language model", "group": "Language model", "points": ml_points, "why": _why_text_ml(ml_text["probability"], ml_points)})
    for label, pts, why in combos:
        grade_lines.append({"label": label, "group": "Combined signals", "points": pts, "why": why})
    if url_reports and link_points:
        winner = max(url_reports, key=lambda u: u["raw_points"])
        for ind in winner["indicators"]:
            if ind["weight"]:
                grade_lines.append({"label": ind["label"], "group": "Links", "points": ind["weight"], "why": _why_points(ind["weight"], ind["explanation"])})
        ml_url = winner.get("ml") or {}
        url_ml_points = ml_url.get("points") or 0
        if url_ml_points:
            reputation = any(i["id"] == "reputation" for i in winner["indicators"])
            grade_lines.append({"label": "URL model", "group": "Links", "points": url_ml_points,
                                "why": _why_url_ml(ml_url["probability"], url_ml_points, reputation=reputation, benign=benign_context)})
    notes = []
    if len(url_reports) > 1:
        notes.append("Only the riskiest link is added to the grade. The other links are shown, and their points are not added again.")

    return {
        "score": score,
        "level": level,
        "grade": _grade(grade_lines, raw, score, intel=bool(intel_types), notes=notes),
        "scenarios": [{"id": s, "name": guidance.SCENARIOS[s][0]} for s in scenarios],
        "summary": _summary(level, scenarios, indicators, url_reports),
        "breakdown": {"wording": lang_points, "email_headers": email_points, "language_model": ml_points,
                      "combinations": combo, "links": link_points, "threat_intel": bool(intel_types),
                      "benign_context": benign_context},
        "indicators": indicators,
        "urls": url_reports,
        "email": email_summary,
        "extracted": {"urls": urls, "emails": extract_emails(clean)[:10], "phones": extract_phones(clean)[:10]},
        "advice": guidance.advice(level, scenarios),
        "ml": {"text": ml_text},
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
        "input_type": "email" if email_summary else ("url" if is_url_only else "message"),
    }


def _live(url: str, parsed, hits: list[Hit]) -> dict:
    info = live_check.follow_redirects(url)
    age = live_check.domain_age_days(parsed.registered_domain)
    info["domain_age_days"] = age
    final = info.get("final_url")
    if final:
        fp = parse(final)
        if fp and fp.registered_domain != parsed.registered_domain:
            hits.append(Hit("redirects_elsewhere", "Redirects to a different domain", 12,
                            f"The link redirects to {fp.registered_domain}, so the address shown isn't where you end up.", [final[:100]], "url"))
    if info.get("https_ok") is False:
        hits.append(Hit("bad_certificate", "HTTPS certificate problem", 15,
                        "The site's security certificate is invalid; your browser would show a warning.", [info.get("error") or ""], "url"))
    if age is not None and age < 30:
        hits.append(Hit("new_domain", f"Domain registered {age} days ago", 25,
                        "Scam sites are usually brand new; most are taken down within weeks.", [parsed.registered_domain], "url"))
    elif age is not None and age > 365 * 3:
        hits.append(Hit("old_domain", f"Domain is {age // 365} years old", -5,
                        "Long-established domains are less likely to be throwaway scam sites.", [parsed.registered_domain], "url"))
    return info


def _summary(level: str, scenarios: list[str], indicators: list[dict], urls: list[dict]) -> str:
    if level == "low":
        return "No strong signs of phishing or fraud were found."
    kind = guidance.SCENARIOS[scenarios[0]][0] if scenarios else "Suspicious content"
    top = [i["label"].lower() for i in indicators if i["weight"] > 0][:2]
    top += [i["label"].lower() for u in urls for i in u["indicators"] if i["weight"] > 0][:2]
    reasons = "; ".join(dict.fromkeys(top))
    prefix = "Likely" if level == "high" else "Possible"
    return f"{prefix} {kind.lower()}" + (f": {reasons}." if reasons else ".")
