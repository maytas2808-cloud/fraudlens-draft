"""Rule-based indicators for phishing and fraud language (English + common Hinglish)."""
import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Rule:
    id: str
    label: str
    weight: int
    explanation: str
    patterns: tuple[str, ...]
    category: str = "language"
    suppresses: tuple[str, ...] = ()


@dataclass
class Hit:
    id: str
    label: str
    weight: int
    explanation: str
    evidence: list[str] = field(default_factory=list)
    category: str = "language"

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "label": self.label,
            "weight": self.weight,
            "explanation": self.explanation,
            "evidence": self.evidence,
            "category": self.category,
        }


BANK_BRANDS = (
    "sbi", "state bank", "hdfc", "icici", "axis bank", "kotak", "pnb", "punjab national", "bank of baroda",
    "canara", "union bank", "yes bank", "idfc", "indusind", "paytm", "phonepe", "google pay", "gpay", "bhim",
    "paypal", "amazon pay", "mobikwik", "airtel payments",
)
OTHER_BRANDS = (
    "amazon", "flipkart", "myntra", "netflix", "apple", "icloud", "microsoft", "outlook", "office 365", "google",
    "gmail", "facebook", "instagram", "whatsapp", "jio", "airtel", "vodafone", "vi ", "bsnl", "fedex", "dhl",
    "blue dart", "bluedart", "india post", "delhivery", "irctc", "dtdc", "ekart", "linkedin", "naukri",
)
GOV_ENTITIES = (
    "income tax", "it department", "rbi", "reserve bank", "epfo", "uidai", "aadhaar", "trai", "dot ", "department of telecom",
    "cbi", "police", "cyber cell", "cyber crime", "customs", "narcotics", "ncb", "enforcement directorate", " ed ",
    "npci", "electricity board", "bescom", "msedcl", "tneb", "bses", "tata power", "parivahan", "traffic challan",
    "e-challan", "rto", "passport", "gst department", "ministry", "government of india", "govt", "court",
    "sebi", "lic", "pm kisan", "pradhan mantri",
)

NEG = r"(?<!not )(?<!n't )(?<!never )"

RULES: tuple[Rule, ...] = (
    Rule("urgency", "Urgency or time pressure", 10,
         "Scammers rush you so you act before thinking or checking.",
         (r"\burgent(?:ly)?\b", r"\bimmediate(?:ly)?\b", r"\bwithin \d+ ?(?:hours?|hrs?|minutes?|mins?|days?)\b",
          r"\btoday only\b", r"\blast (?:chance|date|reminder|warning)\b", r"\bact now\b", r"\bfinal (?:notice|warning|reminder)\b",
          r"\bexpir(?:e|es|ed|ing)\b", r"\bbefore (?:midnight|tonight|\d)", r"\bas soon as possible\b|\basap\b",
          r"\bturant\b", r"\bjaldi\b", r"\baaj hi\b")),
    Rule("threat", "Threat of account block, penalty or arrest", 15,
         "Threatening loss of service, fines or legal action is a classic pressure tactic.",
         (r"\b(?:will be|has been|is|are|been|get) (?:temporarily |permanently )?(?:blocked|suspended|deactivated|frozen|closed|terminated|disconnected|cancell?ed|restricted|locked)\b",
          r"\blegal action\b", r"\b(?:arrest|arrested|warrant)\b", r"\bdigital arrest\b", r"\bfir\b", r"\bpenalty\b|\bfine of\b",
          r"\bpower (?:supply )?(?:will be )?(?:cut|disconnected)\b", r"\bdisconnect(?:ed|ion)\b",
          r"\bkhata band\b", r"\bband ho jayega\b", r"\bcase (?:has been )?(?:filed|registered)\b", r"\bsim (?:will be )?(?:blocked|deactivated)\b")),
    Rule("credential_request", "Asks for OTP, PIN, password or card details", 25,
         "No bank, government office or company will ever ask you to share an OTP, PIN, CVV or password.",
         (NEG + r"\b(?:share|send|provide|tell|give|reply with|enter|update|confirm|verify|submit|forward)\b[^.\n]{0,40}\b(?:otp|one[- ]time password|pin|m-?pin|upi pin|cvv|password|passcode|net ?banking|login details|credentials|card (?:number|details)|debit card|credit card|security code)\b",
          r"\b(?:otp|pin|cvv|password)\b[^.\n]{0,25}\b(?:share|send|tell|batao|bhejo|reply)\b",
          r"\botp batao\b|\botp bhejo\b")),
    Rule("kyc", "KYC / PAN / Aadhaar update demand", 20,
         "Fake 'KYC pending' or 'PAN not linked' messages are the most common Indian banking scam.",
         (r"\bkyc\b[^.\n]{0,40}\b(?:update|pending|expired?|verify|verification|incomplete|suspend|complete|block)",
          r"\b(?:update|complete|verify)\b[^.\n]{0,30}\bkyc\b",
          r"\bpan\b[^.\n]{0,30}\b(?:link|update|not linked|expired)\b", r"\baadhaa?r\b[^.\n]{0,30}\b(?:link|update|verify)\b")),
    Rule("payment_request", "Asks you to pay a fee or approve a payment", 20,
         "Requests to pay a 'processing', 'registration' or 'release' fee, or to approve a UPI collect request, are how the money is taken.",
         (r"\b(?:processing|registration|release|clearance|verification|delivery|redelivery|customs|security|refundable|joining|activation|convenience|service|gst) (?:fee|charge|charges|amount|deposit)\b",
          r"\b(?:pay|transfer|deposit|send)\b[^.\n]{0,30}(?:rs\.?|inr|₹)\s?\d",
          r"\bcollect request\b", r"\bapprove (?:the )?(?:payment|request)\b", r"\benter (?:your )?upi pin to receive\b",
          r"\bscan (?:the )?qr\b[^.\n]{0,30}\b(?:receive|get|refund|cashback)\b",
          r"\bpay (?:now|immediately|today)\b", r"\bpending (?:bill|dues|payment)\b")),
    Rule("prize", "Prize, lottery or unexpected reward", 20,
         "You cannot win a lottery or lucky draw you never entered.",
         (r"\b(?:you have|you've|u have) (?:won|been selected)\b", r"\blottery\b", r"\blucky (?:draw|winner|customer)\b",
          r"\bjackpot\b", r"\bkbc\b", r"\b(?:claim|redeem) (?:your |the )?(?:prize|reward|gift|cashback|voucher|points)\b",
          r"\bcongratulations?\b[^.\n]{0,60}\b(?:won|winner|selected|prize|reward)\b", r"\binaam\b|\blottery lagi\b",
          r"\bfree (?:iphone|gift|recharge)\b")),
    Rule("job", "Too-good-to-be-true job offer", 20,
         "Task-based 'like and earn' or work-from-home offers with a joining fee are fake job scams.",
         (r"\bwork from home\b", r"\bpart[- ]time (?:job|work)\b", r"\bearn\b[^.\n]{0,25}(?:rs\.?|inr|₹)?\s?\d[\d,]*\s?(?:/-)?\s?(?:per|a|daily|/)\s?(?:day|hour|task)",
          r"\b(?:like|subscribe to|rate)\b[^.\n]{0,25}\b(?:youtube|videos|hotels|products)\b[^.\n]{0,40}\b(?:earn|paid|commission)\b",
          r"\bno (?:experience|interview) (?:required|needed)\b", r"\bdaily (?:income|payout|salary)\b", r"\bprepaid tasks?\b",
          r"\bhiring\b[^.\n]{0,40}\b(?:telegram|whatsapp)\b")),
    Rule("investment", "Guaranteed-return investment pitch", 20,
         "Guaranteed or unrealistically high returns are the hallmark of investment and crypto scams.",
         (r"\bguaranteed (?:returns?|profit|income)\b", r"\bdouble (?:your|the) (?:money|investment)\b",
          r"\b\d{1,3}\s?% (?:daily|per day|weekly|monthly|returns?|profit)\b", r"\b(?:crypto|bitcoin|usdt|forex) (?:trading|investment|scheme|plan)\b",
          r"\b(?:stock|trading|share market) (?:tips|group)\b", r"\bipo allotment\b", r"\brisk[- ]free\b[^.\n]{0,20}\b(?:investment|returns?|profit)\b",
          r"\bvip (?:trading )?group\b")),
    Rule("remote_access", "Asks you to install a remote-access or unknown app", 25,
         "Remote-access apps (AnyDesk, TeamViewer) or APK files let fraudsters control your phone and read OTPs.",
         (r"\banydesk\b", r"\bteamviewer\b", r"\bquick ?support\b", r"\brust ?desk\b", r"\b\w+\.apk\b", r"\binstall (?:this|the) app\b",
          r"\bscreen ?shar(?:e|ing)\b", r"\bdownload (?:this|the) (?:app|application|file)\b")),
    Rule("unusual_payment", "Gift card or crypto payment requested", 20,
         "Legitimate organisations don't take payment in gift cards or cryptocurrency.",
         (r"\b(?:gift ?cards?|google play (?:cards?|codes?|vouchers?)|amazon (?:gift )?cards?|itunes cards?|steam cards?)\b",
          r"\b(?:bitcoin|btc|usdt|crypto) (?:wallet|address|payment)\b", r"\bpay (?:in|via|through) (?:bitcoin|crypto|usdt|gift cards?)\b")),
    Rule("delivery", "Parcel held / delivery problem", 15,
         "Fake courier messages claim a parcel is held to collect a small fee and your card details.",
         (r"\b(?:parcel|package|shipment|courier|consignment)\b[^.\n]{0,50}\b(?:held|on hold|returned|undeliver|failed|pending|seized|stuck)",
          r"\b(?:delivery|redelivery) (?:failed|attempt|unsuccessful)\b", r"\b(?:incomplete|incorrect|update (?:your )?) ?address\b")),
    Rule("loan", "Instant / pre-approved loan offer", 15,
         "Unsolicited instant-loan offers lead to fee fraud or predatory loan apps.",
         (r"\bpre[- ]?approved (?:personal )?loan\b", r"\binstant (?:personal )?loan\b", r"\bloan\b[^.\n]{0,30}\bwithout (?:cibil|documents|credit check)\b",
          r"\bno cibil\b")),
    Rule("family_impersonation", "Claims to be family or a friend on a new number", 20,
         "'Hi Mum, I lost my phone, this is my new number' messages ask for urgent money; call the person on their old number first.",
         (r"\b(?:this is my new (?:number|no)|i lost my phone|changed my (?:number|phone)|my phone (?:is )?(?:broken|lost|stolen|dead))\b",
          r"\b(?:hi|hello|hey) (?:mom|mum|dad|papa|mummy|maa|beta)\b[^.\n]{0,80}\b(?:new number|urgent(?:ly)?|money|transfer)\b")),
    Rule("generic_greeting", "Generic greeting", 5,
         "Real banks usually address you by name; 'Dear customer' is common in mass phishing.",
         (r"\bdear (?:customer|user|valued (?:customer|member)|account ?holder|client|sir/?madam|member|beneficiary|winner)\b",)),
    Rule("link_cta", "Pushes you to click a link", 8,
         "Phishing needs you to click; pressure to open a link is a key step.",
         (r"\bclick (?:here|on|the link|below|this link|now)\b", r"\btap (?:here|the link|below)\b", r"\b(?:visit|open|follow) (?:the |this )?link\b",
          r"\blog ?in (?:now|here|immediately|to avoid)\b", r"\bverify (?:now|here|your account)\b")),
    Rule("contact_switch", "Moves you to a phone call or chat app", 10,
         "Fraudsters move you to WhatsApp, Telegram or a phone call where there are fewer safeguards.",
         (r"\b(?:call|contact|whatsapp|message|ping|dm)\b[^.\n]{0,40}(?:\+?91[\s-]?)?(?<!\d)[6-9]\d{9}\b", r"\b(?:telegram|whatsapp) (?:me|us|group|channel)\b",
          r"\bcall (?:us|our (?:executive|helpline|agent)|immediately|now)\b", r"\breply (?:yes|y|stop|with)\b")),
    Rule("secrecy", "Asks you to keep it secret", 10,
         "Being told not to tell family or the bank is a strong sign of 'digital arrest' and investment scams.",
         (r"\b(?:do not|don't) (?:tell|inform|share this with) (?:anyone|your family|the bank|others)\b", r"\bkeep (?:this|it) (?:confidential|secret)\b",
          r"\bconfidential (?:matter|investigation)\b")),
    Rule("impersonation_bank", "Mentions a bank or payment app", 6,
         "The message uses a bank or payment brand; check it really comes from them.",
         tuple(r"\b" + re.escape(b.strip()) + r"\b" for b in BANK_BRANDS), category="impersonation"),
    Rule("impersonation_gov", "Mentions a government body", 8,
         "The message claims to be from a government office; they don't send payment links by SMS.",
         tuple(r"\b" + re.escape(g.strip()) + r"\b" for g in GOV_ENTITIES), category="impersonation"),
    Rule("impersonation_brand", "Mentions a well-known company", 4,
         "The message uses a known brand name; check the sender and link really belong to it.",
         tuple(r"\b" + re.escape(b.strip()) + r"\b" for b in OTHER_BRANDS), category="impersonation"),
)

SAFE_RULES: tuple[Rule, ...] = (
    Rule("safe_otp_warning", "Contains an 'never share your OTP' warning", -15,
         "Genuine OTP and transaction messages usually warn you never to share the code.",
         (r"\b(?:do not|don't|never|pls do not|please do not) (?:share|disclose|tell)\b[^.\n]{0,30}\b(?:otp|pin|code|password|this)\b",
          r"\bnever (?:asks?|call) (?:you )?for\b[^.\n]{0,30}\b(?:otp|pin|password)\b", r"\bif not (?:done|initiated) by you\b"),
         category="reassurance"),
    Rule("safe_delivery_otp", "Delivery OTP to give the agent in person", -10,
         "Couriers and food apps legitimately ask you to tell the delivery agent an OTP when the parcel is handed over.",
         (r"\b(?:share|give|tell)\b[^.\n]{0,20}\botp\b[^.\n]{0,40}\b(?:delivery (?:agent|partner|executive|boy)|at the time of delivery|(?:only )?(?:at|upon|on) delivery)\b",),
         category="reassurance", suppresses=("credential_request",)),
)

_COMPILED = [(r, [re.compile(p, re.I) for p in r.patterns]) for r in RULES + SAFE_RULES]


def _snippet(text: str, m: re.Match) -> str:
    s, e = max(0, m.start() - 25), min(len(text), m.end() + 25)
    return ("…" if s else "") + text[s:e].replace("\n", " ").strip() + ("…" if e < len(text) else "")


def run_text_rules(text: str) -> list[Hit]:
    hits: list[Hit] = []
    for rule, pats in _COMPILED:
        evidence = []
        for p in pats:
            m = p.search(text)
            if m:
                evidence.append(_snippet(text, m))
            if len(evidence) >= 2:
                break
        if evidence:
            hits.append(Hit(rule.id, rule.label, rule.weight, rule.explanation, evidence, rule.category))
    suppressed = {s for rule, _ in _COMPILED if rule.suppresses and any(h.id == rule.id for h in hits) for s in rule.suppresses}
    return [h for h in hits if h.id not in suppressed]
