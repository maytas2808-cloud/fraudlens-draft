"""Named fraud scenarios and the advice shown for each."""

SCENARIOS = {
    "bank_kyc": ("Fake bank / KYC alert",
                 ["Don't click the link or call numbers in the message.",
                  "Open your bank's official app or type the bank's website yourself to check for any alert.",
                  "Banks never ask for OTP, PIN, CVV or passwords by SMS, email or phone.",
                  "If you already shared details, call your bank's official helpline and block your card/UPI immediately."]),
    "payment_request": ("Fraudulent payment request",
                        ["Never enter your UPI PIN to receive money: a PIN is only needed to send money.",
                         "Decline unknown UPI collect requests and don't scan QR codes sent by strangers.",
                         "Don't pay 'processing', 'release' or 'registration' fees to get money or a prize."]),
    "government": ("Government / police impersonation",
                   ["Government offices and police don't demand payments or ID by phone, WhatsApp or SMS.",
                    "There is no such thing as a 'digital arrest'. Hang up and don't transfer money.",
                    "Check directly on the official .gov.in website or by visiting the office.",
                    "Report it at cybercrime.gov.in or call 1930."]),
    "digital_arrest": ("'Digital arrest' scam",
                       ["Police, CBI, ED and customs never arrest anyone over a video call or ask for money to 'clear your name'.",
                        "Don't stay on the call, don't transfer money and don't keep it secret: tell family immediately.",
                        "Call 1930 or report at cybercrime.gov.in."]),
    "job": ("Fake job / task scam",
            ["Real employers don't charge a joining or registration fee.",
             "'Like videos / rate hotels and earn' tasks are a known scam that ends in asking you to deposit money.",
             "Check the company on its official website and LinkedIn before sharing documents."]),
    "investment": ("Investment / trading scam",
                   ["No legitimate investment guarantees high or fixed daily returns.",
                    "Only invest through SEBI-registered brokers and apps; check registration on sebi.gov.in.",
                    "Be wary of WhatsApp/Telegram 'VIP trading groups' and screenshots of profits."]),
    "prize": ("Prize / lottery scam",
              ["You can't win a lottery or lucky draw you never entered.",
               "Never pay a fee or tax to release a prize.",
               "Delete the message and block the sender."]),
    "delivery": ("Courier / delivery scam",
                 ["Check delivery status only in the courier's official app or website using your own tracking number.",
                  "Couriers don't ask for card details to 'update an address'."]),
    "tech_support": ("Remote-access / tech-support scam",
                     ["Never install AnyDesk, TeamViewer or an APK because someone asked you to.",
                      "If you installed one, uninstall it, turn on flight mode and call your bank to secure your accounts."]),
    "loan": ("Loan scam",
             ["Only take loans from RBI-registered lenders; check the lender on the RBI website.",
              "Don't pay upfront fees and don't give loan apps access to your contacts and photos."]),
    "family": ("Family / friend impersonation",
               ["Call the person on the number you already have saved, or ask a question only they would know.",
                "Don't send money to a 'new number' or a new UPI ID until you have spoken to them."]),
    "credential_phishing": ("Credential phishing",
                            ["Don't enter passwords or OTPs on pages opened from a message.",
                             "Go to the site by typing its address yourself or using the official app.",
                             "If you entered a password, change it now and turn on two-factor authentication."]),
    "malware": ("Malware link",
                ["Don't open the link or download anything from it.",
                 "If you already downloaded a file, don't run it; scan your device."]),
}

GENERAL = {
    "high": ["Treat this as a scam. Don't reply, click, call back or pay.",
             "Verify independently using contact details you already trust (official app, website you type yourself, card back).",
             "Report it: forward scam SMS to 7726 (SPAM), report at sancharsaathi.gov.in (Chakshu), or cybercrime.gov.in / call 1930 if money was lost."],
    "medium": ["Be careful. Don't act on this message until you have verified it independently.",
               "Contact the organisation using details you find yourself, not those in the message."],
    "low": ["No strong warning signs found. Still, never share OTPs, PINs or passwords, and stay alert to unusual requests."],
}


def detect_scenarios(ids: set[str], intel_types: set[str]) -> list[str]:
    s = []
    if "digital_arrest" in ids or ({"impersonation_gov", "threat", "secrecy"} <= ids):
        s.append("digital_arrest")
    if "kyc" in ids or ("impersonation_bank" in ids and ids & {"threat", "credential_request", "link_cta", "urgency"}):
        s.append("bank_kyc")
    if "impersonation_gov" in ids and ids & {"threat", "payment_request", "credential_request", "link_cta", "urgency"} and "digital_arrest" not in s:
        s.append("government")
    for rid, name in (("job", "job"), ("investment", "investment"), ("prize", "prize"), ("delivery", "delivery"),
                      ("remote_access", "tech_support"), ("loan", "loan"), ("family_impersonation", "family")):
        if rid in ids:
            s.append(name)
    if ids & {"payment_request", "unusual_payment"}:
        s.append("payment_request")
    if ids & {"credential_request", "brand_mismatch", "lookalike", "sender_brand_mismatch", "punycode"} and "bank_kyc" not in s:
        s.append("credential_phishing")
    if any("malware" in t for t in intel_types):
        s.append("malware")
    return s


def advice(level: str, scenarios: list[str]) -> list[str]:
    out = list(GENERAL[level])
    if level != "low":
        for sc in scenarios:
            for tip in SCENARIOS[sc][1]:
                if tip not in out:
                    out.append(tip)
    return out[:8]
