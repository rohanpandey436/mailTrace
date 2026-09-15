from __future__ import annotations

import logging
import re
import unicodedata

from ..config import Settings
from ..schemas import (
    SEVERITY_ORDER,
    AttachmentAnalysis,
    AuthResult,
    BecPattern,
    BecPatternName,
    Finding,
    NlpAnalysis,
    ParsedEmail,
    Severity,
    ShapWeight,
    ThreatCategory,
    UrlAnalysis,
)
from .knowledge import BRANDS, EXEC_TITLES, FREEMAIL_DOMAINS
from .link_analyzer import registrable_domain

log = logging.getLogger("mailtrace.nlp")

URGENCY = (
    "immediately", "urgent", "urgently", "within 24 hours", "within 48 hours", "within 72 hours", "asap",
    "as soon as possible", "right away", "act now", "final notice", "last chance", "expires today",
    "expire today", "deadline", "time-sensitive", "time sensitive", "do not delay", "respond today",
    "before it's too late", "last warning", "final warning", "today only", "limited time", "without delay",
    "promptly", "at the earliest", "by end of day", "before 4 pm", "before 5 pm", "24 hours", "48 hours",
    "72 hours", "immediate action", "action required", "respond immediately", "reply immediately",
    "right now", "hurry", "expiring today", "expires in", "only today", "before midnight", "within the hour",
)
THREAT = (
    "suspended", "suspension", "terminated", "termination", "legal action", "penalty", "blocked", "locked",
    "unauthorized access", "unauthorised access", "unusual activity", "suspicious activity", "police", "court",
    "arrest", "fine of", "deactivated", "deactivation", "compromised", "restricted", "frozen",
    "permanently disabled", "permanently deactivated", "permanent suspension", "disabled", "de-registered",
    "cancelled", "cancellation", "seized", "lawsuit", "prosecution", "cyber cell", "tax evasion",
    "non-compliance", "warrant", "blacklisted", "will be deleted", "will be closed", "will be suspended",
    "will be blocked", "will be disconnected", "expired", "failure to", "failed to comply", "breach",
    "hacked", "stolen", "fraudulent activity", "case registered", "fir", "summons", "penal action",
)
FINANCIAL = (
    "invoice", "payment", "wire transfer", "bank account", "account number", "ifsc", "swift", "iban", "upi",
    "neft", "rtgs", "imps", "beneficiary", "remittance", "remit", "overdue", "pending payment", "gift card",
    "gift cards", "bitcoin", "crypto", "cryptocurrency", "tax refund", "refund", "lottery", "prize",
    "inheritance", "fund transfer", "processing fee", "transfer fee", "insurance fee", "registration fee",
    "security deposit", "winnings", "cash prize", "payout", "purchase order", "bank details",
    "banking details", "account details", "utr", "transaction", "wallet", "cashback", "loan", "investment",
    "guaranteed returns", "profit", "commission", "bank transfer", "western union", "moneygram", "lakh",
    "crore", "rupees", "usd", "dollars", "amount", "fee", "fees", "pay", "paid", "deposit", "cheque", "demand draft",
    "money", "dollar", "rupee", "rs", "rs.", "inr", "lakhs", "crores", "cash", "euro", "euros", "pounds",
    "paise", "paisa", "paisey", "rupaye", "rupay", "btc", "eth", "usdt", "paytm", "phonepe", "gpay", "google pay",
    "पैसे", "पैसा", "रुपये", "रुपए", "लाख", "करोड़",
)
MONEY_DEMAND = (
    "send me", "give me", "pay me", "pay us", "send us", "transfer me", "return my money", "money back", "my money",
    "give back", "want my money", "paise de", "paisa de", "paise do", "paise bhejo", "bhejo", "bhej do", "de de",
    "de do", "dedo", "wapas do", "wapas kar", "vapas do", "vapas kar", "lauta", "पैसे दो", "पैसे भेजो", "वापस दो",
    "दे दो", "भेजो", "लौटा",
)
VIOLENCE = (
    "kill you", "kill u", "kill your", "i will kill", "will kill you", "murder you", "hurt you", "hurt your family",
    "harm you", "harm your family", "your family will suffer", "i know where you live", "know where you live",
    "know where your family", "where your family lives", "watch your back", "pray for your life", "pray for u r life",
    "pray for ur life", "you will regret", "you'll regret", "you will regret it", "break your legs", "shoot you",
    "stab you", "burn your house", "acid attack", "rape you", "beat you up", "bomb", "blow up your", "blow you up",
    "your life is in danger", "last day of your life", "you are dead", "u r dead", "you are a dead man",
    "finish you", "destroy you", "ruin your life", "ruin you", "i am watching you", "i'm watching you",
    "watching you", "i saw you", "i know your address", "i know your house", "i know where you work",
    "jaan se maar", "jaan se mar", "jan se maar", "jan se mar", "maar dunga", "maar dalunga", "mar dunga",
    "mar dalunga", "maar daalunga", "dekh lunga", "dekh loonga", "chhodunga nahi", "chodunga nahi",
    "nahi chhodunga", "nahi chodunga", "anjaam bura", "anjam bura", "khatam kar dunga", "khatam kar",
    "tumhari khair nahi", "teri khair nahi", "ghar jaanta hoon", "ghar janta hu",
    "जान से मार", "मार दूंगा", "मार डालूंगा", "मार डालेंगे", "छोड़ूंगा नहीं", "नहीं छोड़ूंगा", "अंजाम बुरा",
    "खत्म कर दूंगा", "देख लूंगा", "बम", "जान ले लूंगा", "तेरी खैर नहीं", "तुम्हारी खैर नहीं",
)
EXTORTION = (
    "leak your", "leak them", "leak it", "publish your", "publish everything", "publish them", "send the video",
    "send them to all", "send it to all", "send it to your", "all your contacts", "your contact list",
    "private photos", "your photos", "your pictures", "intimate", "nude", "nudes", "webcam", "recorded you",
    "i have your", "we have your", "i have a video", "i have videos", "we have downloaded", "your data",
    "your files", "pay or", "or else", "otherwise i will", "otherwise i", "last warning", "final warning",
    "this is not a joke", "not a joke", "do not contact the police", "don't contact the police",
    "do not involve the police", "not involve the police", "do not go to the police", "price doubles",
    "price will double", "ransom", "decryption key", "encrypted your", "hush money", "keep quiet",
    "or i will", "or we will", "or i send", "or i'll", "warna", "varna", "nahi to", "nahi toh", "nhi to", "nhi toh",
    "वरना", "नहीं तो",
)
INVESTMENT = (
    "guaranteed returns", "guaranteed return", "guaranteed profit", "guaranteed profits", "guaranteed income",
    "double your money", "triple your money", "risk-free", "risk free", "zero risk", "passive income",
    "trading bot", "ai trading", "auto trading", "monthly returns", "daily returns", "weekly returns",
    "daily profit", "monthly profit", "investment plan", "investment opportunity", "minimum deposit",
    "minimum investment", "withdraw profit", "withdraw any time", "withdraw anytime", "crypto trading",
    "forex trading", "binary options", "mining contract", "high returns", "assured returns", "fixed returns",
    "% returns", "% return", "% profit", "% monthly", "% daily", "returns of", "roi of", "join our investment",
    "investors trust us", "investment scheme", "trading platform", "grow your money", "multiply your money",
)
TECHSUPPORT = (
    "infected", "virus", "viruses", "malware", "spyware", "trojan", "ransomware detected", "your computer",
    "your pc", "your laptop", "your device", "licence has expired", "license has expired", "licence expired",
    "license expired", "windows licence", "windows license", "certified support", "certified technician",
    "technician", "remote access", "anydesk", "teamviewer", "ultraviewer", "call our support", "call microsoft",
    "call apple", "call now", "call immediately", "toll free", "toll-free", "do not switch off",
    "don't switch off", "do not turn off", "don't turn off", "security warning", "system alert", "firewall",
    "at risk", "your antivirus", "antivirus subscription", "auto-renewed", "auto renewed", "geek squad",
    "norton", "mcafee",
)
STRONG_MONEY_TERMS: frozenset[str] = frozenset({
    "money", "cash", "paise", "paisa", "paisey", "rupaye", "rupay", "rupees", "rupee", "rs", "rs.", "inr", "dollars",
    "dollar", "usd", "euro", "euros", "pounds", "lakh", "lakhs", "crore", "crores", "bitcoin", "btc", "eth", "usdt",
    "crypto", "cryptocurrency", "wallet", "bank account", "bank transfer", "wire transfer", "western union", "moneygram",
    "upi", "paytm", "phonepe", "gpay", "google pay", "gift card", "gift cards", "ransom",
    "पैसे", "पैसा", "रुपये", "रुपए", "लाख", "करोड़",
})
_MONEY_AMOUNT_RE = re.compile(
    r"(?:(?:rs\.?|inr|usd|₹|\$|€|£)\s?\d[\d,]*(?:\.\d+)?(?:\s?(?:lakh|lakhs|crore|crores|k))?"
    r"|\b\d[\d,]*(?:\.\d+)?\s?(?:rupees|rupee|rs|dollars|dollar|usd|lakh|lakhs|crore|crores|btc|eth|usdt|रुपये|रुपए))",
    re.IGNORECASE,
)
_UPI_HANDLE_RE = re.compile(
    r"(?<![\w.])[a-z0-9][a-z0-9._-]{1,}@(?:ybl|paytm|ptyes|ptaxis|ptsbi|pthdfc|okaxis|oksbi|okicici|okhdfcbank|"
    r"okbizaxis|ibl|axl|apl|yapl|upi|ikwik|fam|kotak|indus|sbi|hdfcbank|icici|axisbank|barodampay|cnrb|boi|pnb|"
    r"idfcbank|federal|dbs|yesbank|waaxis|wasbi|wahdfcbank|waicici|freecharge|airtel|slice|naviaxis|goaxb|kmbl|"
    r"abfspay|superyes|tapicici|timecosmos|mbk|amazonpay|jupiteraxis|rapl|axisb|postbank|jio)(?![\w.])",
    re.IGNORECASE,
)
_WALLET_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40}|T[A-Za-z1-9]{33})(?![A-Za-z0-9])"
)
_IFSC_RE = re.compile(r"(?<![A-Za-z0-9])[A-Z]{4}0[A-Z0-9]{6}(?![A-Za-z0-9])")
_REMITTANCE_RE = re.compile(r"\b(?:western union|moneygram|ria money|mtcn)\b", re.IGNORECASE)
_PHONE_RE = re.compile(r"(?<![\d@\w])(?:\+\d{1,3}[\s-]?)?(?:\d[\s-]?){9,12}\d(?![\d\w])")
CREDENTIAL = (
    "password", "passcode", "verify your account", "verify account", "login", "log in", "sign in", "signin",
    "username", "user id", "otp", "one-time password", "one time password", "pin", "cvv", "aadhaar", "aadhar",
    "pan card", "pan number", "re-enter", "confirm your identity", "update your details",
    "update your information", "security check", "2fa", "two-factor", "kyc", "re-verify", "re-verification",
    "verification code", "credentials", "account verification", "validate your account", "confirm your account",
    "unlock your account", "reactivate", "secure your account", "authenticate", "login details", "net banking",
    "netbanking", "debit card", "credit card", "card number", "expiry date", "security question",
    "mother's maiden name", "verify your identity", "identity verification", "biometric", "e-kyc", "re-kyc",
)
AUTHORITY = (
    "ceo", "cfo", "coo", "cto", "director", "managing director", "chairman", "president", "manager",
    "government", "income tax department", "rbi", "reserve bank", "police", "bank official", "hr department",
    "it department", "it helpdesk", "helpdesk", "administrator", "admin team", "security team", "compliance",
    "legal department", "ministry", "officer", "official", "sebi", "uidai", "cyber cell", "customs", "court",
    "supreme court", "high court", "tax authority", "regulator", "board", "commissioner", "inspector",
)
SECRECY = (
    "confidential", "keep this between us", "do not discuss", "discreet", "discretion", "do not tell",
    "private matter", "handle quietly", "do not share", "strictly confidential", "do not disclose",
    "between you and me", "don't mention", "keep it private", "without informing", "secret",
    "not to inform", "do not inform", "keep this to yourself", "avoid double claiming",
)
REWARD = (
    "won", "winner", "congratulations", "reward", "bonus", "free", "selected", "claim", "cashback", "prize",
    "jackpot", "lucky", "gift", "voucher", "coupon", "giveaway", "lottery", "grant", "award", "winning",
    "credited", "approved", "eligible", "lucky draw", "prize draw", "claim now", "redeem",
)
SCARCITY = (
    "only a few", "limited", "exclusive", "last few", "stock", "spots left", "seats left", "first come",
    "while supplies last", "limited slots", "limited period", "few hours left", "running out",
    "only 3 left", "limited offer", "one-time offer",
)
CURIOSITY = (
    "see attached", "see the attached", "you have a new message", "document shared", "shared a document",
    "shared a file", "new voicemail", "voice message", "new fax", "invoice attached", "check the attachment",
    "open the attachment", "view document", "review the document", "attached claim form", "attached form",
)
GENERIC_GREETINGS = (
    "dear customer", "dear user", "dear member", "dear sir", "dear madam", "dear sir/madam",
    "dear account holder", "dear valued", "dear client", "dear beneficiary", "dear lucky winner", "dear winner",
    "dear friend", "dear taxpayer", "dear employee", "dear subscriber", "dear cardholder", "dear applicant",
    "hello customer", "hello user", "attention:", "attn:", "dear participant", "dear recipient",
)
REPLY_CUES = (
    "reply to this email", "reply on this email", "respond with", "send me your number", "kindly revert",
    "revert back", "reply with", "reply back", "email me back", "reply only", "respond to this email",
    "write back", "reply immediately", "reply asap", "confirm by replying", "share the utr", "on this email only",
    "revert to this email", "reply on my personal", "contact our claims officer", "get back to me",
)
_BANK_CHANGE_TERMS = (
    "bank account", "account number", "ifsc", "swift", "iban", "beneficiary", "routing number", "sort code",
    "account details", "bank details", "banking details", "wire instructions", "remittance instructions",
    "account type", "bank name",
)
_CHANGE_TERMS = (
    "change", "changed", "update", "updated", "new account", "revised", "different account", "new bank",
    "no longer", "instead of", "alternate account", "alternative account", "use the following", "use the new",
    "below account", "account below", "new remittance", "new details", "under audit", "new beneficiary",
)
_PAYMENT_ACTION_TERMS = (
    "release the payment", "release payment", "make the payment", "process the payment", "transfer the amount",
    "pay", "payment", "transfer", "remit", "neft", "rtgs", "wire", "settle", "clear the invoice",
)
_UNCHANGED_RE = re.compile(
    r"\b(?:unchanged|remains? the same|not changed|no change|same as before|same as always|as per (?:our |the )?contract)\b"
)
_PAYMENT_DIVERSION_EXPLICIT = (
    "bank details have changed", "new account below", "updated bank details",
    "remit to the new", "pay to this account", "account is under audit", "update the beneficiary",
    "updated beneficiary", "new remittance instructions", "wire instructions changed", "changed our bank",
    "use the new account", "payment to the new account", "release the payment to the new",
)
_INVOICE_TERMS = ("invoice", "bill", "statement", "purchase order", "po number", "receipt", "payment request", "outstanding balance")
_DUE_TERMS = (
    "attached", "overdue", "past due", "due", "pay now", "pending", "outstanding", "final notice",
    "kindly pay", "make the payment", "release payment", "unpaid", "settle", "immediate payment",
)
_CTA_TERMS = (
    "click here", "login here", "verify now", "click the link", "click below", "update now", "confirm now",
    "sign in here", "verify here", "complete kyc", "click to verify", "follow the link", "use the link",
    "access your account", "complete verification", "verify now:", "open this link", "link below",
)
_CRED_EXPLICIT = (
    "enter your password", "enter your otp", "enter the otp", "provide your password", "share your otp",
    "share the otp", "confirm your password", "re-enter your password", "enter your pin", "submit your details",
    "fill in your details", "confirm your account number", "confirm your account", "aadhaar number",
    "pan card details", "otp sent to your phone", "registered mobile number",
)
_EXEC_PHRASES = (
    "are you available", "are you at your desk", "at your desk", "quick task", "quick favour", "quick favor",
    "need a favour", "need a favor", "i'm in a meeting", "i am in a meeting", "in a meeting", "can't talk",
    "cannot take calls", "can't take calls", "gift cards", "gift card", "keep this confidential",
    "reply on this email", "reply on my personal", "personal email", "urgent request", "handle something",
    "need you to handle", "let me know once you see this", "are you free", "got a moment", "do you have a moment",
    "i need your help", "need your assistance", "before i board", "boarding a flight", "travelling", "traveling",
    "board meeting", "unreachable on phone", "handle this over email", "email only", "do the needful",
    "sent from my iphone", "let me know when you are", "i need you to", "task for you",
)
_ATTACHMENT_LURE_RE = re.compile(r"(invoice|bill|payment|remittance|receipt|statement|\bpo\b|purchase[_ -]?order|claim[_ -]?form|swift|payslip)", re.IGNORECASE)
_DEVANAGARI_RE = re.compile(r"[ऀ-ॿ]")
_LETTER_RE = re.compile(r"[A-Za-zऀ-ॿ]")
_WORD_RE = re.compile(r"\S+")


def _compile(lexicon: tuple[str, ...]) -> re.Pattern[str]:
    phrases = sorted({p.lower() for p in lexicon}, key=len, reverse=True)
    alternatives = "|".join(re.escape(p).replace(r"\ ", " ").replace(" ", r"\s+") for p in phrases)
    return re.compile(rf"(?<![\w-])(?:{alternatives})(?![\w-])", re.IGNORECASE)


_PATTERNS: dict[str, re.Pattern[str]] = {
    name: _compile(lexicon)
    for name, lexicon in {
        "urgency": URGENCY, "threat": THREAT, "financial": FINANCIAL, "credential": CREDENTIAL,
        "authority": AUTHORITY, "secrecy": SECRECY, "reward": REWARD, "scarcity": SCARCITY,
        "curiosity": CURIOSITY, "greeting": GENERIC_GREETINGS, "reply": REPLY_CUES,
        "bank_change": _BANK_CHANGE_TERMS, "change": _CHANGE_TERMS, "payment_action": _PAYMENT_ACTION_TERMS,
        "payment_explicit": _PAYMENT_DIVERSION_EXPLICIT, "invoice": _INVOICE_TERMS, "due": _DUE_TERMS,
        "cta": _CTA_TERMS, "cred_explicit": _CRED_EXPLICIT, "exec": _EXEC_PHRASES,
        "money_demand": MONEY_DEMAND, "violence": VIOLENCE, "extortion": EXTORTION,
        "investment": INVESTMENT, "techsupport": TECHSUPPORT,
    }.items()
}


def payment_handles(text: str) -> list[str]:
    found: list[str] = []
    for match in _UPI_HANDLE_RE.finditer(text):
        found.append(f"UPI {match.group(0).lower()}")
    for match in _WALLET_RE.finditer(text):
        found.append(f"wallet {match.group(0)}")
    for match in _IFSC_RE.finditer(text):
        found.append(f"IFSC {match.group(0)}")
    for match in _REMITTANCE_RE.finditer(text):
        found.append(match.group(0).lower())
    return _dedupe(found)


def _first_party_links(parsed: ParsedEmail, url_analysis: UrlAnalysis, cfg: Settings, auth: AuthResult | None) -> bool:
    if auth is None or not url_analysis.urls:
        return False
    if auth.spf.lower() != "pass" and auth.dkim.lower() != "pass":
        return False
    if not (auth.spf_aligned or auth.dkim_aligned) or auth.dmarc.lower() == "fail":
        return False
    sender_rd = registrable_domain(parsed.sender.domain)
    if not sender_rd:
        return False
    allowed = {sender_rd} | {registrable_domain(d) for d in cfg.org_domains if d}
    for domains in BRANDS.values():
        if sender_rd in domains:
            allowed |= {registrable_domain(d) for d in domains}
    hosts = [u for u in url_analysis.urls if u.host]
    return bool(hosts) and all((u.registrable_domain or registrable_domain(u.host)) in allowed for u in hosts)


def normalize_text(subject: str, body: str) -> str:
    combined = f"{subject or ''}\n{body or ''}"
    combined = unicodedata.normalize("NFKC", combined)
    combined = combined.replace("’", "'").replace("‘", "'").replace("“", '"').replace("”", '"')
    combined = combined.replace("–", "-").replace("—", "-")
    combined = re.sub(r"[ \t\r\f\v\xa0]+", " ", combined)
    combined = re.sub(r" *\n *", "\n", combined)
    combined = re.sub(r"\n{2,}", "\n", combined)
    return combined.strip().lower()[:200000]


def model_input(parsed: ParsedEmail) -> str:
    return normalize_text(parsed.subject, _body_text(parsed))


def _hits(name: str, text: str) -> list[str]:
    seen: set[str] = set()
    found: list[str] = []
    for match in _PATTERNS[name].finditer(text):
        phrase = re.sub(r"\s+", " ", match.group(0).lower())
        if phrase not in seen:
            seen.add(phrase)
            found.append(phrase)
    return found


def detect_language(text: str) -> str:
    letters = _LETTER_RE.findall(text or "")
    if not letters:
        return "en"
    devanagari = sum(1 for ch in letters if _DEVANAGARI_RE.match(ch))
    ratio = devanagari / len(letters)
    if ratio > 0.3:
        return "hi"
    return "en"


def _body_text(parsed: ParsedEmail) -> str:
    if parsed.text_body:
        return parsed.text_body
    if parsed.html_body:
        from .parser import html_to_text

        return html_to_text(parsed.html_body)
    return ""


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def _sender_is_external(parsed: ParsedEmail, cfg: Settings) -> bool:
    sender_rd = registrable_domain(parsed.sender.domain)
    org = {registrable_domain(d) for d in cfg.org_domains if d}
    return bool(sender_rd) and sender_rd not in org


def _reply_to_mismatch(parsed: ParsedEmail) -> bool:
    sender_rd = registrable_domain(parsed.sender.domain)
    return any(r.domain and registrable_domain(r.domain) != sender_rd for r in parsed.reply_to)


def _display_name_signals(parsed: ParsedEmail, cfg: Settings) -> list[str]:
    name = (parsed.sender.display_name or "").lower()
    if not name:
        return []
    signals: list[str] = []
    for title in list(EXEC_TITLES) + [e for e in cfg.executives if e]:
        title = title.lower().strip()
        if title and re.search(rf"(?<![\w]){re.escape(title)}(?![\w])", name):
            signals.append(f"display name '{parsed.sender.display_name}' matches '{title}'")
            break
    return signals


def detect_bec_patterns(
    text: str,
    parsed: ParsedEmail,
    url_analysis: UrlAnalysis,
    att_analysis: AttachmentAnalysis,
    cfg: Settings,
    auth: AuthResult | None = None,
) -> list[BecPattern]:
    patterns: list[BecPattern] = []
    urgency = _hits("urgency", text)
    secrecy = _hits("secrecy", text)
    threat = _hits("threat", text)
    reply_cues = _hits("reply", text)
    external = _sender_is_external(parsed, cfg)
    sender_free = registrable_domain(parsed.sender.domain) in FREEMAIL_DOMAINS
    reply_mismatch = _reply_to_mismatch(parsed)
    word_count = len(_WORD_RE.findall(text))
    first_party = _first_party_links(parsed, url_analysis, cfg, auth)
    risky_urls = [u for u in url_analysis.urls if SEVERITY_ORDER[u.risk.value] >= SEVERITY_ORDER["medium"]]
    high_urls = [u for u in url_analysis.urls if SEVERITY_ORDER[u.risk.value] >= SEVERITY_ORDER["high"]]
    keyword_urls = [] if first_party else [u for u in url_analysis.urls if u.suspicious_keywords]
    high_atts = [a for a in att_analysis.attachments if SEVERITY_ORDER[a.risk.value] >= SEVERITY_ORDER["high"]]

    bank = _hits("bank_change", text)
    change = _hits("change", text)
    explicit_pay = _hits("payment_explicit", text)
    action = _hits("payment_action", text)
    if bank and change and not explicit_pay and _UNCHANGED_RE.search(text):
        change = []
    conf = 0.0
    evidence: list[str] = []
    if bank and change and action:
        conf = 0.4
        evidence += bank[:2] + change[:2] + action[:2]
        if urgency:
            conf += 0.15
            evidence.append(urgency[0])
        if secrecy:
            conf += 0.15
            evidence.append(secrecy[0])
        if reply_mismatch:
            conf += 0.15
            evidence.append("reply-to domain differs from sender")
    if explicit_pay:
        conf = max(conf, 0.7)
        evidence = explicit_pay[:2] + [e for e in evidence if e not in explicit_pay]
        if urgency or secrecy or reply_mismatch:
            conf += 0.15
    if conf >= 0.35:
        patterns.append(BecPattern(pattern="payment_diversion", confidence=_clamp01(conf), evidence=_dedupe(evidence)))

    invoice = _hits("invoice", text)
    due = _hits("due", text)
    conf = 0.0
    evidence = []
    if invoice and due:
        conf = 0.3
        evidence += invoice[:2] + due[:2]
    lure_atts = [a for a in att_analysis.attachments if _ATTACHMENT_LURE_RE.search(a.filename)]
    if lure_atts and (invoice or due):
        conf = max(conf, 0.3)
        if any(SEVERITY_ORDER[a.risk.value] >= SEVERITY_ORDER["medium"] for a in lure_atts):
            conf += 0.25
            evidence.append(f"attachment '{lure_atts[0].filename}' ({lure_atts[0].risk.value} risk)")
        else:
            evidence.append(f"attachment '{lure_atts[0].filename}'")
    if conf > 0 and high_atts:
        conf += 0.2
        evidence.append(f"dangerous attachment '{high_atts[0].filename}'")
    if conf > 0 and urgency:
        conf += 0.1
        evidence.append(urgency[0])
    if conf > 0 and (reply_mismatch or sender_free) and invoice:
        conf += 0.1
        evidence.append("free-mail sender" if sender_free else "reply-to domain differs from sender")
    if conf >= 0.35:
        patterns.append(BecPattern(pattern="fake_invoice", confidence=_clamp01(conf), evidence=_dedupe(evidence)))

    cred = _hits("credential", text)
    cta = _hits("cta", text)
    explicit_cred = _hits("cred_explicit", text)
    conf = 0.0
    evidence = []
    link_signal = bool(risky_urls or keyword_urls)
    if cred and (link_signal or cta):
        conf = 0.4
        evidence += cred[:3]
        if cta:
            evidence.append(cta[0])
        if link_signal:
            sample = (risky_urls or keyword_urls)[0]
            evidence.append(f"link {sample.host or sample.url[:60]}")
        if explicit_cred:
            conf += 0.2
            evidence += explicit_cred[:2]
        if high_urls:
            conf += 0.15
        if threat:
            conf += 0.1
            evidence.append(threat[0])
        if urgency:
            conf += 0.1
    elif len(cred) >= 3 and (reply_cues or explicit_cred) and not url_analysis.urls:
        conf = 0.45
        evidence += cred[:3] + (reply_cues[:1] or explicit_cred[:1])
        evidence.append("credentials requested by reply")
    elif explicit_cred and cred:
        conf = 0.35
        evidence += explicit_cred[:2]
    if conf > 0 and first_party and not high_urls:
        conf *= 0.5
        evidence.append("every link stays on the authenticated sender's own domain")
    if conf >= 0.35:
        patterns.append(BecPattern(pattern="credential_harvesting", confidence=_clamp01(conf), evidence=_dedupe(evidence)))

    financial = _hits("financial", text)
    demand = _hits("money_demand", text)
    handles = payment_handles(text)
    violence = _hits("violence", text)
    extortion = _hits("extortion", text)
    strong_money = [t for t in financial if t in STRONG_MONEY_TERMS]
    amounts = [m.group(0).strip() for m in _MONEY_AMOUNT_RE.finditer(text)]
    money = bool(strong_money or demand or handles or amounts)
    conf = 0.0
    evidence = []
    if violence:
        conf = 0.55 + min(0.2, 0.1 * (len(violence) - 1))
        evidence += violence[:3]
        if extortion:
            conf += 0.15
            evidence += extortion[:2]
    elif extortion and money:
        conf = 0.45 + min(0.25, 0.1 * len(extortion))
        evidence += extortion[:3]
    if conf > 0 and money:
        conf += 0.1
        evidence += (amounts[:1] + strong_money[:2] + demand[:1] + handles[:1])[:3]
    if conf > 0 and urgency:
        conf += 0.05
    if conf >= 0.35:
        name: BecPatternName = "extortion" if money else "violent_threat"
        patterns.append(BecPattern(pattern=name, confidence=_clamp01(conf), evidence=_dedupe(evidence)))

    invest = _hits("investment", text)
    reward = _hits("reward", text)
    scarcity = _hits("scarcity", text)
    conf = 0.0
    evidence = []
    if len(invest) >= 2 or (invest and (reward or scarcity or handles)):
        conf = 0.4 + 0.1 * min(3, max(0, len(invest) - 1))
        evidence += invest[:3]
        if url_analysis.urls or handles:
            conf += 0.1
            evidence.append(f"link {url_analysis.urls[0].host}" if url_analysis.urls else handles[0])
        if scarcity or urgency:
            conf += 0.1
            evidence += (scarcity or urgency)[:1]
        if reward:
            evidence += reward[:1]
    if conf >= 0.35:
        patterns.append(BecPattern(pattern="investment_scam", confidence=_clamp01(conf), evidence=_dedupe(evidence)))

    tech = _hits("techsupport", text)
    phones = [m.group(0).strip() for m in _PHONE_RE.finditer(text)]
    authority = _hits("authority", text)
    conf = 0.0
    evidence = []
    if len(tech) >= 2 and (phones or urgency or threat):
        conf = 0.4 + 0.1 * min(3, len(tech) - 2)
        evidence += tech[:3]
        if phones:
            conf += 0.2
            evidence.append(f"phone {phones[0]}")
        if authority:
            conf += 0.1
            evidence += authority[:1]
        if urgency:
            evidence += urgency[:1]
    if conf >= 0.35:
        patterns.append(BecPattern(pattern="callback_scam", confidence=_clamp01(conf), evidence=_dedupe(evidence)))

    name_signals = _display_name_signals(parsed, cfg)
    exec_phrases = _hits("exec", text)
    conf = 0.0
    evidence = []
    if name_signals:
        conf += 0.35
        evidence += name_signals
    if exec_phrases:
        conf += min(0.45, 0.15 * len(exec_phrases))
        evidence += exec_phrases[:4]
    if conf > 0:
        if word_count < 120:
            conf += 0.1
            evidence.append(f"short message ({word_count} words)")
        if sender_free or external:
            conf += 0.1
            evidence.append("free-mail sender" if sender_free else "sender outside the protected organisation")
        if reply_cues:
            conf += 0.05
    if conf >= 0.35:
        patterns.append(BecPattern(pattern="executive_impersonation", confidence=_clamp01(conf), evidence=_dedupe(evidence)))
    return patterns


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out[:8]


def _heuristic_probabilities(
    cred: int, fin: int, threat: int, reward: int, secrecy: int, authority: int, urgency: float,
    exec_conf: float, link_signal: bool, total_words: int,
) -> dict[str, float]:
    weights = {
        "Phishing": 1.0 * cred + (2.0 if link_signal else 0.0) + 0.5 * threat,
        "Fraud-Related": 1.0 * fin + 0.7 * reward + 0.5 * secrecy,
        "Impersonated": 3.0 * exec_conf + 0.5 * authority,
        "Suspicious": 0.5 + 2.0 * urgency,
        "Legitimate": 3.0 if total_words else 1.0,
    }
    total = sum(weights.values()) or 1.0
    return {label: round(value / total, 4) for label, value in weights.items()}


_SHAP_TOP_K = 12
_ATTRIBUTION_METHOD = {"linear": "exact-shap-linear", "transformer": "occlusion", "unavailable": "none"}

_ModelOutcome = tuple[str | None, dict[str, float], list[str], list[tuple[str, float]], str, str]


def _run_bundled_transformer(text: str) -> _ModelOutcome | None:
    try:
        from ..ai import transformer
    except ImportError:
        return None
    classifier = transformer.TransformerClassifier.load()
    if classifier is None:
        return None
    try:
        label, probabilities = classifier.predict(text)
        attributions = transformer.occlusion_attributions(classifier, text, label, probabilities.get(label, 0.0))
    except Exception:
        log.exception("the bundled transformer failed; using the linear classifier")
        return None
    top_terms = [token for token, weight in attributions if weight > 0][:8]
    name = f"distilroberta-onnx-int8 ({transformer.ATTRIBUTION_METHOD} attribution)"
    return label, probabilities, top_terms, attributions[:_SHAP_TOP_K], name, "transformer"


def _run_model(text: str, cfg: Settings) -> _ModelOutcome:
    try:
        from ..ai import model_trainer as train
    except ImportError as exc:
        log.warning("ML package unavailable (%s); using rule heuristics", exc)
        return None, {}, [], [], "unavailable", "unavailable"

    if getattr(cfg, "transformer_enabled", False):
        bundled = _run_bundled_transformer(text)
        if bundled is not None:
            return bundled

    model_id = (getattr(cfg, "transformer_model", "") or "").strip()
    if model_id:
        outcome = train.transformer_predict(text, cfg)
        if outcome is not None:
            label, probs, attributions = outcome
            top_terms = [token for token, weight in attributions if weight > 0][:8]
            name = f"{model_id} ({train.TRANSFORMER_ATTRIBUTION} attribution)"
            return label, probs, top_terms, attributions[:_SHAP_TOP_K], name, "transformer"

    try:
        pipeline = train.load_or_train(cfg)
        label, probs = train.predict(pipeline, text)
        weights = train.shap_values(pipeline, text, label, top_k=_SHAP_TOP_K)
        return label, probs, train.explain(pipeline, text, label), weights, train.MODEL_VERSION, "linear"
    except ImportError as exc:
        log.warning("ML classifier unavailable (%s); using rule heuristics", exc)
    except Exception:
        log.exception("ML classification failed; using rule heuristics")
    return None, {}, [], [], "unavailable", "unavailable"


def _finding(fid: str, severity: Severity, title: str, detail: str, evidence: dict[str, object]) -> Finding:
    return Finding(id=fid, module="nlp", severity=severity, title=title, detail=detail, evidence=evidence)


_SCAM_PATTERN_TITLES: dict[str, tuple[str, str, str]] = {
    "extortion": ("extortion_demand", "Money demanded under threat", "Extortion indicators"),
    "violent_threat": ("violent_threat_pattern", "Violent threat", "Threat indicators"),
    "investment_scam": ("investment_scam", "Investment scam lure", "Investment-scam indicators"),
    "callback_scam": ("callback_scam", "Tech-support / call-back scam", "Call-back scam indicators"),
}


def analyze_content(
    parsed: ParsedEmail,
    url_analysis: UrlAnalysis,
    att_analysis: AttachmentAnalysis,
    cfg: Settings,
    auth: AuthResult | None = None,
) -> NlpAnalysis:
    body = _body_text(parsed)
    text = normalize_text(parsed.subject, body)
    words = _WORD_RE.findall(text)
    analysis = NlpAnalysis(language=detect_language(text), word_count=len(words))

    urgency = _hits("urgency", text)
    threat = _hits("threat", text)
    financial = _hits("financial", text)
    violence = _hits("violence", text)
    handles = payment_handles(text)
    credential = _hits("credential", text)
    authority = _hits("authority", text)
    secrecy = _hits("secrecy", text)
    reward = _hits("reward", text)
    scarcity = _hits("scarcity", text)
    curiosity = _hits("curiosity", text)
    greeting = _hits("greeting", text[:400])
    reply_cues = _hits("reply", text)

    exclamations = text.count("!")
    exclamation_density = exclamations / max(1, len(words))
    subject_letters = [c for c in (parsed.subject or "") if c.isalpha()]
    subject_caps = (
        sum(1 for c in subject_letters if c.isupper()) / len(subject_letters) if len(subject_letters) >= 8 else 0.0
    )
    urgency_score = _clamp01(
        0.25 * len(urgency) + 0.15 * len(threat) + min(0.2, exclamation_density) + (0.1 if subject_caps > 0.5 else 0.0)
    )

    cues: list[str] = []
    if authority:
        cues.append("authority")
    if threat or violence:
        cues.append("fear")
    if scarcity or urgency:
        cues.append("scarcity")
    if secrecy:
        cues.append("secrecy")
    if reward:
        cues.append("reward")
    if curiosity:
        cues.append("curiosity")

    analysis.urgency_score = urgency_score
    analysis.urgency_phrases = urgency[:10]
    analysis.social_engineering_cues = cues
    analysis.financial_terms = financial[:15]
    analysis.payment_handles = handles[:10]
    analysis.credential_terms = credential[:15]
    analysis.threat_terms = (threat + violence)[:10]
    analysis.generic_greeting = bool(greeting)
    risky_links = any(SEVERITY_ORDER[u.risk.value] >= SEVERITY_ORDER["medium"] for u in url_analysis.urls)
    analysis.requests_reply_not_click = bool(reply_cues) and not risky_links

    bec = detect_bec_patterns(text, parsed, url_analysis, att_analysis, cfg, auth)
    analysis.bec_patterns = bec
    max_bec = max((p.confidence for p in bec), default=0.0)
    exec_conf = max((p.confidence for p in bec if p.pattern == "executive_impersonation"), default=0.0)

    label, probs, top_terms, attributions, model_name, backend = _run_model(text, cfg)
    if label is None:
        probs = _heuristic_probabilities(
            len(credential), len(financial), len(threat), len(reward), len(secrecy), len(authority),
            urgency_score, exec_conf, risky_links or any(u.suspicious_keywords for u in url_analysis.urls), len(words),
        )
        label = max(probs.items(), key=lambda item: item[1])[0]
    try:
        analysis.ml_category = ThreatCategory(label)
    except ValueError:
        analysis.ml_category = ThreatCategory.LEGITIMATE
    analysis.ml_probabilities = {k: round(float(v), 4) for k, v in probs.items()}
    analysis.ml_top_terms = top_terms
    analysis.shap_weights = [ShapWeight(token=str(token), weight=round(float(weight), 6)) for token, weight in attributions]
    analysis.ml_model = model_name
    analysis.ml_backend = backend

    non_legit = 1.0 - float(probs.get(ThreatCategory.LEGITIMATE.value, 0.0))
    analysis.score = _clamp01(0.45 * non_legit + 0.25 * urgency_score + 0.2 * max_bec + (0.1 if len(cues) >= 2 else 0.0))

    findings: list[Finding] = []
    if urgency_score >= 0.25:
        findings.append(_finding(
            "urgency_language", Severity.MEDIUM if urgency_score >= 0.5 else Severity.LOW, "Urgency pressure",
            f"The message pushes for immediate action (urgency score {urgency_score:.2f}): {', '.join(urgency[:4]) or 'tone/punctuation'}.",
            {"score": round(urgency_score, 3), "phrases": urgency[:10], "exclamations": exclamations},
        ))
    if threat:
        findings.append(_finding(
            "fear_or_threat_language", Severity.MEDIUM if len(threat) >= 2 else Severity.LOW, "Fear / threat language",
            f"Consequences are threatened to force compliance: {', '.join(threat[:4])}.",
            {"phrases": threat[:10]},
        ))
    if violence:
        findings.append(_finding(
            "violent_threat", Severity.CRITICAL, "Threat of physical harm",
            f"The message threatens violence or stalks the recipient: {', '.join(violence[:4])}. This is criminal "
            f"intimidation, not spam, and should be preserved for the police.",
            {"phrases": violence[:10]},
        ))
    if handles:
        findings.append(_finding(
            "payment_handle", Severity.MEDIUM, "Direct payment instructions",
            f"The text names where to send money: {', '.join(handles[:3])}. Genuine billing points at an invoice or a "
            f"portal; scams and extortion name a UPI ID, wallet or remittance service in the body.",
            {"handles": handles[:10]},
        ))
    cred_conf = max((p.confidence for p in bec if p.pattern == "credential_harvesting"), default=0.0)
    if credential:
        sev = Severity.HIGH if cred_conf >= 0.5 else (Severity.MEDIUM if len(credential) >= 2 else Severity.LOW)
        findings.append(_finding(
            "credential_request", sev, "Credential / identity data requested",
            f"The text asks for or refers to secrets and identity data: {', '.join(credential[:5])}.",
            {"terms": credential[:15], "harvest_confidence": round(cred_conf, 3)},
        ))
    if len(financial) >= 2:
        pressure = bool(reward or secrecy or urgency_score >= 0.5)
        findings.append(_finding(
            "financial_lure", Severity.MEDIUM if (len(financial) >= 3 and pressure) else Severity.LOW, "Financial lure",
            f"Money-related language {', '.join(financial[:5])}" + (" combined with pressure cues." if pressure else "."),
            {"terms": financial[:15], "pressure": pressure},
        ))
    if greeting:
        findings.append(_finding(
            "generic_greeting", Severity.LOW, "Generic greeting",
            f"The message opens with '{greeting[0]}' instead of addressing the recipient by name.",
            {"greeting": greeting[0]},
        ))
    if secrecy:
        findings.append(_finding(
            "secrecy_cue", Severity.MEDIUM, "Secrecy requested",
            f"The sender asks for discretion ({', '.join(secrecy[:3])}), a hallmark of BEC and advance-fee fraud.",
            {"phrases": secrecy[:10]},
        ))
    if authority:
        findings.append(_finding(
            "authority_cue", Severity.LOW, "Authority invoked",
            f"The message leans on an authority figure or institution: {', '.join(authority[:4])}.",
            {"phrases": authority[:10]},
        ))
    if len(reward) >= 2:
        findings.append(_finding(
            "reward_lure", Severity.MEDIUM if financial else Severity.LOW, "Reward / prize lure",
            f"Promises a reward or win: {', '.join(reward[:4])}.",
            {"phrases": reward[:10]},
        ))
    for pattern in bec:
        sev = Severity.CRITICAL if pattern.confidence >= 0.75 else (Severity.HIGH if pattern.confidence >= 0.5 else Severity.MEDIUM)
        pretty = pattern.pattern.replace("_", " ")
        if pattern.pattern in _SCAM_PATTERN_TITLES:
            fid, title, lead = _SCAM_PATTERN_TITLES[pattern.pattern]
            if pattern.pattern in ("extortion", "violent_threat"):
                sev = Severity.CRITICAL if pattern.confidence >= 0.5 else Severity.HIGH
        else:
            fid, title, lead = f"bec_{pattern.pattern}", f"BEC pattern: {pretty}", f"{pretty.capitalize()} indicators"
        findings.append(_finding(
            fid, sev, title,
            f"{lead} with confidence {pattern.confidence:.2f}: {', '.join(pattern.evidence[:4])}.",
            {"pattern": pattern.pattern, "confidence": round(pattern.confidence, 3), "evidence": pattern.evidence},
        ))
    if analysis.requests_reply_not_click:
        findings.append(_finding(
            "reply_not_click", Severity.LOW, "Asks for a reply rather than a click",
            f"The sender steers the conversation to email replies ({reply_cues[0]}), typical of BEC and advance-fee scams.",
            {"phrases": reply_cues[:5]},
        ))
    attribution_method = _ATTRIBUTION_METHOD.get(backend, "none")
    shap_evidence = [{"token": w.token, "weight": round(w.weight, 4)} for w in analysis.shap_weights[:8]]
    shap_summary = ", ".join(f"{w.token} {w.weight:+.3f}" for w in analysis.shap_weights[:5])
    findings.append(_finding(
        "ml_classification", Severity.INFO, "ML classification",
        f"Classifier {model_name} favours {analysis.ml_category.value} "
        f"(p={analysis.ml_probabilities.get(analysis.ml_category.value, 0.0):.2f}); top terms: {', '.join(top_terms[:5]) or 'n/a'}. "
        f"Token weights ({attribution_method}): {shap_summary or 'n/a'}.",
        {
            "model": model_name, "backend": backend, "attribution": attribution_method,
            "category": analysis.ml_category.value, "probabilities": analysis.ml_probabilities,
            "top_terms": top_terms, "shap_weights": shap_evidence,
        },
    ))
    analysis.findings = findings
    return analysis
