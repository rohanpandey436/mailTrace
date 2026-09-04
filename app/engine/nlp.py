"""
Content analysis: lexicon features, social-engineering cues, BEC pattern
detection and the ML classifier (dual validation partner of the rule engine).

Approach
--------
1. The subject and body are normalised (NFKC, lower-case, collapsed
   whitespace) and scanned with phrase-aware, word-boundary lexicons for
   urgency, threat/fear, financial, credential, authority, secrecy, reward,
   scarcity and curiosity language.
2. Four BEC patterns are scored from combinations of those hits plus
   structural signals (links, attachments, sender/Reply-To relationship,
   display name): payment diversion, fake invoice, credential harvesting and
   executive impersonation.  Evidence lists quote the phrases actually found.
3. The classifier (``app.ml.train``) supplies a category, class probabilities
   and signed token-level attributions.  Two backends, picked in this order:

   * ``transformer`` - a DistilRoBERTa (or other) sequence-classification model,
     used only when ``Settings.transformer_model`` is set.  Its attributions are
     occlusion deltas, not Shapley values, so the method is named in
     ``ml_model`` and in the finding evidence.  Off by default: `transformers`
     and `torch` are not in requirements.txt (see ``app/ml/train.py``).
   * ``linear`` - the bundled TF-IDF + logistic-regression model, whose
     attributions are *exact* SHAP values ``phi_i = w_i * (x_i - E[x_i])``.

   When scikit-learn is unavailable the module degrades to a documented
   heuristic probability estimate, ``ml_backend="unavailable"`` and no weights.
4. ``score`` blends the model's non-legitimate mass, urgency, the strongest
   BEC pattern and cue diversity into one 0-1 content score.
"""
from __future__ import annotations

import logging
import re
import unicodedata
from typing import Optional

from ..config import Settings
from ..schemas import (
    SEVERITY_ORDER,
    AttachmentAnalysis,
    BecPattern,
    Finding,
    NlpAnalysis,
    ParsedEmail,
    Severity,
    ShapWeight,
    ThreatCategory,
    UrlAnalysis,
)
from .knowledge import EXEC_TITLES, FREEMAIL_DOMAINS
from .urls import registrable_domain

log = logging.getLogger("mailtrace.nlp")

# --------------------------------------------------------------------------- #
# Lexicons (lower-case; phrases allowed; matched on word boundaries)
# --------------------------------------------------------------------------- #
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
)
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
# BEC sub-lexicons
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
_PAYMENT_DIVERSION_EXPLICIT = (
    "bank details have changed", "our bank details", "new account below", "updated bank details",
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


def _compile(lexicon: tuple[str, ...]) -> re.Pattern:
    phrases = sorted({p.lower() for p in lexicon}, key=len, reverse=True)
    # re.escape leaves spaces alone (3.7+) but older versions escaped them; a
    # phrase may span a line break in the normalised text, so allow any run of
    # whitespace between words.
    alternatives = "|".join(re.escape(p).replace(r"\ ", " ").replace(" ", r"\s+") for p in phrases)
    return re.compile(rf"(?<![\w-])(?:{alternatives})(?![\w-])", re.IGNORECASE)


_PATTERNS: dict[str, re.Pattern] = {
    name: _compile(lexicon)
    for name, lexicon in {
        "urgency": URGENCY, "threat": THREAT, "financial": FINANCIAL, "credential": CREDENTIAL,
        "authority": AUTHORITY, "secrecy": SECRECY, "reward": REWARD, "scarcity": SCARCITY,
        "curiosity": CURIOSITY, "greeting": GENERIC_GREETINGS, "reply": REPLY_CUES,
        "bank_change": _BANK_CHANGE_TERMS, "change": _CHANGE_TERMS, "payment_action": _PAYMENT_ACTION_TERMS,
        "payment_explicit": _PAYMENT_DIVERSION_EXPLICIT, "invoice": _INVOICE_TERMS, "due": _DUE_TERMS,
        "cta": _CTA_TERMS, "cred_explicit": _CRED_EXPLICIT, "exec": _EXEC_PHRASES,
    }.items()
}


# --------------------------------------------------------------------------- #
# Text helpers
# --------------------------------------------------------------------------- #
def normalize_text(subject: str, body: str) -> str:
    """NFKC-normalised, lower-case, whitespace-collapsed subject + body."""
    combined = f"{subject or ''}\n{body or ''}"
    combined = unicodedata.normalize("NFKC", combined)
    combined = combined.replace("’", "'").replace("‘", "'").replace("“", '"').replace("”", '"')
    combined = combined.replace("–", "-").replace("—", "-")
    combined = re.sub(r"[ \t\r\f\v\xa0]+", " ", combined)
    combined = re.sub(r" *\n *", "\n", combined)
    combined = re.sub(r"\n{2,}", "\n", combined)
    return combined.strip().lower()[:200000]


def _hits(name: str, text: str) -> list[str]:
    """Unique lexicon phrases present in ``text``, in order of appearance."""
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


# --------------------------------------------------------------------------- #
# BEC patterns
# --------------------------------------------------------------------------- #
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
    risky_urls = [u for u in url_analysis.urls if SEVERITY_ORDER[u.risk.value] >= SEVERITY_ORDER["medium"]]
    high_urls = [u for u in url_analysis.urls if SEVERITY_ORDER[u.risk.value] >= SEVERITY_ORDER["high"]]
    keyword_urls = [u for u in url_analysis.urls if u.suspicious_keywords]
    risky_atts = [a for a in att_analysis.attachments if SEVERITY_ORDER[a.risk.value] >= SEVERITY_ORDER["medium"]]
    high_atts = [a for a in att_analysis.attachments if SEVERITY_ORDER[a.risk.value] >= SEVERITY_ORDER["high"]]

    # 1. Payment diversion -----------------------------------------------
    bank = _hits("bank_change", text)
    change = _hits("change", text)
    explicit_pay = _hits("payment_explicit", text)
    action = _hits("payment_action", text)
    conf = 0.0
    evidence: list[str] = []
    # All three legs are required: the message must name banking details, say
    # they are new/changed, AND ask for a payment to be made.  Without the
    # payment leg this is a credential-phishing pattern ("confirm your account
    # number", "update your details"), not a diversion of funds.
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

    # 2. Fake invoice ----------------------------------------------------
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

    # 3. Credential harvesting -------------------------------------------
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
    if conf >= 0.35:
        patterns.append(BecPattern(pattern="credential_harvesting", confidence=_clamp01(conf), evidence=_dedupe(evidence)))

    # 4. Executive impersonation -----------------------------------------
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


# --------------------------------------------------------------------------- #
# ML
# --------------------------------------------------------------------------- #
def _heuristic_probabilities(
    cred: int, fin: int, threat: int, reward: int, secrecy: int, authority: int, urgency: float,
    exec_conf: float, link_signal: bool, total_words: int,
) -> dict[str, float]:
    """Rules-only stand-in for the classifier when scikit-learn is missing:
    each class accumulates weight from its characteristic cues, 'Legitimate'
    gets a fixed prior that dominates when few cues fire, and the weights are
    normalised to sum to one."""
    weights = {
        "Phishing": 1.0 * cred + (2.0 if link_signal else 0.0) + 0.5 * threat,
        "Fraud-Related": 1.0 * fin + 0.7 * reward + 0.5 * secrecy,
        "Impersonated": 3.0 * exec_conf + 0.5 * authority,
        "Suspicious": 0.5 + 2.0 * urgency,
        "Legitimate": 3.0 if total_words else 1.0,
    }
    total = sum(weights.values()) or 1.0
    return {label: round(value / total, 4) for label, value in weights.items()}


#: How many signed token attributions are carried on the report.
_SHAP_TOP_K = 12
#: What produced ``NlpAnalysis.shap_weights`` for each backend. The transformer
#: string mirrors ``train.TRANSFORMER_ATTRIBUTION``: those values are honest
#: leave-one-token-out deltas, not Shapley values.
_ATTRIBUTION_METHOD = {"linear": "exact-shap-linear", "transformer": "occlusion", "unavailable": "none"}

_ModelOutcome = tuple[Optional[str], dict[str, float], list[str], list[tuple[str, float]], str, str]


def _run_model(text: str, cfg: Settings) -> _ModelOutcome:
    """(label, probabilities, top terms, token attributions, model name, backend).

    The optional transformer is tried first and falls back silently; the linear
    model is the default.  ``label`` is None only when neither backend ran, and
    the caller then uses the rule heuristic.
    """
    try:
        from ..ml import train
    except ImportError as exc:  # pragma: no cover - the package ships with the app
        log.warning("ML package unavailable (%s); using rule heuristics", exc)
        return None, {}, [], [], "unavailable", "unavailable"

    model_id = (getattr(cfg, "transformer_model", "") or "").strip()
    if model_id:
        # Never fatal: transformer_predict returns None on any failure (packages
        # absent, download blocked, OOM) so analysis continues on the linear model.
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
    except Exception:  # noqa: BLE001 - model failure must never abort analysis
        log.exception("ML classification failed; using rule heuristics")
    return None, {}, [], [], "unavailable", "unavailable"


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def _finding(fid: str, severity: Severity, title: str, detail: str, evidence: dict) -> Finding:
    return Finding(id=fid, module="nlp", severity=severity, title=title, detail=detail, evidence=evidence)


def analyze_content(
    parsed: ParsedEmail, url_analysis: UrlAnalysis, att_analysis: AttachmentAnalysis, cfg: Settings
) -> NlpAnalysis:
    body = _body_text(parsed)
    text = normalize_text(parsed.subject, body)
    words = _WORD_RE.findall(text)
    analysis = NlpAnalysis(language=detect_language(text), word_count=len(words))

    urgency = _hits("urgency", text)
    threat = _hits("threat", text)
    financial = _hits("financial", text)
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
    if threat:
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
    analysis.credential_terms = credential[:15]
    analysis.threat_terms = threat[:10]
    analysis.generic_greeting = bool(greeting)
    risky_links = any(SEVERITY_ORDER[u.risk.value] >= SEVERITY_ORDER["medium"] for u in url_analysis.urls)
    analysis.requests_reply_not_click = bool(reply_cues) and not risky_links

    bec = detect_bec_patterns(text, parsed, url_analysis, att_analysis, cfg)
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
        findings.append(_finding(
            f"bec_{pattern.pattern}", sev, f"BEC pattern: {pretty}",
            f"{pretty.capitalize()} indicators with confidence {pattern.confidence:.2f}: {', '.join(pattern.evidence[:4])}.",
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
