"""
Analyst decisions on a case (Stage 6).

What a decision does, and - more importantly - what it does not do.

Recording a decision writes the analyst's choice and its author into the
hash-linked chain of custody, gives the case a status the case list can
filter and display, and hands back the indicators (IOCs) to feed to whatever
actually enforces: a mail gateway, a firewall, a SIEM, or the outbound
webhooks in ``app/api/alerts.py``.

It does NOT contact Microsoft 365, Google Workspace or any mail transfer
agent.  Nothing is moved to a quarantine folder, no sender is added to a
block list, no message is recalled or deleted.  MailTrace is a forensic
analysis tool with no mailbox credentials and no write access to mail flow,
and a button that silently did nothing while claiming otherwise would be
worse than no button at all.  ``CaseDecision.enforced`` is therefore always
False, and the dashboard wording says "record decision", not "quarantine".
"""
from __future__ import annotations

from typing import Literal

from ..database.case_manager import Store
from ..schemas import AnalysisResult, CaseDecision, CaseStatus
from .errors import NotFound

DecisionName = Literal["quarantine", "block"]

#: decision -> (the case status it sets, the custody action it records)
DECISIONS: dict[DecisionName, tuple[CaseStatus, str]] = {
    "quarantine": ("quarantined", "quarantine_decision"),
    "block": ("blocked", "block_decision"),
}
_DECISION_ACTIONS = {action for _, action in DECISIONS.values()}

# The correlation engine and the attribution engine label the same fact
# differently ("ip:" vs "origin_ip:", "domain:" vs "sender_domain:"), so a plain
# string dedupe across the two would list every shared fact twice and inflate
# the count an analyst is shown.  The prefix is normalised before comparing.
_INDICATOR_ALIASES: dict[str, str] = {
    "origin_ip": "ip",
    "sender_domain": "domain",
    "reply_to": "replyto",
    "url_host": "urlhost",
    "attachment_sha256": "file",
    "sender": "sender",
}


def load_case(store: Store, email_id: str) -> AnalysisResult:
    """The stored analysis for a case, or ``NotFound``."""
    result = store.get_analysis(email_id)
    if result is None:
        raise NotFound(f"email {email_id} not found")
    return result


def _indicator_key(indicator: str) -> str:
    prefix, separator, value = indicator.partition(":")
    if not separator:
        return indicator.strip().lower()
    normalised = prefix.strip().lower()
    return f"{_INDICATOR_ALIASES.get(normalised, normalised)}:{value.strip().lower()}"


def indicators(result: AnalysisResult) -> list[str]:
    """IOCs worth handing to the system that does enforce, newest evidence first.

    Deduplicated by the fact each one states rather than by its exact
    spelling, so the same IP appearing as both ``ip:`` and ``origin_ip:`` is
    listed once.
    """
    seen: set[str] = set()
    unique: list[str] = []
    for indicator in [*result.intel.indicators, *result.attribution.indicators]:
        key = _indicator_key(indicator)
        if key in seen:
            continue
        seen.add(key)
        unique.append(indicator)
    return unique


def current(store: Store, result: AnalysisResult) -> CaseDecision:
    """The decision recorded against a case, with its ledger history."""
    chain = store.get_custody(result.id)
    return CaseDecision(
        email_id=result.id,
        status=store.get_case_status(result.id),
        enforced=False,
        indicators=indicators(result),
        history=[event for event in chain.events if event.action in _DECISION_ACTIONS],
    )


def record(store: Store, email_id: str, decision: DecisionName, actor: str) -> CaseDecision:
    """Record ``decision`` for a case and return the new decision state."""
    status, action = DECISIONS[decision]
    result = load_case(store, email_id)
    previous = store.get_case_status(email_id)
    if not store.set_case_status(email_id, status, actor):
        raise NotFound(f"email {email_id} not found")
    store.record_custody(
        email_id,
        actor,
        action,
        {
            "decision": decision,
            "status": status,
            "previous_status": previous,
            "category": result.verdict.category.value,
            "risk_score": result.verdict.risk_score,
            "indicator_count": len(indicators(result)),
            # Recorded in the ledger itself so a reader of the chain, years
            # later, cannot mistake this for gateway enforcement.
            "enforced": False,
            "note": "analyst decision recorded in MailTrace; no mail system was contacted",
        },
        result.email.raw_sha256,
    )
    return current(store, result)
