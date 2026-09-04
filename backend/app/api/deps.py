"""
Shared FastAPI dependencies.

The application factory places the live ``Settings`` and ``Store`` on
``app.state``; these helpers hand them to path operations so routers never
touch module-level singletons (tests inject their own configuration through
``create_app(settings)``).  PII-mask resolution and the two small helpers that
mask list rows and alerts also live here so every router applies exactly the
same privacy policy at the API boundary.
"""
from __future__ import annotations

from typing import Optional

from fastapi import HTTPException, Query, Request

from ..config import Settings
from ..db import Store
from ..engine.privacy import mask_email, mask_text
from ..schemas import Alert, CaseSummary

# Actor recorded in the chain of custody when a request carries no identity.
DEFAULT_ACTOR = "analyst"


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_store(request: Request) -> Store:
    store = getattr(request.app.state, "store", None)
    if store is None:
        raise HTTPException(status_code=503, detail="store not initialised: application startup has not completed")
    return store


def mask_param(
    request: Request,
    mask: Optional[bool] = Query(None, description="Mask PII in the response; defaults to MAILTRACE_PII_MASK_DEFAULT"),
) -> bool:
    if mask is None:
        return bool(request.app.state.settings.pii_mask_default)
    return mask


def mask_summary(summary: CaseSummary) -> CaseSummary:
    """Case-list row with the sender address and any PII in the subject masked."""
    return summary.model_copy(
        update={
            "subject": mask_text(summary.subject),
            "sender": mask_email(summary.sender) if summary.sender else "",
        }
    )


def mask_alert(alert: Alert) -> Alert:
    """Alert with the sender address and any PII in subject/message masked."""
    return alert.model_copy(
        update={
            "subject": mask_text(alert.subject),
            "sender": mask_email(alert.sender) if alert.sender else "",
            "message": mask_text(alert.message),
        }
    )
