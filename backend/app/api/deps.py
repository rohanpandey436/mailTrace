"""Shared FastAPI dependencies."""
from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Query, Request

from ..config import Settings
from ..database.case_manager import Store
from ..schemas import Alert, CaseSummary
from ..utils.pii_masker import mask_email, mask_text

# Actor recorded in the chain of custody when a request carries no identity.
DEFAULT_ACTOR = "analyst"


def get_settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def get_store(request: Request) -> Store:
    store: Store | None = getattr(request.app.state, "store", None)
    if store is None:
        raise HTTPException(status_code=503, detail="store not initialised: application startup has not completed")
    return store


def mask_param(
    request: Request,
    mask: Annotated[bool | None, Query(description="Mask PII in the response; defaults to MAILTRACE_PII_MASK_DEFAULT")] = None,
) -> bool:
    if mask is None:
        return bool(request.app.state.settings.pii_mask_default)
    return mask


SettingsDep = Annotated[Settings, Depends(get_settings)]
StoreDep = Annotated[Store, Depends(get_store)]
MaskDep = Annotated[bool, Depends(mask_param)]
ActorParam = Annotated[str, Query(min_length=1, max_length=64, description="Recorded in the chain of custody")]


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
