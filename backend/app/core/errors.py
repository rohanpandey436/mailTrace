"""Errors the domain layer raises."""
from __future__ import annotations


class NotFound(LookupError):
    """A case, campaign or alert that does not exist (HTTP 404 at the API)."""
