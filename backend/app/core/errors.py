"""
Errors the domain layer raises.

The analysis engine and the case services know nothing about HTTP.  They
raise these, and ``app/main.py`` translates them into the API's uniform
``{"error": ...}`` responses.
"""
from __future__ import annotations


class NotFound(LookupError):
    """A case, campaign or alert that does not exist (HTTP 404 at the API)."""
