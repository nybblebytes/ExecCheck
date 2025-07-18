"""Utility helpers for working with timestamps."""

from datetime import datetime

def to_iso8601(ts: int | float | None) -> str:
    """Convert a UNIX timestamp to an ISO-8601 string."""

    try:
        return datetime.utcfromtimestamp(ts).isoformat() + "Z"
    except Exception:
        return "Invalid"
