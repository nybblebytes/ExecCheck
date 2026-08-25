"""Utility helpers for working with timestamps."""

from datetime import UTC, datetime

def to_iso8601(ts: int | float | None) -> str | None:
    """Convert a UNIX timestamp to an ISO-8601 string."""

    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(ts, UTC).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, TypeError, ValueError):
        return f"Invalid (raw={ts!r})"
