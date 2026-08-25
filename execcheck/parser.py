"""Low-level parser for the executable_measurements_v2 table."""

import sqlite3

from .combine import _connect_read_only


def _tri_state(value):
    """Preserve SQL NULL instead of converting it to False."""
    return None if value is None else bool(value)


def parse_exec_policy(db_path: str) -> list[dict]:
    """Parse the ExecPolicy database and return raw measurement rows."""

    with _connect_read_only(db_path) as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("""
                SELECT
                    cdhash,
                    file_identifier,
                    responsible_file_identifier,
                    team_identifier,
                    signing_identifier,
                    main_executable_hash,
                    is_signed,
                    is_valid,
                    is_quarantined,
                    timestamp
                FROM executable_measurements_v2
            """)
            rows = cursor.fetchall()
        except sqlite3.OperationalError as error:
            print(f"Error reading table: {error}")
            return []

    results = []
    for row in rows:
        (
            cdhash,
            file_id,
            resp_file_id,
            team_id,
            signing_id,
            main_hash,
            is_signed,
            is_valid,
            is_quarantined,
            ts
        ) = row
        results.append({
            "cdhash": (cdhash or "").strip().lower(),
            "file_identifier": (file_id or "").strip().lower(),
            "responsible_file_identifier": resp_file_id,
            "team_identifier": team_id,
            "signing_identifier": signing_id,
            # Historical aliases retained for existing consumers.
            "team_id": team_id,
            "signing_id": signing_id,
            "main_executable_hash": main_hash,
            "is_signed": _tri_state(is_signed),
            "is_valid": _tri_state(is_valid),
            "is_quarantined": _tri_state(is_quarantined),
            "timestamp": ts,
        })
    return results
