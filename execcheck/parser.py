"""Low-level parser for the executable_measurements_v2 table."""

import sqlite3


def parse_exec_policy(db_path: str) -> list[dict]:
    """Parse the ExecPolicy database and return raw measurement rows."""

    conn = sqlite3.connect(db_path)
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
    except sqlite3.OperationalError as e:
        print(f"Error reading table: {e}")
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
            "team_id": team_id,
            "signing_id": signing_id,
            "main_executable_hash": main_hash,
            "is_signed": bool(is_signed),
            "is_valid": bool(is_valid),
            "is_quarantined": bool(is_quarantined),
            "timestamp": ts,
        })
    conn.close()
    return results
