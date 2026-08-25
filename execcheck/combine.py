"""Source-aware correlation of ExecPolicy tables.

The combined representation deliberately keeps raw source rows.  Canonical
fields are conveniences for analysis, not replacements for source evidence.
"""

from __future__ import annotations

import sqlite3
import shutil
from collections import defaultdict
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any


SOURCE_TABLES = (
    "executable_measurements_v2",
    "policy_scan_cache",
    "provenance_tracking",
)

FIELD_ALIASES: dict[str, dict[str, tuple[str, ...]]] = {
    "cdhash": {table: ("cdhash",) for table in SOURCE_TABLES},
    "file_identifier": {table: ("file_identifier",) for table in SOURCE_TABLES},
    "bundle_identifier": {
        "executable_measurements_v2": ("bundle_identifier", "bundle_id"),
        "policy_scan_cache": ("bundle_id", "bundle_identifier"),
        "provenance_tracking": ("bundle_id", "bundle_identifier"),
    },
    "team_identifier": {table: ("team_identifier",) for table in SOURCE_TABLES},
    "signing_identifier": {table: ("signing_identifier",) for table in SOURCE_TABLES},
    "main_executable_hash": {
        "executable_measurements_v2": ("main_executable_hash",),
    },
    "is_signed": {"executable_measurements_v2": ("is_signed",)},
    "is_valid": {"executable_measurements_v2": ("is_valid",)},
    "is_quarantined": {"executable_measurements_v2": ("is_quarantined",)},
    "policy_match": {"policy_scan_cache": ("policy_match",)},
    "malware_result": {"policy_scan_cache": ("malware_result",)},
    "scan_flags": {"policy_scan_cache": ("flags",)},
}

TRI_STATE_FIELDS = {"is_signed", "is_valid", "is_quarantined"}


@contextmanager
def _connect_read_only(db_path: str):
    """Analyze a private snapshot so SQLite never writes beside evidence.

    SQLite may need shared-memory bookkeeping even for a read-only WAL-mode
    database.  Copying the database and any supplied WAL/SHM companions avoids
    modifying timestamps or creating sidecars next to the source artifact while
    still including uncheckpointed WAL evidence.
    """
    source = Path(db_path).expanduser().resolve()
    if not source.is_file():
        raise FileNotFoundError(f"ExecPolicy database not found: {source}")

    with TemporaryDirectory(prefix="execcheck-snapshot-") as temp_directory:
        snapshot = Path(temp_directory) / source.name
        shutil.copy2(source, snapshot)
        for suffix in ("-wal", "-shm"):
            companion = Path(f"{source}{suffix}")
            if companion.is_file():
                shutil.copy2(companion, Path(f"{snapshot}{suffix}"))

        uri = f"{snapshot.as_uri()}?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only = ON")
        try:
            yield conn
        finally:
            conn.close()


def _load_table(conn: sqlite3.Connection, table: str) -> list[dict[str, Any]]:
    """Load a source table, returning an empty list only when it is absent."""
    exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
    ).fetchone()
    if not exists:
        return []
    return [dict(row) for row in conn.execute(f'SELECT * FROM "{table}"')]


def _identity(value: Any) -> str:
    return str(value).strip().lower() if value is not None else ""


def _row_identity(row: dict[str, Any]) -> tuple[str, str] | None:
    cdhash = _identity(row.get("cdhash"))
    if cdhash:
        return "cdhash", cdhash
    file_identifier = _identity(row.get("file_identifier"))
    if file_identifier:
        return "file_identifier", file_identifier
    return None


def _value_for(row: dict[str, Any], aliases: tuple[str, ...]) -> tuple[bool, Any]:
    for alias in aliases:
        if alias in row:
            return True, row[alias]
    return False, None


def _normalise_value(field: str, value: Any) -> Any:
    if field == "cdhash" and value is not None:
        return _identity(value)
    if field in TRI_STATE_FIELDS and value is not None:
        return bool(value)
    return value


def _value_key(value: Any) -> tuple[str, str]:
    """Keep type-distinct SQLite observations distinct during conflict checks."""
    return type(value).__name__, repr(value)


def _canonical_field(
    field: str,
    records: dict[str, list[dict[str, Any]]],
) -> tuple[Any, dict[str, Any], dict[str, Any] | None]:
    observations: list[dict[str, Any]] = []
    null_sources: set[str] = set()

    for table, aliases in FIELD_ALIASES[field].items():
        for row in records[table]:
            present, raw_value = _value_for(row, aliases)
            if not present:
                continue
            value = _normalise_value(field, raw_value)
            if value is None or value == "":
                null_sources.add(table)
            else:
                observations.append({"value": value, "source": table})

    unique_values: list[Any] = []
    seen_values: set[tuple[str, str]] = set()
    for observation in observations:
        key = _value_key(observation["value"])
        if key not in seen_values:
            seen_values.add(key)
            unique_values.append(observation["value"])

    if not unique_values:
        state = "observed_null" if null_sources else "unknown"
        provenance = {
            "value": None,
            "state": state,
            "sources": [],
            "observed_null_sources": sorted(null_sources),
        }
        return None, provenance, None

    def sources_for(value: Any) -> list[str]:
        key = _value_key(value)
        return sorted(
            {item["source"] for item in observations if _value_key(item["value"]) == key}
        )

    if len(unique_values) > 1:
        conflict = {
            "values": [
                {"value": value, "sources": sources_for(value)}
                for value in unique_values
            ]
        }
        provenance = {
            "value": None,
            "state": "conflicting",
            "sources": sorted({item["source"] for item in observations}),
            "observed_null_sources": sorted(null_sources),
        }
        return None, provenance, conflict

    value = unique_values[0]
    provenance = {
        "value": value,
        "state": "observed",
        "sources": sources_for(value),
        "observed_null_sources": sorted(null_sources),
    }
    return value, provenance, None


def _group_source_rows(
    rows_by_table: dict[str, list[dict[str, Any]]],
) -> dict[tuple[str, str], dict[str, list[dict[str, Any]]]]:
    """Group every source row exactly once, preferring CDHash identity."""
    groups: dict[tuple[str, str], dict[str, list[dict[str, Any]]]] = {}
    deferred: list[tuple[str, dict[str, Any]]] = []

    def group_for(key: tuple[str, str]) -> dict[str, list[dict[str, Any]]]:
        return groups.setdefault(key, {table: [] for table in SOURCE_TABLES})

    for table, rows in rows_by_table.items():
        for row in rows:
            identity = _row_identity(row)
            if identity and identity[0] == "cdhash":
                group_for(identity)[table].append(row)
            else:
                deferred.append((table, row))

    file_to_cdhashes: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for key, records in groups.items():
        for rows in records.values():
            for row in rows:
                file_identifier = _identity(row.get("file_identifier"))
                if file_identifier:
                    file_to_cdhashes[file_identifier].add(key)

    orphan_number = 0
    for table, row in deferred:
        file_identifier = _identity(row.get("file_identifier"))
        candidates = file_to_cdhashes.get(file_identifier, set())
        if len(candidates) == 1:
            key = next(iter(candidates))
        elif file_identifier:
            key = ("file_identifier", file_identifier)
        else:
            orphan_number += 1
            key = ("orphan", str(orphan_number))
        group_for(key)[table].append(row)

    return groups


def _origin_context(provenance_rows: list[dict[str, Any]]) -> tuple[list[str], list[dict[str, Any]]]:
    observations = [
        {
            "url": row.get("url"),
            "timestamp": row.get("timestamp"),
            "flags": row.get("flags"),
            "pk": row.get("pk"),
            "link_pk": row.get("link_pk"),
        }
        for row in provenance_rows
    ]
    observations.sort(key=lambda item: (item["timestamp"] is None, item["timestamp"] or 0, item["pk"] or 0))
    urls: list[str] = []
    for observation in observations:
        url = observation["url"]
        if url and url not in urls:
            urls.append(url)
    return urls, observations


def _build_combined_row(
    key: tuple[str, str],
    records: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    source_tables = [table for table in SOURCE_TABLES if records[table]]
    field_provenance: dict[str, Any] = {}
    field_conflicts: dict[str, Any] = {}
    row: dict[str, Any] = {}

    for field in FIELD_ALIASES:
        value, provenance, conflict = _canonical_field(field, records)
        row[field] = value
        field_provenance[field] = provenance
        if conflict:
            field_conflicts[field] = conflict

    origin_urls, origin_observations = _origin_context(records["provenance_tracking"])
    scan_timestamps = [r.get("timestamp") for r in records["policy_scan_cache"]]
    provenance_timestamps = [r.get("timestamp") for r in records["provenance_tracking"]]
    exec_timestamps = [r.get("timestamp") for r in records["executable_measurements_v2"]]

    # Backward-compatible singular fields remain deterministic; plural/raw fields
    # retain all observations and should be preferred by forensic consumers.
    row.update(
        {
            "bundle_id": row["bundle_identifier"],
            "origin_url": origin_urls[0] if origin_urls else None,
            "origin_urls": origin_urls,
            "origin_observations": origin_observations,
            "timestamp": exec_timestamps[0] if len(exec_timestamps) == 1 else None,
            "scan_timestamp": scan_timestamps[0] if len(scan_timestamps) == 1 else None,
            "scan_timestamps": scan_timestamps,
            "provenance_timestamp": provenance_timestamps[0] if len(provenance_timestamps) == 1 else None,
            "provenance_timestamps": provenance_timestamps,
            "revocation_check_time": (
                records["policy_scan_cache"][0].get("revocation_check_time")
                if len(records["policy_scan_cache"]) == 1
                else None
            ),
            "volume_uuid": (
                records["policy_scan_cache"][0].get("volume_uuid")
                if len(records["policy_scan_cache"]) == 1
                else None
            ),
            "provenance_flags": (
                records["provenance_tracking"][0].get("flags")
                if len(records["provenance_tracking"]) == 1
                else None
            ),
        }
    )

    confidence = "high" if key[0] == "cdhash" else "low"
    if field_conflicts and confidence == "high":
        confidence = "medium"
    uncertainty_reasons = []
    if not records["executable_measurements_v2"]:
        uncertainty_reasons.append("no executable_measurements_v2 observation")
    if field_conflicts:
        uncertainty_reasons.append("conflicting canonical field observations")
    if key[0] != "cdhash":
        uncertainty_reasons.append(f"correlated by fallback {key[0]}")

    row.update(
        {
            "source_tables": source_tables,
            "source_counts": {table: len(records[table]) for table in SOURCE_TABLES},
            "source_records": records,
            "field_provenance": field_provenance,
            "field_conflicts": field_conflicts,
            "correlation": {
                "key_type": key[0],
                "key": key[1],
                "confidence": confidence,
                "sources": source_tables,
            },
            "correlation_type": "strong" if confidence == "high" else "weak",
            "correlated_from": key[1],
            "uncertainty_reasons": uncertainty_reasons,
            "evidence_quality": confidence,
            "completeness": {
                "source_tables_present": len(source_tables),
                "source_tables_expected": len(SOURCE_TABLES),
            },
        }
    )
    return row


def combine_exec_policy_tables(db_path: str) -> list[dict[str, Any]]:
    """Return source-aware, non-duplicated records from an ExecPolicy database."""
    with _connect_read_only(db_path) as conn:
        rows_by_table = {table: _load_table(conn, table) for table in SOURCE_TABLES}

    groups = _group_source_rows(rows_by_table)
    return [_build_combined_row(key, groups[key]) for key in sorted(groups)]
