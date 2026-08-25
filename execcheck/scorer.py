"""Forensic-safe risk scoring and transparent allowlist context."""

from __future__ import annotations

from fnmatch import fnmatchcase
from typing import Any


def _normalise(value: Any) -> str:
    return str(value).strip().lower()


def annotate_allowlist(entry: dict, config) -> list[dict[str, str]]:
    """Record allowlist matches without removing or rewriting evidence."""
    matches: list[dict[str, str]] = []
    whitelist = config.whitelist

    hashes = {
        _normalise(value)
        for value in (entry.get("cdhash"), entry.get("main_executable_hash"))
        if value
    }
    for configured in whitelist.hashes:
        if _normalise(configured) in hashes:
            matches.append({"type": "hash", "value": configured})

    team_identifier = entry.get("team_identifier")
    for configured in whitelist.team_ids:
        if team_identifier and _normalise(configured) == _normalise(team_identifier):
            matches.append({"type": "team_id", "value": configured})

    paths = [
        value
        for value in [entry.get("file_identifier"), *(entry.get("origin_urls") or [])]
        if value
    ]
    for configured in whitelist.paths:
        if any(fnmatchcase(str(path), configured) for path in paths):
            matches.append({"type": "path", "value": configured})

    entry["allowlist_matches"] = matches
    return matches


def _observed_team_id_absence(entry: dict) -> bool:
    provenance = entry.get("field_provenance", {}).get("team_identifier", {})
    return (
        entry.get("team_identifier") is None
        and provenance.get("state") == "observed_null"
        and bool(provenance.get("observed_null_sources"))
    )


def _suppressed_rules(entry: dict) -> set[str]:
    match_types = {match.get("type") for match in entry.get("allowlist_matches", [])}
    suppressed = set()
    if match_types & {"hash", "path"}:
        suppressed.update({"unsigned", "missing_team_id", "custom_flag_mask"})
    if "team_id" in match_types:
        suppressed.update({"missing_team_id", "custom_flag_mask"})
    return suppressed


def score_entry(entry: dict, config) -> tuple[int, list[str]]:
    """Calculate suspicious-evidence score; unknown values never score."""
    score = 0
    trace: list[str] = []
    scoring = config.scoring

    if "allowlist_matches" not in entry:
        annotate_allowlist(entry, config)
    suppressed = _suppressed_rules(entry)
    entry["allowlist_suppressed_rules"] = sorted(suppressed)

    # Only an explicitly observed False is evidence of an unsigned artifact.
    if entry.get("is_signed") is False and scoring.unsigned and "unsigned" not in suppressed:
        score += scoring.unsigned
        trace.append(f"unsigned (+{scoring.unsigned})")

    # A missing source row is an evidence gap, not an observed missing Team ID.
    if (
        _observed_team_id_absence(entry)
        and scoring.missing_team_id
        and "missing_team_id" not in suppressed
    ):
        score += scoring.missing_team_id
        trace.append(f"missing_team_id (+{scoring.missing_team_id})")

    # Do not equate Apple's numeric Override value with an explicit block.
    if entry.get("policy_match_label") == "Override: Block" and scoring.override_blocked:
        score += scoring.override_blocked
        trace.append(f"override_blocked (+{scoring.override_blocked})")

    if entry.get("vt_malicious") is True and scoring.vt_malicious:
        score += scoring.vt_malicious
        trace.append(f"vt_malicious (+{scoring.vt_malicious})")

    flags = entry.get("scan_flags")
    if (
        isinstance(flags, int)
        and scoring.custom_flag_mask
        and "custom_flag_mask" not in suppressed
    ):
        for configured_mask, flag_score in scoring.custom_flag_mask.items():
            bitmask = int(configured_mask, 0) if isinstance(configured_mask, str) else configured_mask
            if flags & bitmask:
                score += flag_score
                trace.append(f"flag {hex(bitmask)} (+{flag_score})")

    return score, trace


def filter_output_rows(rows: list[dict], output_config) -> list[dict]:
    """Apply configured minimum score and AND-combined output filters."""
    filtered = [row for row in rows if row.get("risk_score", 0) >= output_config.min_score]

    def matches(row: dict, field: str, expected: Any) -> bool:
        if field == "team_id_missing":
            actual = _observed_team_id_absence(row)
        elif field == "blocked":
            actual = row.get("policy_match_label") == "Override: Block"
        else:
            actual = row.get(field)
        if isinstance(expected, list):
            return actual in expected
        return actual == expected

    for field, expected in output_config.filters.items():
        filtered = [row for row in filtered if matches(row, field, expected)]
    return filtered
