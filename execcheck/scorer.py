"""Risk scoring rules for ExecCheck entries."""


def score_entry(entry: dict, config) -> tuple[int, list[str]]:
    """Calculate a risk score and trace for a single record."""
    score = 0
    trace = []

    scoring = config.scoring

    # Score: unsigned binary
    if not entry.get("is_signed") and scoring.unsigned:
        score += scoring.unsigned
        trace.append(f"unsigned (+{scoring.unsigned})")

    # Score: missing team_id
    if not entry.get("team_identifier") and scoring.missing_team_id:
        score += scoring.missing_team_id
        trace.append(f"missing_team_id (+{scoring.missing_team_id})")

    # Score: override_blocked
    policy_label = entry.get("policy_match_label")
    policy_code = entry.get("policy_match")
    if (
        policy_label in {"Override", "Override: Block"} or policy_code == 3
    ) and scoring.override_blocked:
        score += scoring.override_blocked
        trace.append(f"override_blocked (+{scoring.override_blocked})")

    # Score: VT malicious
    if entry.get("vt_malicious") and hasattr(config.scoring, "vt_malicious"):
        score += config.scoring.vt_malicious
        trace.append(f"vt_malicious (+{config.scoring.vt_malicious})")


    # Score: custom flag mask (bitmask logic)
    flags = entry.get("scan_flags", 0) or 0
    if isinstance(flags, int) and scoring.custom_flag_mask:
        for bitmask_hex, flag_score in scoring.custom_flag_mask.items():
            bitmask = int(bitmask_hex, 16) if isinstance(bitmask_hex, str) else bitmask_hex
            if flags & bitmask:
                score += flag_score
                trace.append(f"flag {hex(bitmask)} (+{flag_score})")

    return score, trace
