def test_score_entry_override_blocked():
    cfg = make_config()
    entry = {
        "is_signed": True,
        "team_identifier": "TEAM",
        "policy_match_label": "Override: Block",
        "vt_malicious": False,
        "scan_flags": 0,
    }
    score, trace = score_entry(entry, cfg)
    assert score == cfg.scoring.override_blocked
    assert "override_blocked (+7)" in trace


def test_score_entry_multiple_triggers():
    cfg = make_config()
    entry = {
        "is_signed": False,
        "team_identifier": None,
        "policy_match_label": "Override: Block",
        "vt_malicious": True,
        "scan_flags": 0x2800,  # 0x2000 | 0x800
    }
    score, trace = score_entry(entry, cfg)
    expected = 5 + 3 + 7 + 10 + 4 + 2
    assert score == expected
    assert len(trace) == 6
    assert "override_blocked (+7)" in trace