import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from execcheck.scorer import score_entry
from execcheck.config import Config, ScoringWeights, Whitelist, OutputConfig


def make_config():
    """Create a minimal configuration object for tests."""
    return Config(
        vt_api_key=None,
        scoring=ScoringWeights(
            unsigned=5,
            missing_team_id=3,
            override_blocked=7,
            vt_malicious=10,
            custom_flag_mask={0x2000: 4, 0x800: 2},
        ),
        whitelist=Whitelist(hashes=[], team_ids=[], paths=[]),
        output=OutputConfig(min_score=5, filters={"team_id_missing": True, "blocked": True}),
    )


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
