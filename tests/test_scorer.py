from pathlib import Path

from execcheck.config import Config, OutputConfig, ScoringWeights, Whitelist, load_config
from execcheck.scorer import annotate_allowlist, filter_output_rows, score_entry


def make_config(*, custom_flags=None, whitelist=None, output=None):
    return Config(
        scoring=ScoringWeights(
            unsigned=5,
            missing_team_id=3,
            override_blocked=7,
            vt_malicious=10,
            custom_flag_mask=custom_flags or {},
        ),
        whitelist=whitelist or Whitelist(),
        output=output or OutputConfig(),
    )


def test_unknown_is_not_treated_as_unsigned():
    score, trace = score_entry({"is_signed": None, "team_identifier": "TEAM"}, make_config())
    assert score == 0
    assert not any("unsigned" in item for item in trace)


def test_explicit_false_is_treated_as_unsigned():
    score, trace = score_entry({"is_signed": False, "team_identifier": "TEAM"}, make_config())
    assert score == 5
    assert "unsigned (+5)" in trace


def test_unknown_team_id_is_not_scored_as_missing():
    entry = {
        "team_identifier": None,
        "field_provenance": {"team_identifier": {"state": "unknown"}},
    }
    score, trace = score_entry(entry, make_config())
    assert score == 0
    assert not any("missing_team_id" in item for item in trace)


def test_observed_null_team_id_can_be_scored():
    entry = {
        "team_identifier": None,
        "field_provenance": {
            "team_identifier": {
                "state": "observed_null",
                "observed_null_sources": ["executable_measurements_v2"],
            }
        },
    }
    score, trace = score_entry(entry, make_config())
    assert score == 3
    assert "missing_team_id (+3)" in trace


def test_numeric_override_is_not_assumed_to_be_blocked():
    score, trace = score_entry(
        {"is_signed": True, "team_identifier": "TEAM", "policy_match": 3},
        make_config(),
    )
    assert score == 0
    assert not any("override_blocked" in item for item in trace)


def test_explicit_override_block_still_scores():
    score, trace = score_entry(
        {
            "is_signed": True,
            "team_identifier": "TEAM",
            "policy_match_label": "Override: Block",
        },
        make_config(),
    )
    assert score == 7
    assert "override_blocked (+7)" in trace


def test_unknown_flag_has_no_default_score():
    score, trace = score_entry(
        {"is_signed": None, "team_identifier": "TEAM", "scan_flags": 0x2000},
        make_config(),
    )
    assert score == 0
    assert trace == []


def test_sample_configuration_has_no_unknown_flag_scores():
    config = load_config(str(Path(__file__).parents[1] / "sample_config.yaml"))
    assert config.scoring.custom_flag_mask == {}
    assert config.output.min_score == 0
    assert config.output.filters == {}


def test_explicit_custom_flag_score_still_works():
    score, trace = score_entry(
        {"is_signed": None, "team_identifier": "TEAM", "scan_flags": 0x2000},
        make_config(custom_flags={0x2000: 4}),
    )
    assert score == 4
    assert "flag 0x2000 (+4)" in trace


def test_allowlist_is_transparent_and_suppresses_applicable_heuristics():
    config = make_config(
        custom_flags={0x2000: 4},
        whitelist=Whitelist(hashes=["ABC"], team_ids=[], paths=[]),
    )
    entry = {
        "cdhash": "abc",
        "is_signed": False,
        "team_identifier": None,
        "scan_flags": 0x2000,
        "field_provenance": {
            "team_identifier": {
                "state": "observed_null",
                "observed_null_sources": ["executable_measurements_v2"],
            }
        },
    }
    annotate_allowlist(entry, config)
    score, trace = score_entry(entry, config)
    assert entry["allowlist_matches"] == [{"type": "hash", "value": "ABC"}]
    assert set(entry["allowlist_suppressed_rules"]) == {
        "unsigned",
        "missing_team_id",
        "custom_flag_mask",
    }
    assert score == 0
    assert trace == []
    assert entry["is_signed"] is False  # Evidence is retained.


def test_output_min_score_and_filters_are_enforced():
    rows = [
        {"risk_score": 2, "team_identifier": "A"},
        {"risk_score": 7, "team_identifier": "A"},
        {"risk_score": 8, "team_identifier": "B"},
    ]
    output = OutputConfig(min_score=5, filters={"team_identifier": "A"})
    assert filter_output_rows(rows, output) == [rows[1]]
