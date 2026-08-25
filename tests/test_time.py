from execcheck.utils.time import to_iso8601


def test_timestamp_uses_python_310_compatible_utc_timezone():
    assert to_iso8601(0) == "1970-01-01T00:00:00Z"


def test_missing_timestamp_remains_unknown():
    assert to_iso8601(None) is None
