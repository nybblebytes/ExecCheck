from execcheck import vt


class Response:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self.payload = payload or {}

    def json(self):
        return self.payload


def test_vt_http_failure_is_unknown_not_false(monkeypatch):
    monkeypatch.setattr(vt.requests, "get", lambda *args, **kwargs: Response(503))
    monkeypatch.setattr(vt.time, "sleep", lambda _: None)
    result = vt.query_vt(["hash"], "key")["hash"]
    assert result["vt_malicious"] is None
    assert result["vt_evidence_state"] == "unknown"
    assert result["vt_error"] == "HTTP status 503"


def test_vt_zero_malicious_is_observed_false(monkeypatch):
    payload = {
        "data": {"attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 12}}}
    }
    monkeypatch.setattr(vt.requests, "get", lambda *args, **kwargs: Response(200, payload))
    monkeypatch.setattr(vt.time, "sleep", lambda _: None)
    result = vt.query_vt(["hash"], "key")["hash"]
    assert result["vt_malicious"] is False
    assert result["vt_evidence_state"] == "observed"
