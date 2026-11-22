import pytest

from hx.fastpath import FastPath
from hx.pacer import Pacer, BudgetExhausted


class Response:
    def __init__(self, status_code=200, location=None, text=""):
        self.status_code = status_code
        self.headers = {"Location": location} if location else {}
        self.text = text


def test_redirect_hops_each_consume_budget(monkeypatch):
    calls = []

    def fake_request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        if url.endswith("/start"):
            return Response(302, "/final")
        return Response(200, text="done")

    monkeypatch.setattr("hx.fastpath.cffi.request", fake_request)
    pacer = Pacer(budget=2)
    fast = FastPath(request_guard=pacer.reserve)

    response = fast._request("GET", "https://example.test/start", timeout=5)

    assert response.status_code == 200
    assert pacer.used == 2
    assert [call[1] for call in calls] == [
        "https://example.test/start",
        "https://example.test/final",
    ]
    assert all(call[2]["allow_redirects"] is False for call in calls)


def test_redirect_stops_before_exceeding_budget(monkeypatch):
    calls = []

    def fake_request(method, url, **kwargs):
        calls.append(url)
        return Response(302, "/next")

    monkeypatch.setattr("hx.fastpath.cffi.request", fake_request)
    pacer = Pacer(budget=1)
    fast = FastPath(request_guard=pacer.reserve)

    with pytest.raises(BudgetExhausted):
        fast._request("GET", "https://example.test/start")

    assert calls == ["https://example.test/start"]
    assert pacer.used == 1
    assert pacer.exhausted
