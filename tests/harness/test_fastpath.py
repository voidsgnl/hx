import pytest
from hx.fastpath import FastPath


def test_cookie_filter_only_allowed_domains():
    fp = FastPath()
    fp.set_allowed_domains({"localhost"})
    cookies = [
        {"name": "cf_clearance", "value": "x", "domain": "localhost"},
        {"name": "tracker", "value": "y", "domain": "evil.example"},
    ]
    out = fp._cookies(cookies)
    assert out == {"cf_clearance": "x"}   # third-party cookie must not leak