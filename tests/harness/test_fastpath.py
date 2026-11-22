from urllib.request import urlopen

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


def test_chrome_impersonation_can_fetch_juice_shop_http_response():
    url = "http://127.0.0.1:3000/rest/products/search?q=test"
    try:
        with urlopen(url, timeout=2) as response:
            assert response.status == 200
    except OSError as exc:
        pytest.skip(f"local Juice Shop is unavailable: {exc}")

    body = FastPath().fetch_body(url, [])
    assert '"status":"success"' in body
    assert "OWASP SSL Advanced Forensic Tool" in body
