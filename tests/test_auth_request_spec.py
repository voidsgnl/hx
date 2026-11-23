from hx.scanner import RequestSpec, _apply_marker, scan


BASE = "http://localhost:5000"


def test_apply_marker_preserves_headers_and_cookies():
    spec = RequestSpec(
        method="GET",
        url="http://x/y",
        headers={"X": "1"},
        cookies={"a": "b"},
    )
    out = _apply_marker(spec, "q", "marker")
    assert out.headers == {"X": "1"}
    assert out.cookies == {"a": "b"}


async def test_authed_scan_proves_end_to_end():
    spec = RequestSpec(
        method="GET",
        url=f"{BASE}/authed-reflect?q=test",
        headers={"X-Test-Auth": "secret"},
    )
    res = await scan(spec, budget=30)
    assert res.reached_app
    assert len(res.findings) == 1
    assert res.findings[0].probe.proven


async def test_authed_cookie_scan_proves_end_to_end():
    spec = RequestSpec(
        method="GET",
        url=f"{BASE}/authed-cookie-reflect?q=test",
        cookies={"X-Test-Auth": "secret"},
    )
    res = await scan(spec, budget=30)
    assert res.reached_app
    assert len(res.findings) == 1
    assert res.findings[0].probe.proven


async def test_authed_scan_without_header_does_not_prove():
    spec = RequestSpec(
        method="GET",
        url=f"{BASE}/authed-reflect?q=test",
    )
    res = await scan(spec, budget=20)
    assert len(res.findings) == 0
    assert res.coverage.params_tested == 1
    assert res.coverage.blocked >= 1
    assert any(
        "GET /authed-reflect -> 401" in detail
        for detail in res.coverage.blocked_detail
    )
