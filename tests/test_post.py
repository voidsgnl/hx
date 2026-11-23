import pytest

from hx.client import TargetClient
from hx.oracle import probe_post_form, probe_post_json, ORACLE_INIT_JS
from hx.scanner import RequestSpec, scan

BASE = "http://localhost:5000"
PAYLOAD = "<script>window.__hx_proof('hxpost')</script>"


@pytest.fixture
async def client():
    c = TargetClient(BASE, profile_dir="/tmp/hx-post-profile")
    await c.start(oracle_init_script=ORACLE_INIT_JS)
    assert await c.warm()
    yield c
    await c.close()


async def test_post_form_proves(client):
    r = await probe_post_form(
        client.page,
        f"{BASE}/post-reflect",
        {"q": PAYLOAD},
        payload_id="hxpost",
    )
    assert r.proven, f"POST form not proven, hits={r.hits}"


async def test_post_json_proves(client):
    r = await probe_post_json(
        client.page,
        f"{BASE}/post-json",
        {"q": PAYLOAD},
        payload_id="hxpost",
    )
    assert r.proven, f"POST JSON not proven, hits={r.hits}"


async def test_post_safe_does_not_prove(client):
    r = await probe_post_form(
        client.page,
        f"{BASE}/post-safe",
        {"q": PAYLOAD},
        payload_id="hxpost",
    )
    assert not r.proven, f"FALSE POSITIVE on /post-safe, hits={r.hits}"


async def test_post_wrong_marker_does_not_prove(client):
    r = await probe_post_form(
        client.page,
        f"{BASE}/post-reflect",
        {"q": PAYLOAD},
        payload_id="hxnotthesame",
    )
    assert not r.proven, f"wrong POST payload marker was accepted, hits={r.hits}"


async def test_scanner_post_form_end_to_end():
    spec = RequestSpec(
        method="POST",
        url=f"{BASE}/post-reflect",
        form={"q": "test"},
    )
    res = await scan(spec, budget=30)
    assert res.reached_app
    assert len(res.findings) == 1
    assert res.findings[0].param == "q"
    assert res.findings[0].probe.proven


async def test_scanner_post_safe_no_finding():
    spec = RequestSpec(
        method="POST",
        url=f"{BASE}/post-safe",
        form={"q": "test"},
    )
    res = await scan(spec, budget=30)
    assert res.reached_app
    assert len(res.findings) == 0


async def test_scanner_post_form_uses_live_csrf_token_and_browser_session():
    spec = RequestSpec(
        method="POST",
        url=f"{BASE}/post-form-reflect",
        form={"q": ""},
        form_page=f"{BASE}/post-form-page",
    )
    res = await scan(spec, budget=60)
    assert res.reached_app
    assert len(res.findings) == 1
    assert res.findings[0].param == "q"
    assert res.findings[0].probe.proven
