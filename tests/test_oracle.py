"""The oracle gate and payload-attribution regression tests."""
import pytest
from urllib.parse import quote

from hx.client import TargetClient
from hx.oracle import probe, ORACLE_INIT_JS

BASE = "http://localhost:5000"


@pytest.fixture
async def client():
    c = TargetClient(BASE, profile_dir="/tmp/hx-test-profile")
    await c.start(oracle_init_script=ORACLE_INIT_JS)
    ok = await c.warm()
    assert ok, "failed to reach harness (is tests/harness/app.py running?)"
    yield c
    await c.close()


REFLECT_PAYLOAD = "<script>window.__hx_proof('hxprobe1')</script>"
DOM_PAYLOAD = "<img src=x onerror=window.__hx_proof('hxprobe2')>"


async def test_reflect_proves(client):
    url = f"{BASE}/reflect?q={quote(REFLECT_PAYLOAD)}"
    r = await probe(client.page, url, REFLECT_PAYLOAD, payload_id="hxprobe1")
    assert r.proven, f"expected proven reflected XSS, hits={r.hits}"


async def test_dom_proves(client):
    url = f"{BASE}/dom?q={quote(DOM_PAYLOAD)}"
    r = await probe(client.page, url, DOM_PAYLOAD, payload_id="hxprobe2")
    assert r.proven, f"expected proven DOM XSS, hits={r.hits}"


async def test_safe_does_not_prove(client):
    url = f"{BASE}/safe?q={quote(REFLECT_PAYLOAD)}"
    r = await probe(client.page, url, REFLECT_PAYLOAD, payload_id="hxprobe1")
    assert not r.proven, f"FALSE POSITIVE on /safe, hits={r.hits}"


async def test_attr_does_not_prove(client):
    url = f"{BASE}/attr?q={quote(REFLECT_PAYLOAD)}"
    r = await probe(client.page, url, REFLECT_PAYLOAD, payload_id="hxprobe1")
    assert not r.proven, f"FALSE POSITIVE on /attr, hits={r.hits}"


async def test_different_executed_marker_does_not_prove(client):
    url = f"{BASE}/reflect?q={quote(REFLECT_PAYLOAD)}"
    r = await probe(client.page, url, REFLECT_PAYLOAD, payload_id="hxnotthesame")
    assert not r.proven, f"wrong payload marker was accepted, hits={r.hits}"


async def test_unrelated_page_execution_does_not_prove(client):
    url = f"{BASE}/unrelated-alert"
    r = await probe(
        client.page,
        url,
        "<script>window.__hx_proof('hxexpected')</script>",
        payload_id="hxexpected",
    )
    assert not r.proven, f"unrelated JavaScript was attributed to the probe: {r.hits}"



async def test_cross_origin_navigation_still_proves(client):
    # The fixture warms localhost, while this request uses 127.0.0.1.
    # They reach the same harness but are distinct browser origins, so
    # origin-scoped sessionStorage cannot carry the active probe ID.
    cross_origin = "http://127.0.0.1:5000"
    payload = "<script>window.__hx_proof('hxcrossorigin')</script>"
    url = f"{cross_origin}/reflect?q={quote(payload)}"
    result = await probe(
        client.page, url, payload, payload_id="hxcrossorigin"
    )
    assert result.proven, (
        f"expected proof after cross-origin navigation, hits={result.hits}"
    )
