"""The oracle gate and payload-attribution regression tests."""
import pytest
from urllib.parse import quote

from hx.client import TargetClient
from hx.oracle import probe, ORACLE_INIT_JS
from hx.payloads import control_payload_for

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



async def test_target_origin_execution_proves_even_after_cross_origin_warmup(client):
    # The browser was initially warmed on localhost, but this probe explicitly
    # targets 127.0.0.1. The proof must be accepted in the requested origin.
    target = "http://127.0.0.1:5000"
    payload = "<script>window.__hx_proof('hxtargetorigin')</script>"
    url = f"{target}/reflect?q={quote(payload)}"
    result = await probe(
        client.page, url, payload, payload_id="hxtargetorigin"
    )
    assert result.proven
    assert result.hits[0].origin == target


async def test_execution_after_cross_origin_redirect_is_not_attributed(client):
    payload = "<script>window.__hx_proof('hxredirectorigin')</script>"
    url = f"{BASE}/cross-origin-redirect?q={quote(payload)}"
    result = await probe(
        client.page, url, payload, payload_id="hxredirectorigin"
    )
    assert not result.proven
    assert any(hit.origin == "http://127.0.0.1:5000" for hit in result.hits)



async def test_benign_control_callback_does_not_prove(client):
    active = "<script>window.__hx_proof('hx-control')</script>"
    control = control_payload_for(active)
    assert control is not None
    url = f"{BASE}/reflect?q={quote(control)}"
    result = await probe(
        client.page, url, control, payload_id="hx-control"
    )
    assert not result.proven
