"""The oracle gate. Ground-truth harness endpoints.

Rules:
  /reflect  -> MUST prove
  /dom      -> MUST prove
  /safe     -> MUST NOT prove (escaped)
  /attr     -> MUST NOT prove (escaped attr)
"""
import asyncio
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

REFLECT_PAYLOAD = "<script>alert('hxprobe1')</script>"
DOM_PAYLOAD = "<img src=x onerror=alert('hxprobe2')>"

async def test_reflect_proves(client):
    url = f"{BASE}/reflect?q={quote(REFLECT_PAYLOAD)}"
    r = await probe(client.page, url, REFLECT_PAYLOAD)
    assert r.proven, f"expected proven reflected XSS, hits={r.hits}"

async def test_dom_proves(client):
    url = f"{BASE}/dom?q={quote(DOM_PAYLOAD)}"
    r = await probe(client.page, url, DOM_PAYLOAD)
    assert r.proven, f"expected proven DOM XSS, hits={r.hits}"

async def test_safe_does_not_prove(client):
    url = f"{BASE}/safe?q={quote(REFLECT_PAYLOAD)}"
    r = await probe(client.page, url, REFLECT_PAYLOAD)
    assert not r.proven, f"FALSE POSITIVE on /safe, hits={r.hits}"

async def test_attr_does_not_prove(client):
    url = f"{BASE}/attr?q={quote(REFLECT_PAYLOAD)}"
    r = await probe(client.page, url, REFLECT_PAYLOAD)
    assert not r.proven, f"FALSE POSITIVE on /attr, hits={r.hits}"