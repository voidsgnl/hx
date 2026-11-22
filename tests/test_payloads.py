"""Payload engine gate: detection + proof per context."""
import pytest
from urllib.parse import quote

from hx.client import TargetClient
from hx.fastpath import FastPath
from hx.oracle import probe, ORACLE_INIT_JS
from hx.payloads import detect_context, payloads_for, Context

BASE = "http://localhost:5000"

CASES = [
    ("/jsstring", Context.JS_STRING_DOUBLE),
    ("/jsstring-single", Context.JS_STRING_SINGLE),
    ("/attr-double", Context.ATTR_DOUBLE),
    ("/attr-single", Context.ATTR_SINGLE),
    ("/url-attr", Context.URL_ATTR),
    ("/script-block", Context.SCRIPT_BLOCK),
]


@pytest.fixture
async def client():
    c = TargetClient(BASE, profile_dir="/tmp/hx-payload-profile")
    await c.start(oracle_init_script=ORACLE_INIT_JS)
    assert await c.warm()
    yield c
    await c.close()


@pytest.mark.parametrize("path,expected_ctx", CASES)
async def test_context_detected_and_proven(client, path, expected_ctx):
    fp = FastPath()
    fp.set_allowed_domains({"localhost"})
    marker = "hxctxmark"
    url = f"{BASE}{path}?q={quote(marker)}"
    cookies = await client.cookies()
    cand = fp.find_reflection(url, marker, cookies)
    assert cand is not None, f"marker did not reflect on {path}"

    body = fp.fetch_body(url, cookies)
    det = detect_context(body, cand.offset)
    assert det.context == expected_ctx, (
        f"{path}: got {det.context}, want {expected_ctx}"
    )

    proven = False
    for payload in payloads_for(det.context):
        purl = f"{BASE}{path}?q={quote(payload)}"
        r = await probe(client.page, purl, payload)
        if r.proven:
            proven = True
            break
    assert proven, f"{path}: no payload from {det.context} proved"


@pytest.mark.parametrize("path,expected_ctx", [
    ("/eval-sink", Context.JS_STRING_SINGLE),
])
async def test_eval_sink_still_proves(client, path, expected_ctx):
    fp = FastPath()
    fp.set_allowed_domains({"localhost"})
    marker = "hxevalmark"
    url = f"{BASE}{path}?q={quote(marker)}"
    cookies = await client.cookies()
    cand = fp.find_reflection(url, marker, cookies)
    assert cand is not None

    body = fp.fetch_body(url, cookies)
    det = detect_context(body, cand.offset)
    assert det.context == expected_ctx

    proven = False
    for payload in payloads_for(det.context):
        purl = f"{BASE}{path}?q={quote(payload)}"
        r = await probe(client.page, purl, payload)
        if r.proven:
            hit_kinds = {
                h.kind for h in r.hits
                if h.payload_id == r.payload_id
            }
            assert hit_kinds & {"alert", "confirm", "prompt"}
            proven = True
            break
    assert proven, f"{path}: no JS_STRING_SINGLE payload proved"
