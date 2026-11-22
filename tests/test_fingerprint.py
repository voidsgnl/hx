import pytest
from curl_cffi import requests as cffi

from hx.client import TargetClient
from hx.fingerprint import check_fingerprint_match
from hx.oracle import ORACLE_INIT_JS
from hx.versions import CHROMIUM_MAJOR, CURL_CFFI_IMPERSONATE

BASE = "http://localhost:5000"


@pytest.fixture
async def client():
    c = TargetClient(BASE, profile_dir="/tmp/hx-fp-profile")
    await c.start(oracle_init_script=ORACLE_INIT_JS)
    assert await c.warm()
    yield c
    await c.close()


async def test_fingerprint_matches(client):
    result = await check_fingerprint_match(client.page, CURL_CFFI_IMPERSONATE)
    assert result.browser_version is not None
    assert result.browser_version == CHROMIUM_MAJOR, (
        f"Playwright Chromium drifted: expected {CHROMIUM_MAJOR}, "
        f"got {result.browser_version}"
    )
    assert result.impersonate_version == CHROMIUM_MAJOR
    assert result.matches is True
    response = cffi.get(
        f"{BASE}/reflect?q=fingerprint",
        impersonate=CURL_CFFI_IMPERSONATE,
        timeout=5,
    )
    assert response.status_code == 200


async def test_fingerprint_mismatch_warns(client):
    result = await check_fingerprint_match(client.page, "chrome999")
    assert result.matches is False
    assert result.warning is not None
    assert "FINGERPRINT MISMATCH" in result.warning


async def test_chrome152_profile_is_detected_as_drift(client):
    result = await check_fingerprint_match(client.page, "chrome152")
    assert result.browser_version == CHROMIUM_MAJOR
    assert result.impersonate_version == "152"
    assert result.matches is False
    assert "FINGERPRINT MISMATCH" in (result.warning or "")
    response = cffi.get(
        f"{BASE}/reflect?q=fingerprint",
        impersonate="chrome152",
        timeout=5,
    )
    assert response.status_code == 200


async def test_fingerprint_bad_impersonate_string(client):
    result = await check_fingerprint_match(client.page, "not-a-chrome-profile")
    assert result.matches is False
    assert "could not parse" in (result.warning or "")
