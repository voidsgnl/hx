import pytest

from hx.client import TargetClient
from hx.fingerprint import check_fingerprint_match
from hx.oracle import ORACLE_INIT_JS

BASE = "http://localhost:5000"


@pytest.fixture
async def client():
    c = TargetClient(BASE, profile_dir="/tmp/hx-fp-profile")
    await c.start(oracle_init_script=ORACLE_INIT_JS)
    assert await c.warm()
    yield c
    await c.close()


async def test_fingerprint_check_runs(client):
    result = await check_fingerprint_match(client.page, "chrome124")
    assert result.browser_version is not None
    assert result.impersonate_version == "124"
    if not result.matches:
        assert result.warning is not None
        assert "FINGERPRINT MISMATCH" in result.warning


async def test_fingerprint_mismatch_warns(client):
    result = await check_fingerprint_match(client.page, "chrome999")
    assert result.matches is False
    assert result.warning is not None
    assert "FINGERPRINT MISMATCH" in result.warning


async def test_fingerprint_bad_impersonate_string(client):
    result = await check_fingerprint_match(client.page, "not-a-chrome-profile")
    assert result.matches is False
    assert "could not parse" in (result.warning or "")
