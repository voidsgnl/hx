import json

import pytest

from hx.client import TargetClient
from hx.oracle import ORACLE_INIT_JS


BASE = "http://localhost:5000"


@pytest.mark.asyncio
async def test_client_restores_cookie_and_local_storage(tmp_path):
    state_path = tmp_path / "storage-state.json"
    state_path.write_text(json.dumps({
        "cookies": [{
            "name": "hx_auth",
            "value": "valid",
            "domain": "localhost",
            "path": "/",
            "expires": -1,
            "httpOnly": False,
            "secure": False,
            "sameSite": "Lax",
        }],
        "origins": [{
            "origin": BASE,
            "localStorage": [{"name": "hx_session", "value": "restored"}],
        }],
    }), encoding="utf-8")

    client = TargetClient(BASE)
    await client.start(
        oracle_init_script=ORACLE_INIT_JS,
        storage_state=str(state_path),
    )
    try:
        await client.page.goto(f"{BASE}/auth-form-page")
        state = await client.page.evaluate("""() => ({
          cookie: document.cookie,
          local: localStorage.getItem("hx_session")
        })""")
        assert "hx_auth=valid" in state["cookie"]
        assert state["local"] == "restored"
        assert "authentication required" not in await client.page.content()
    finally:
        await client.close()
