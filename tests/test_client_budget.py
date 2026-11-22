import pytest

from hx.client import TargetClient
from hx.oracle import ORACLE_INIT_JS
from hx.pacer import Pacer


BASE = "http://localhost:5000"


@pytest.mark.asyncio
async def test_browser_requests_cannot_exceed_shared_budget():
    pacer = Pacer(min_delay=0.0, max_delay=0.0, budget=1)
    client = TargetClient(BASE, profile_dir="/tmp/hx-budget-profile")
    await client.start(
        oracle_init_script=ORACLE_INIT_JS,
        request_guard=pacer.reserve,
    )
    try:
        await client.warm()
        if not client.budget_exhausted:
            try:
                await client.page.goto(
                    f"{BASE}/reflect?q=second",
                    wait_until="domcontentloaded",
                    timeout=5000,
                )
            except Exception:
                pass

        assert pacer.used <= 1
        assert client.budget_exhausted
    finally:
        await client.close()
