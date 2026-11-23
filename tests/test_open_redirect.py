import pytest

from hx.engines import AttackSurface, EngineContext, OpenRedirectEngine
from hx.pacer import Pacer


BASE = "http://localhost:5000"


class EmptyBrowserSession:
    async def cookies(self):
        return []


@pytest.mark.asyncio
async def test_open_redirect_engine_detects_external_location_without_following():
    pacer = Pacer(budget=10, min_delay=0, max_delay=0)
    engine = OpenRedirectEngine()
    surface = AttackSurface(
        url=f"{BASE}/redirect?next=%2F",
        method="GET",
        parameters=("next",),
        behaviour="general",
        source="discovered-page",
    )
    result = await engine.run(
        surface,
        EngineContext(
            proxy=None,
            budget=10,
            headless=True,
            client=EmptyBrowserSession(),
            pacer=pacer,
        ),
    )
    assert len(result.findings) == 1
    assert result.findings[0].status == 302
    assert result.findings[0].destination == (
        "https://hx.invalid/hx-open-redirect-check"
    )
    assert result.requests_used == 1


@pytest.mark.asyncio
async def test_open_redirect_engine_ignores_same_origin_redirects():
    pacer = Pacer(budget=10, min_delay=0, max_delay=0)
    surface = AttackSurface(
        url=f"{BASE}/internal-redirect?next=%2F",
        method="GET",
        parameters=("next",),
        behaviour="general",
        source="discovered-page",
    )
    result = await OpenRedirectEngine().run(
        surface,
        EngineContext(
            proxy=None,
            budget=10,
            headless=True,
            client=EmptyBrowserSession(),
            pacer=pacer,
        ),
    )
    assert result.findings == []
    assert result.requests_used == 1


def test_open_redirect_engine_does_not_treat_fragment_parameters_as_server_inputs():
    surface = AttackSurface(
        url="https://example.test/#/continue?next=%2F",
        method="GET",
        parameters=("next",),
        behaviour="general",
        source="discovered-page",
    )
    assert not OpenRedirectEngine().supports(surface)
