import json

import pytest

from hx.site_mapper import SiteMapResult, DiscoveredPage
from hx.website_scan import _get_form_target, _targets_from_map, scan_website
from hx.engines import AttackSurface, default_registry
import hx.website_scan as website_scan_module


def test_get_form_target_uses_only_injectable_non_password_fields():
    target = _get_form_target(
        "https://example.test/search?lang=en",
        [
            {"name": "q", "type": "search", "role": "injectable"},
            {"name": "password", "type": "password", "role": "injectable"},
            {"name": "csrf", "type": "hidden", "role": "static"},
        ],
    )
    assert target == "https://example.test/search?lang=en&q=hx"


def test_target_planner_keeps_scope_and_skips_post_forms():
    site_map = SiteMapResult(target="https://example.test/")
    site_map.pages.append(DiscoveredPage(
        url="https://example.test/",
        depth=0,
        title="home",
        status=200,
        forms=[
            {
                "action": "https://example.test/search",
                "method": "GET",
                "fields": [{"name": "q", "type": "search", "role": "injectable"}],
            },
            {
                "action": "https://example.test/save",
                "method": "POST",
                "fields": [{"name": "content", "type": "textarea", "role": "injectable"}],
            },
            {
                "action": "https://outside.test/search",
                "method": "GET",
                "fields": [{"name": "q", "type": "search", "role": "injectable"}],
            },
        ],
    ))
    targets, skipped_forms, skipped_endpoints = _targets_from_map(site_map)
    assert targets == ["https://example.test/search?q=hx"]
    assert skipped_forms == 1
    assert skipped_endpoints == 0


def test_engine_registry_selects_only_engines_that_support_a_surface():
    registry = default_registry()
    assert registry.engine_ids == ("xss",)
    supported = AttackSurface(
        url="https://example.test/search?q=x",
        method="GET",
        parameters=("q",),
        behaviour="search",
        source="page",
    )
    unsupported = AttackSurface(
        url="https://example.test/",
        method="GET",
        parameters=(),
        behaviour="general",
        source="page",
    )
    assert [engine.engine_id for engine in registry.select(supported)] == ["xss"]
    assert registry.select(unsupported) == []


@pytest.mark.asyncio
async def test_website_scan_maps_and_tests_get_form_inputs(monkeypatch):
    starts = 0
    closes = 0
    original_client = website_scan_module.TargetClient

    class CountingClient(original_client):
        async def start(self, *args, **kwargs):
            nonlocal starts
            starts += 1
            return await super().start(*args, **kwargs)

        async def close(self):
            nonlocal closes
            closes += 1
            return await super().close()

    monkeypatch.setattr(website_scan_module, "TargetClient", CountingClient)
    result = await website_scan_module.scan_website(
        "http://localhost:5000/discovery",
        budget=100,
        max_pages=5,
        max_depth=1,
    )
    assert result.site_map.pages
    assert result.tested_targets
    assert result.skipped_post_forms == 1
    assert result.engines_run == ["xss"]
    assert result.requests_used <= 100
    assert starts == 1
    assert closes == 1
    assert any(finding.param == "q" for finding in result.findings)


@pytest.mark.asyncio
async def test_website_scan_active_post_preserves_authenticated_session_and_csrf(tmp_path):
    state_path = tmp_path / "authenticated-state.json"
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
        "origins": [],
    }), encoding="utf-8")

    result = await scan_website(
        "http://localhost:5000/auth-form-page",
        budget=100,
        max_pages=3,
        max_depth=0,
        active_post=True,
        storage_state=str(state_path),
    )
    assert result.post_forms_tested == 1
    assert result.skipped_post_forms == 0
    assert result.tested_targets
    assert any(finding.param == "q" for finding in result.findings)
