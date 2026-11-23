import json

import pytest

from hx.site_mapper import SiteMapResult, DiscoveredPage
from hx.website_scan import (
    _get_form_target, _post_surfaces_from_map, _api_surfaces_from_map, _targets_from_map, scan_website,
)
from hx.engines import AttackSurface, default_registry
from hx.scanner import RequestSpec, _apply_marker
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


def test_post_planner_excludes_authentication_forms_unless_explicitly_enabled():
    site_map = SiteMapResult(target="https://example.test/")
    site_map.pages.append(DiscoveredPage(
        url="https://example.test/login",
        depth=0,
        title="login",
        status=200,
        behaviour="authentication",
        forms=[{
            "action": "https://example.test/login",
            "method": "POST",
            "fields": [
                {"name": "username", "type": "text", "role": "injectable"},
                {"name": "password", "type": "password", "role": "injectable"},
            ],
        }],
    ))
    assert _post_surfaces_from_map(site_map) == []
    enabled = _post_surfaces_from_map(site_map, include_auth_forms=True)
    assert len(enabled) == 1
    assert enabled[0].parameters == ("username",)


def test_engine_registry_selects_only_engines_that_support_a_surface():
    registry = default_registry()
    assert registry.engine_ids == ("open_redirect", "xss")
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
    redirect_surface = AttackSurface(
        url="https://example.test/continue?next=%2F",
        method="GET",
        parameters=("next",),
        behaviour="general",
        source="page",
    )
    assert {engine.engine_id for engine in registry.select(redirect_surface)} == {
        "open_redirect", "xss"
    }


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
        include_auth_forms=True,
        storage_state=str(state_path),
    )
    assert result.post_forms_tested == 1
    assert result.skipped_post_forms == 0
    assert result.tested_targets
    assert any(finding.param == "q" for finding in result.findings)



def test_api_planner_preserves_json_body_and_auth_headers_but_skips_secrets():
    site_map = SiteMapResult(target="https://example.test/")
    from hx.site_mapper import DiscoveredEndpoint
    site_map.endpoints.append(DiscoveredEndpoint(
        url="https://example.test/api/update",
        method="POST",
        resource_type="fetch",
        source_page="https://example.test/profile",
        request_body={"message": "hello", "csrf_token": "secret-token"},
        headers={
            "content-type": "application/json",
            "authorization": "Bearer private",
            "x-csrf-token": "csrf-private",
        },
        content_type="application/json",
    ))
    surfaces = _api_surfaces_from_map(site_map)
    assert len(surfaces) == 1
    assert surfaces[0].parameters == ("message",)
    assert surfaces[0].request_body["csrf_token"] == "secret-token"
    assert surfaces[0].headers["authorization"] == "Bearer private"
    public = site_map.to_dict()["endpoints"][0]
    assert public["headers"]["authorization"] == "<redacted>"
    assert public["headers"]["x-csrf-token"] == "<redacted>"
    assert public["request_body"]["csrf_token"] == "<redacted>"


@pytest.mark.asyncio
async def test_website_scan_replays_authenticated_json_api_with_custom_csrf_header():
    result = await website_scan_module.scan_website(
        "http://localhost:5000/api-page",
        budget=160,
        max_pages=2,
        max_depth=0,
        active_api=True,
    )
    assert result.post_apis_tested == 1
    assert result.skipped_post_apis == 0
    api_endpoint = next(
        endpoint for endpoint in result.site_map.endpoints
        if endpoint.method == "POST" and endpoint.request_body
    )
    assert api_endpoint.headers.get("authorization") == "Bearer hx-api-secret"
    assert api_endpoint.headers.get("x-csrf-token") == "hx-api-csrf"
    assert result.scans and any(
        candidate.param == "message" for candidate in result.scans[0].reflections
    ), result.to_dict()
    assert any(finding.param == "message" for finding in result.findings), result.to_dict()
    assert result.findings[0].confidence == "proven_execution"
    public_endpoint = result.to_dict()["site_map"]["endpoints"][0]
    assert public_endpoint["headers"]["authorization"] == "<redacted>"



def test_api_planner_finds_nested_json_scalars_but_skips_nested_secrets():
    site_map = SiteMapResult(target="https://example.test/")
    from hx.site_mapper import DiscoveredEndpoint
    site_map.endpoints.append(DiscoveredEndpoint(
        url="https://example.test/api/update",
        method="POST",
        resource_type="fetch",
        source_page="https://example.test/profile",
        request_body={
            "profile": {"bio": "hello", "csrf_token": "secret"},
            "items": [{"label": "first"}],
        },
        headers={"content-type": "application/json"},
        content_type="application/json",
    ))
    surfaces = _api_surfaces_from_map(site_map)
    assert surfaces[0].parameters == ("/items/0/label", "/profile/bio")


def test_nested_json_marker_replacement_preserves_siblings_and_arrays():
    spec = RequestSpec(
        method="JSON",
        url="https://example.test/api",
        json_body={
            "profile": {"bio": "hello", "csrf_token": "keep"},
            "items": [{"label": "first"}, {"label": "second"}],
        },
        parameters=("/profile/bio",),
    )
    marked = _apply_marker(spec, "/profile/bio", "hx-marker")
    assert marked.json_body["profile"]["bio"] == "hx-marker"
    assert marked.json_body["profile"]["csrf_token"] == "keep"
    assert marked.json_body["items"] == [
        {"label": "first"}, {"label": "second"}
    ]


@pytest.mark.asyncio
async def test_website_scan_replays_nested_json_with_rotating_csrf_header():
    result = await website_scan_module.scan_website(
        "http://localhost:5000/api-rotating-page",
        budget=240,
        max_pages=2,
        max_depth=0,
        active_api=True,
    )
    assert result.post_apis_tested == 1
    endpoint = next(
        endpoint for endpoint in result.site_map.endpoints
        if endpoint.url.endswith("/api/rotating-xss")
    )
    assert endpoint.source_page.endswith("/api-rotating-page")
    assert endpoint.headers.get("authorization") == "Bearer hx-rotating-secret"
    assert endpoint.headers.get("x-csrf-token")
    assert any(
        finding.param == "/profile/bio"
        and finding.confidence == "proven_execution"
        for finding in result.findings
    ), result.to_dict()
