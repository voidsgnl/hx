from urllib.parse import urlsplit

import pytest

from hx.site_mapper import (
    _behaviour_for,
    _is_framework_navigation_request,
    _is_in_scope,
    _page_key,
    map_site,
)


def test_scope_is_exact_origin_not_just_hostname():
    base = "https://example.test:443/"
    assert _is_in_scope("https://example.test:443/login", base)
    assert not _is_in_scope("https://sub.example.test:443/", base)
    assert not _is_in_scope("https://example.test:8443/", base)
    assert not _is_in_scope("http://example.test:443/", base)


def test_scope_normalizes_default_ports():
    assert _is_in_scope("http://example.test:80/a", "http://example.test/")
    assert _is_in_scope("https://example.test:443/a", "https://example.test/")


def test_page_key_deduplicates_values_but_preserves_parameter_names():
    first = _page_key("https://example.test/search?q=alice&page=1")
    second = _page_key("https://example.test/search?page=9&q=bob")
    third = _page_key("https://example.test/search?term=bob")
    assert first == second
    assert first != third


def test_framework_navigation_requests_are_not_application_api_surfaces():
    assert _is_framework_navigation_request(
        "https://example.test/about?_rsc=abc"
    )
    assert _is_framework_navigation_request(
        "https://example.test/_next/data/build-id/index.json"
    )
    assert _is_framework_navigation_request(
        "https://example.test/about",
        {"RSC": "1", "Accept": "text/x-component"},
    )
    assert not _is_framework_navigation_request(
        "https://example.test/api/search?q=term",
        {"Accept": "application/json"},
    )


def test_behaviour_classifier_uses_route_and_form_semantics():
    auth_form = [{
        "fields": [
            {"name": "email"},
            {"name": "password"},
        ]
    }]
    assert _behaviour_for("https://example.test/account", auth_form) == "authentication"
    assert _behaviour_for("https://example.test/search", []) == "search"
    assert _behaviour_for("https://example.test/notes", auth_form) == "authentication"


@pytest.mark.asyncio
async def test_maps_forms_and_groups_pages_without_submitting_them():
    progress = []
    result = await map_site(
        "http://localhost:5000/discovery",
        budget=40,
        max_pages=5,
        max_depth=1,
        progress=progress.append,
    )
    assert result.pages
    page = next(item for item in result.pages if item.url.endswith("/discovery"))
    assert page.status == 200
    assert page.behaviour == "search"
    assert len(page.forms) == 2
    assert {field["name"] for form in page.forms for field in form["fields"]} >= {
        "q", "note"
    }
    assert result.groups
    assert result.requests_used > 0
    assert any("Starting Chromium" in event for event in progress)
    assert any("HTTP response" in event for event in progress)
    assert any("Page analysis" in event for event in progress)
    assert any("Page mapped" in event for event in progress)
    assert any("Discovery finished" in event for event in progress)


@pytest.mark.asyncio
async def test_maps_javascript_routes_and_fetch_api_endpoints():
    result = await map_site(
        "http://localhost:5000/spa",
        budget=50,
        max_pages=5,
        max_depth=1,
    )
    route = next(
        page for page in result.pages
        if urlsplit(page.url).path == "/search"
    )
    assert route.query_parameters == ["q"]
    endpoint = next(
        item for item in result.endpoints
        if urlsplit(item.url).path == "/api/search"
    )
    assert endpoint.method == "GET"
    assert endpoint.query_parameters == ["q"]


@pytest.mark.asyncio
async def test_maps_click_triggered_api_and_records_replayable_control():
    result = await map_site(
        "http://localhost:5000/interactive-api-page",
        budget=80,
        max_pages=1,
        max_depth=0,
    )
    assert result.interactions_attempted >= 1, result.to_dict()
    endpoint = next(
        (
            item for item in result.endpoints
            if item.url.endswith("/api/interactive-xss")
        ),
        None,
    )
    assert endpoint is not None, result.to_dict()
    assert endpoint.method == "POST"
    assert endpoint.source_page.endswith("/interactive-api-page")
    assert endpoint.trigger == [
        {"role": "button", "name": "Open profile", "match_index": 0},
        {"role": "button", "name": "Load profile", "match_index": 0},
    ]
    assert endpoint.headers.get("authorization") == "Bearer hx-interactive-secret"
    assert endpoint.headers.get("x-csrf-token")
