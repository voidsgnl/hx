import pytest

from hx.site_mapper import SiteMapResult, DiscoveredPage
from hx.website_scan import _get_form_target, _targets_from_map, scan_website


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


@pytest.mark.asyncio
async def test_website_scan_maps_and_tests_get_form_inputs():
    result = await scan_website(
        "http://localhost:5000/discovery",
        budget=100,
        max_pages=5,
        max_depth=1,
    )
    assert result.site_map.pages
    assert result.tested_targets
    assert result.skipped_post_forms == 1
    assert result.requests_used <= 100
    assert any(finding.param == "q" for finding in result.findings)
