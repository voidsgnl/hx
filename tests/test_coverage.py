from dataclasses import asdict

from hx.scanner import scan

BASE = "http://localhost:5000"


async def test_coverage_on_clean_reflect():
    result = await scan(f"{BASE}/reflect?q=test", budget=30)
    coverage = result.coverage
    assert coverage.params_discovered >= 1
    assert coverage.params_tested + coverage.params_skipped == coverage.params_discovered
    assert coverage.reflections >= 1
    assert (
        coverage.findings_proven + coverage.findings_uncontrolled
        == len(result.findings)
    )
    assert coverage.budget_used == result.requests_used
    assert coverage.requests_unaccounted == 0
    assert coverage.blocked == 0


async def test_coverage_on_safe_reflect_no_finding():
    result = await scan(f"{BASE}/safe?q=test", budget=30)
    coverage = result.coverage
    assert coverage.reflections >= 1
    assert coverage.findings_proven == 0
    assert len(result.findings) == 0


async def test_coverage_budget_exhausted():
    result = await scan(
        f"{BASE}/reflect?a=test&b=test&c=test",
        budget=3,
    )
    coverage = result.coverage
    assert coverage.budget_exhausted is True
    assert coverage.budget_used <= coverage.budget_limit
    assert coverage.params_tested + coverage.params_skipped == coverage.params_discovered
    assert "budget" in coverage.skip_reasons


async def test_coverage_blocked_status():
    result = await scan(f"{BASE}/forbidden?q=test", budget=30)
    coverage = result.coverage
    assert coverage.blocked >= 1
    assert any("GET /forbidden -> 403" in detail for detail in coverage.blocked_detail)


async def test_coverage_json_shape():
    result = await scan(f"{BASE}/reflect?q=test", budget=30)
    payload = result.to_dict()
    assert set(payload["coverage"]) == {
        "params_discovered",
        "params_tested",
        "params_skipped",
        "skip_reasons",
        "reflections",
        "contexts",
        "findings_proven",
        "findings_uncontrolled",
        "blocked",
        "blocked_detail",
        "budget_used",
        "budget_limit",
        "budget_exhausted",
        "requests_unaccounted",
    }
    assert asdict(result.coverage) == payload["coverage"]
