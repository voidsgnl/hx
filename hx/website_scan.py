"""Automated website scan orchestration.

Discovery and vulnerability testing remain separate: the mapper is read-only,
while this coordinator turns discovered, low-risk GET input surfaces into
explicit requests for the existing XSS scanner. Additional vulnerability
engines can be plugged into this orchestration without changing the crawler.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from urllib.parse import parse_qs, parse_qsl, urlencode, urlsplit, urlunsplit

from hx.client import TargetClient
from hx.engines import AttackSurface, EngineContext, default_registry
from hx.oracle import ORACLE_INIT_JS
from hx.pacer import Pacer
from hx.scanner import ScanResult
from hx.site_mapper import SiteMapResult, _is_in_scope, _page_key, map_site


@dataclass
class WebsiteScanResult:
    target: str
    site_map: SiteMapResult
    scans: list[ScanResult] = field(default_factory=list)
    tested_targets: list[str] = field(default_factory=list)
    skipped_post_forms: int = 0
    skipped_post_endpoints: int = 0
    mapping_budget_exhausted: bool = False
    engines_run: list[str] = field(default_factory=list)
    requests_used: int = 0
    budget_exhausted: bool = False

    @property
    def findings(self):
        return [finding for result in self.scans for finding in result.findings]

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "site_map": self.site_map.to_dict(),
            "tested_targets": self.tested_targets,
            "skipped_post_forms": self.skipped_post_forms,
            "skipped_post_endpoints": self.skipped_post_endpoints,
            "mapping_budget_exhausted": self.mapping_budget_exhausted,
            "engines_run": sorted(set(self.engines_run)),
            "requests_used": self.requests_used,
            "budget_exhausted": self.budget_exhausted,
            "findings": [
                {
                    "target": result.target,
                    "param": finding.param,
                    "url": finding.url,
                    "payload": finding.payload,
                    "payload_id": finding.probe.payload_id,
                    "context": finding.context,
                    "hits": [asdict(hit) for hit in finding.probe.hits],
                }
                for result in self.scans
                for finding in result.findings
            ],
            "scans": [
                {
                    "target": result.target,
                    "reached_app": result.reached_app,
                    "requests_used": result.requests_used,
                    "budget_exhausted": result.budget_exhausted,
                    "fingerprint": result.fingerprint,
                    "reflections": [asdict(item) for item in result.reflections],
                    "findings": [
                        {
                            "param": item.param,
                            "url": item.url,
                            "payload": item.payload,
                            "payload_id": item.probe.payload_id,
                            "context": item.context,
                            "hits": [asdict(hit) for hit in item.probe.hits],
                        }
                        for item in result.findings
                    ],
                }
                for result in self.scans
            ],
        }


def _get_form_target(action: str, fields: list[dict]) -> str | None:
    names = [
        item.get("name", "")
        for item in fields
        if item.get("role") == "injectable"
        and item.get("type") not in ("password", "file")
        and item.get("name")
    ]
    if not names:
        return None
    parts = urlsplit(action)
    query = parse_qs(parts.query, keep_blank_values=True)
    for name in names:
        query[name] = ["hx"]
    return urlunsplit(parts._replace(query=urlencode(query, doseq=True)))


def _targets_from_map(site_map: SiteMapResult) -> tuple[list[str], int, int]:
    targets: list[str] = []
    seen: set[str] = set()
    skipped_post_forms = 0
    skipped_post_endpoints = 0

    def add(url: str):
        key = _page_key(url)
        if key not in seen:
            seen.add(key)
            targets.append(url)

    for page in site_map.pages:
        if page.query_parameters:
            add(page.url)
        for form in page.forms:
            if form.get("method", "GET").upper() == "POST":
                skipped_post_forms += 1
                continue
            target = _get_form_target(form.get("action", ""), form.get("fields", []))
            if target and _is_in_scope(target, site_map.target):
                add(target)

    for endpoint in site_map.endpoints:
        if endpoint.method == "GET" and endpoint.query_parameters:
            add(endpoint.url)
        elif endpoint.method == "POST":
            skipped_post_endpoints += 1

    return targets, skipped_post_forms, skipped_post_endpoints


def _surface_for(target: str, site_map: SiteMapResult) -> AttackSurface:
    parts = urlsplit(target)
    parameters = {
        name for name, _ in parse_qsl(parts.query, keep_blank_values=True)
    }
    fragment = parts.fragment
    if "?" in fragment:
        parameters.update(
            name for name, _ in parse_qsl(fragment.split("?", 1)[1], keep_blank_values=True)
        )
    elif "=" in fragment or "&" in fragment:
        parameters.update(
            name for name, _ in parse_qsl(fragment, keep_blank_values=True)
        )

    behaviour = "general"
    source = "discovered-page"
    page = next(
        (item for item in site_map.pages if _page_key(item.url) == _page_key(target)),
        None,
    )
    if page:
        behaviour = page.behaviour
    else:
        endpoint = next((item for item in site_map.endpoints if item.url == target), None)
        if endpoint:
            source = "browser-api"
            parent = next(
                (item for item in site_map.pages if item.url == endpoint.source_page),
                None,
            )
            if parent:
                behaviour = parent.behaviour
        else:
            for candidate in site_map.pages:
                for form in candidate.forms:
                    if form.get("action") == target:
                        behaviour = candidate.behaviour
                        source = "discovered-form"
                        break

    return AttackSurface(
        url=target,
        method="GET",
        parameters=tuple(sorted(parameters)),
        behaviour=behaviour,
        source=source,
    )


async def scan_website(
    base_url: str,
    *,
    proxy: str | None = None,
    budget: int = 300,
    max_pages: int = 100,
    max_depth: int = 3,
    headless: bool = True,
) -> WebsiteScanResult:
    """Map a website, then test discovered GET inputs with the XSS engine.

    POST forms are mapped but not submitted automatically because they may
    change application state. Their testing will require an explicit active
    form-testing policy and suitable CSRF/session handling.
    """
    if budget < 1:
        raise ValueError("budget must be at least 1")
    parsed_base = urlsplit(base_url)
    if parsed_base.scheme not in ("http", "https") or not parsed_base.hostname:
        raise ValueError("base_url must be an absolute http:// or https:// URL")
    # Reserve most of the request budget for actual vulnerability checks.
    # A large site must not consume the entire budget during discovery alone.
    mapping_budget = max(1, int(budget * 0.4))
    origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
    mapping_pacer = Pacer(budget=mapping_budget)
    client = TargetClient(origin, proxy=proxy)
    await client.start(
        oracle_init_script=ORACLE_INIT_JS,
        request_guard=mapping_pacer.reserve,
        headless=headless,
        navigation_guard=lambda destination: _is_in_scope(destination, base_url),
    )
    test_pacer: Pacer | None = None
    try:
        site_map = await map_site(
            base_url,
            proxy=proxy,
            budget=mapping_budget,
            max_pages=max_pages,
            max_depth=max_depth,
            headless=headless,
            _client=client,
            _pacer=mapping_pacer,
        )
        result = WebsiteScanResult(
            target=base_url,
            site_map=site_map,
            mapping_budget_exhausted=site_map.budget_exhausted,
        )
        (
            targets,
            result.skipped_post_forms,
            result.skipped_post_endpoints,
        ) = _targets_from_map(site_map)
        remaining = max(0, budget - mapping_pacer.used)

        if remaining:
            test_pacer = Pacer(budget=remaining)
            client.request_guard = test_pacer.reserve
            # The mapping stage may have exhausted its own allowance. The
            # testing stage gets a fresh allowance, but keeps the same browser
            # context, cookies, and page instrumentation.
            client.budget_exhausted = False

        registry = default_registry()
        for target in targets:
            if remaining <= 0 or test_pacer is None:
                result.budget_exhausted = True
                break
            surface = _surface_for(target, site_map)
            engines = registry.select(surface)
            for engine in engines:
                if remaining <= 0:
                    result.budget_exhausted = True
                    break
                engine_result = await engine.run(
                    surface,
                    EngineContext(
                        proxy=proxy,
                        budget=remaining,
                        headless=headless,
                        client=client,
                        pacer=test_pacer,
                        client_ready=True,
                    ),
                )
                result.engines_run.append(engine.engine_id)
                if engine.engine_id == "xss":
                    result.scans.append(engine_result)
                result.tested_targets.append(target)
                remaining = max(0, remaining - engine_result.requests_used)
                if engine_result.budget_exhausted:
                    result.budget_exhausted = True
                    break
            if result.budget_exhausted:
                break

        result.requests_used = mapping_pacer.used + (
            test_pacer.used if test_pacer else 0
        )
        result.budget_exhausted = result.budget_exhausted or remaining == 0
        return result
    finally:
        await client.close()
