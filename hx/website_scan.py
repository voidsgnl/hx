"""Automated website scan orchestration.

Discovery and vulnerability testing remain separate. The coordinator maps
input surfaces, selects independent engines, and combines their evidence
without coupling vulnerability logic to the crawler.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from urllib.parse import parse_qs, parse_qsl, urlencode, urlsplit, urlunsplit

from hx.client import TargetClient
from hx.engines import AttackSurface, EngineContext, default_registry
from hx.oracle import ORACLE_INIT_JS
from hx.pacer import Pacer
from hx.scanner import ScanResult
from hx.site_mapper import (
    SiteMapResult, _is_in_scope, _mapping_request_allowed, _page_key, map_site,
)


@dataclass
class WebsiteScanResult:
    target: str
    site_map: SiteMapResult
    scans: list[ScanResult] = field(default_factory=list)
    tested_targets: list[str] = field(default_factory=list)
    skipped_post_forms: int = 0
    skipped_post_endpoints: int = 0
    post_forms_tested: int = 0
    post_apis_tested: int = 0
    skipped_post_apis: int = 0
    mapping_budget_exhausted: bool = False
    engines_run: list[str] = field(default_factory=list)
    engine_results: list[dict] = field(default_factory=list)
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
            "post_forms_tested": self.post_forms_tested,
            "post_apis_tested": self.post_apis_tested,
            "skipped_post_apis": self.skipped_post_apis,
            "mapping_budget_exhausted": self.mapping_budget_exhausted,
            "engines_run": sorted(set(self.engines_run)),
            "engine_results": self.engine_results,
            "requests_used": self.requests_used,
            "budget_exhausted": self.budget_exhausted,
            "findings": [
                {
                    "engine": "xss",
                    "target": result.target,
                    "param": finding.param,
                    "url": finding.url,
                    "payload": finding.payload,
                    "payload_id": finding.probe.payload_id,
                    "context": finding.context,
                    "confidence": finding.confidence,
                    "hits": [asdict(hit) for hit in finding.probe.hits],
                    "control_hits": (
                        [asdict(hit) for hit in finding.control_probe.hits]
                        if finding.control_probe else None
                    ),
                }
                for result in self.scans
                for finding in result.findings
            ] + [
                {"engine": engine_result["engine"], **finding}
                for engine_result in self.engine_results
                for finding in engine_result.get("findings", [])
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
                            "confidence": item.confidence,
                            "hits": [asdict(hit) for hit in item.probe.hits],
                            "control_hits": (
                                [asdict(hit) for hit in item.control_probe.hits]
                                if item.control_probe else None
                            ),
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


def _api_surfaces_from_map(site_map: SiteMapResult) -> list[AttackSurface]:
    """Select replayable JSON POST APIs with mutable, non-secret scalar leaves."""
    surfaces = []
    sensitive_words = (
        "password", "secret", "token", "credential", "csrf", "api_key",
        "session", "auth", "signature",
    )

    def scalar_paths(value, prefix=()):
        if isinstance(value, dict):
            for key, child in value.items():
                yield from scalar_paths(child, (*prefix, str(key)))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                yield from scalar_paths(child, (*prefix, str(index)))
        elif isinstance(value, (str, int, float, bool)) or value is None:
            if prefix and not any(
                word in part.lower() for part in prefix for word in sensitive_words
            ):
                escaped = [part.replace("~", "~0").replace("/", "~1") for part in prefix]
                yield "/" + "/".join(escaped)

    for endpoint in site_map.endpoints:
        if endpoint.method != "POST" or not endpoint.request_body:
            continue
        if "application/json" not in endpoint.content_type.lower():
            continue
        if not _is_in_scope(endpoint.url, site_map.target):
            continue
        parameters = tuple(sorted(scalar_paths(endpoint.request_body)))
        if not parameters:
            continue
        parent = next(
            (page for page in site_map.pages if page.url == endpoint.source_page),
            None,
        )
        surfaces.append(AttackSurface(
            url=endpoint.url,
            method="POST",
            parameters=parameters,
            behaviour=parent.behaviour if parent else "general",
            source="browser-api",
            request_body=endpoint.request_body,
            headers=endpoint.headers,
            source_page=endpoint.source_page,
            source_interaction=endpoint.trigger,
        ))
    return surfaces


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


def _post_surfaces_from_map(
    site_map: SiteMapResult,
    *,
    include_auth_forms: bool = False,
) -> list[AttackSurface]:
    """Build safe-to-attempt POST form surfaces from mapped metadata.

    Password and file controls are never mutated by this engine. Authentication
    forms are excluded unless the operator separately opts in.
    """
    surfaces: list[AttackSurface] = []
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    for page in site_map.pages:
        if page.behaviour == "authentication" and not include_auth_forms:
            continue
        for form in page.forms:
            if form.get("method", "GET").upper() != "POST":
                continue
            if any(
                field.get("type") == "file"
                for field in form.get("fields", [])
            ):
                continue
            parameters = tuple(sorted({
                field.get("name", "")
                for field in form.get("fields", [])
                if field.get("role") == "injectable"
                and field.get("name")
                and field.get("type") != "password"
            }))
            action = form.get("action", "")
            if not parameters or not action or not _is_in_scope(action, site_map.target):
                continue
            key = (action, page.url, parameters)
            if key in seen:
                continue
            seen.add(key)
            surfaces.append(AttackSurface(
                url=action,
                method="POST",
                parameters=parameters,
                behaviour=page.behaviour,
                source="discovered-form",
                form_page=page.url,
            ))
    return surfaces


async def scan_website(
    base_url: str,
    *,
    proxy: str | None = None,
    budget: int = 300,
    max_pages: int = 100,
    max_depth: int = 3,
    headless: bool = True,
    active_post: bool = False,
    active_api: bool = False,
    include_auth_forms: bool = False,
    storage_state: str | None = None,
    interaction_limit: int = 3,
    progress=None,
) -> WebsiteScanResult:
    """Map a site and run selected engines against discovered input surfaces.

    POST forms require explicit opt-in. Testing reuses the live browser session
    and reloads the source form before each submission to refresh CSRF fields.
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
        request_filter=_mapping_request_allowed,
        storage_state=storage_state,
    )
    test_pacer: Pacer | None = None
    try:
        if progress:
            progress(f"[bold cyan]Discovery phase[/bold cyan] Mapping {base_url}; page limit {max_pages}, depth limit {max_depth}, discovery budget {mapping_budget}")
        site_map = await map_site(
            base_url,
            proxy=proxy,
            budget=mapping_budget,
            max_pages=max_pages,
            max_depth=max_depth,
            headless=headless,
            _client=client,
            _pacer=mapping_pacer,
            interaction_limit=interaction_limit,
            progress=progress,
        )
        if progress:
            progress(f"[bold green]Discovery summary[/bold green] {len(site_map.pages)} pages, {len(site_map.endpoints)} browser API endpoints, {site_map.interactions_attempted} UI steps; {site_map.requests_used}/{mapping_budget} requests used")
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
        post_surfaces = (
            _post_surfaces_from_map(
                site_map, include_auth_forms=include_auth_forms
            )
            if active_post else []
        )
        api_surfaces = _api_surfaces_from_map(site_map) if active_api else []
        result.post_forms_tested = len(post_surfaces)
        result.skipped_post_forms = max(
            0, result.skipped_post_forms - result.post_forms_tested
        ) if active_post else result.skipped_post_forms
        result.post_apis_tested = len(api_surfaces)
        result.skipped_post_apis = max(
            0, result.skipped_post_endpoints - result.post_apis_tested
        ) if active_api else result.skipped_post_endpoints
        surfaces = [_surface_for(target, site_map) for target in targets]
        surfaces.extend(post_surfaces)
        surfaces.extend(api_surfaces)
        remaining = max(0, budget - mapping_pacer.used)

        if remaining:
            test_pacer = Pacer(budget=remaining)
            client.request_guard = test_pacer.reserve
            # The mapping stage may have exhausted its own allowance. The
            # testing stage gets a fresh allowance, but keeps the same browser
            # context, cookies, and page instrumentation.
            client.budget_exhausted = False

        registry = default_registry()
        if progress:
            progress(f"[bold cyan]Planning complete[/bold cyan] {len(targets)} GET targets + {len(post_surfaces)} opted-in POST forms + {len(api_surfaces)} opted-in JSON APIs = {len(surfaces)} surfaces; {remaining} testing requests available")
        for index, surface in enumerate(surfaces, start=1):
            target = surface.url
            if progress:
                progress(f"[yellow]Target {index}/{len(surfaces)}[/yellow] {surface.method} {target}")
            if remaining <= 0 or test_pacer is None:
                result.budget_exhausted = True
                break
            engines = registry.select(surface)
            if not engines and progress:
                progress(f"[dim]No compatible engine[/dim] {surface.method} {target} — no supported input test for this surface")
            for engine in engines:
                if progress:
                    progress(f"[bold yellow]Running[/bold yellow] {engine.engine_id} against {surface.method} {target}")
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
                elif hasattr(engine_result, "to_dict"):
                    result.engine_results.append({
                        "engine": engine.engine_id,
                        **engine_result.to_dict(),
                    })
                result.tested_targets.append(target)
                if progress:
                    progress(f"[green]Finished[/green] {engine.engine_id} on {target} ({engine_result.requests_used} requests; {test_pacer.remaining} testing requests remain)")
                remaining = max(0, remaining - engine_result.requests_used)
                if engine_result.budget_exhausted:
                    result.budget_exhausted = True
                    break
            if result.budget_exhausted:
                break

        if progress:
            progress(f"[bold green]Testing phase complete[/bold green] {len(result.tested_targets)} target/engine runs; {test_pacer.used if test_pacer else 0} testing requests used")
        result.requests_used = mapping_pacer.used + (
            test_pacer.used if test_pacer else 0
        )
        result.budget_exhausted = result.budget_exhausted or remaining == 0
        return result
    finally:
        await client.close()
