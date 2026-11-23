"""Automated website scan orchestration.

Discovery and vulnerability testing remain separate: the mapper is read-only,
while this coordinator turns discovered, low-risk GET input surfaces into
explicit requests for the existing XSS scanner. Additional vulnerability
engines can be plugged into this orchestration without changing the crawler.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

from hx.scanner import ScanResult, scan
from hx.site_mapper import SiteMapResult, _is_in_scope, _page_key, map_site


@dataclass
class WebsiteScanResult:
    target: str
    site_map: SiteMapResult
    scans: list[ScanResult] = field(default_factory=list)
    tested_targets: list[str] = field(default_factory=list)
    skipped_post_forms: int = 0
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
            "requests_used": self.requests_used,
            "budget_exhausted": self.budget_exhausted,
            "scans": [
                {
                    "target": result.target,
                    "reached_app": result.reached_app,
                    "requests_used": result.requests_used,
                    "budget_exhausted": result.budget_exhausted,
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


def _targets_from_map(site_map: SiteMapResult) -> tuple[list[str], int]:
    targets: list[str] = []
    seen: set[str] = set()
    skipped_post_forms = 0

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

    return targets, skipped_post_forms


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
    site_map = await map_site(
        base_url, proxy=proxy, budget=budget,
        max_pages=max_pages, max_depth=max_depth, headless=headless,
    )
    result = WebsiteScanResult(target=base_url, site_map=site_map)
    targets, result.skipped_post_forms = _targets_from_map(site_map)
    remaining = max(0, budget - site_map.requests_used)

    for target in targets:
        if remaining <= 0:
            result.budget_exhausted = True
            break
        scan_result = await scan(
            target, proxy=proxy, budget=remaining, headless=headless,
        )
        result.scans.append(scan_result)
        result.tested_targets.append(target)
        remaining = max(0, remaining - scan_result.requests_used)
        if scan_result.budget_exhausted:
            result.budget_exhausted = True
            break

    result.requests_used = budget - remaining
    result.budget_exhausted = (
        result.budget_exhausted
        or site_map.budget_exhausted
        or remaining == 0
    )
    return result
