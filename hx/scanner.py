"""Orchestration: reflection discovery -> browser-confirmed execution."""
from dataclasses import asdict, dataclass, field, replace
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
import hashlib
import copy
import logging

from hx.client import TargetClient
from hx.oracle import (
    probe, probe_post_form, probe_post_json, probe_post_form_from_page,
    submit_form_from_page, ORACLE_INIT_JS,
    ProbeResult, make_payload_id, refresh_api_headers, submit_json_from_page,
)
from hx.fastpath import FastPath, Candidate
from hx.pacer import Pacer, BudgetExhausted
from hx.payloads import detect_context, payloads_for, control_payload_for
from hx.fingerprint import check_fingerprint_match

log = logging.getLogger("hx")


@dataclass
class Finding:
    param: str
    url: str
    payload: str
    probe: ProbeResult
    context: str = "unknown"
    confidence: str = "proven_execution"
    control_probe: ProbeResult | None = None


@dataclass
class Coverage:
    params_discovered: int = 0
    params_tested: int = 0
    params_skipped: int = 0
    skip_reasons: dict[str, int] = field(default_factory=dict)
    reflections: int = 0
    contexts: dict[str, int] = field(default_factory=dict)
    findings_proven: int = 0
    findings_uncontrolled: int = 0
    blocked: int = 0
    blocked_detail: list[str] = field(default_factory=list)
    budget_used: int = 0
    budget_limit: int = 0
    budget_exhausted: bool = False
    requests_unaccounted: int = 0


@dataclass
class RequestSpec:
    method: str = "GET"
    url: str = ""
    form: dict[str, str] | None = None
    json_body: dict | None = None
    form_page: str | None = None
    parameters: tuple[str, ...] | None = None
    source_page: str | None = None
    source_interaction: list[dict] | None = None
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)


@dataclass
class ScanResult:
    target: str
    reached_app: bool
    reflections: list[Candidate] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    budget_exhausted: bool = False
    requests_used: int = 0
    fingerprint: dict = field(default_factory=dict)
    coverage: Coverage = field(default_factory=Coverage)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "reached_app": self.reached_app,
            "requests_used": self.requests_used,
            "budget_exhausted": self.budget_exhausted,
            "fingerprint": self.fingerprint,
            "coverage": asdict(self.coverage),
            "reflections": [asdict(item) for item in self.reflections],
            "findings": [
                {
                    "param": item.param,
                    "url": item.url,
                    "payload": item.payload,
                    "payload_id": item.probe.payload_id,
                    "context": item.context,
                    "confidence": item.confidence,
                    "engine": getattr(item, "engine", "xss"),
                    "hits": [asdict(hit) for hit in item.probe.hits],
                }
                for item in self.findings
            ],
        }


def _marker_for(param: str) -> str:
    h = hashlib.sha256(param.encode()).hexdigest()[:10]
    return f"hxrefl{h}"


def _fragment_query(fragment: str) -> dict[str, list[str]]:
    """Extract query parameters from a client-side route fragment."""
    route = fragment.lstrip("#")
    if "?" in route:
        query = route.split("?", 1)[1]
    elif "=" in route or "&" in route:
        query = route
    else:
        return {}
    return parse_qs(query, keep_blank_values=True)


def _with_fragment_param(url: str, param: str, value: str) -> str:
    """Replace one fragment parameter while preserving the client-side route."""
    parts = urlparse(url)
    route = parts.fragment.lstrip("#")
    if "?" in route:
        prefix, query = route.split("?", 1)
        prefix += "?"
    elif "=" in route or "&" in route:
        prefix, query = "", route
    else:
        prefix, query = (route + "?", "") if route else ("", "")
    values = parse_qs(query, keep_blank_values=True)
    values[param] = [value]
    fragment = prefix + urlencode(values, doseq=True)
    return urlunparse(parts._replace(fragment=fragment))


def _with_param(url: str, param: str, value: str) -> str:
    parts = urlparse(url)
    q = parse_qs(parts.query, keep_blank_values=True)
    q[param] = [value]
    return urlunparse(parts._replace(query=urlencode(q, doseq=True)))


def _json_pointer_parts(pointer: str) -> list[str]:
    if not pointer.startswith("/"):
        raise ValueError(f"invalid JSON pointer: {pointer}")
    return [
        part.replace("~1", "/").replace("~0", "~")
        for part in pointer[1:].split("/")
    ]


def _set_json_pointer(document: dict, pointer: str, value):
    """Replace an existing JSON scalar addressed by an RFC 6901 pointer."""
    parts = _json_pointer_parts(pointer)
    current = document
    for part in parts[:-1]:
        if isinstance(current, list):
            current = current[int(part)]
        else:
            current = current[part]
    final = parts[-1]
    if isinstance(current, list):
        current[int(final)] = value
    else:
        if final not in current:
            raise KeyError(pointer)
        current[final] = value
    return document


def _apply_marker(spec: RequestSpec, param: str, value: str) -> RequestSpec:
    if spec.method == "GET":
        return replace(spec, url=_with_param(spec.url, param, value))
    if spec.method == "POST":
        form = dict(spec.form or {})
        form[param] = value
        return replace(spec, form=form)
    if spec.method == "JSON":
        body = copy.deepcopy(spec.json_body or {})
        _set_json_pointer(body, param, value)
        return replace(spec, json_body=body)
    raise ValueError(f"unknown method {spec.method}")


def _normalize_request_state(spec: RequestSpec) -> RequestSpec:
    """Move any explicit Cookie header into the shared cookie source."""
    headers = dict(spec.headers or {})
    cookies = dict(spec.cookies or {})
    header_cookies: dict[str, str] = {}
    for key in list(headers):
        if key.lower() != "cookie":
            continue
        raw = headers.pop(key)
        for pair in raw.split(";"):
            name, separator, value = pair.strip().partition("=")
            if not separator or not name.strip():
                raise ValueError("malformed Cookie header; expected name=value pairs")
            header_cookies[name.strip()] = value.strip()
    conflicts = header_cookies.keys() & cookies.keys()
    if conflicts:
        log.debug(
            "RequestSpec.cookies override Cookie header values for: %s",
            ", ".join(sorted(conflicts)),
        )
    return replace(
        spec,
        headers=headers,
        cookies={**header_cookies, **cookies},
    )


async def _run_probe(
    client: TargetClient,
    spec: RequestSpec,
    param: str,
    payload: str,
    payload_id: str,
    source: str,
) -> tuple[ProbeResult, str]:
    """Run one payload through the browser oracle for its input transport."""
    if source == "fragment":
        payload_url = _with_fragment_param(spec.url, param, payload)
        result = await probe(
            client.page, payload_url, payload, payload_id=payload_id
        )
        return result, payload_url

    payload_spec = _apply_marker(spec, param, payload)
    if payload_spec.method == "GET":
        result = await probe(
            client.page, payload_spec.url, payload, payload_id=payload_id
        )
    elif payload_spec.method == "POST" and spec.form_page:
        result = await probe_post_form_from_page(
            client.page, spec.form_page, payload_spec.url, param, payload,
            payload_id=payload_id,
        )
    elif payload_spec.method == "POST":
        result = await probe_post_form(
            client.page, payload_spec.url, payload_spec.form or {},
            payload_id=payload_id,
        )
    else:
        result = await probe_post_json(
            client.page, payload_spec.url, payload_spec.json_body or {},
            payload_id=payload_id, headers=payload_spec.headers,
            source_page=payload_spec.source_page,
            source_interaction=payload_spec.source_interaction,
        )
    return result, payload_spec.url


async def scan(target: str | RequestSpec, *, proxy: str | None = None,
               budget: int = 120, headless: bool = True,
               _client: TargetClient | None = None,
               _pacer: Pacer | None = None,
               _warm: bool = True,
               storage_state: str | None = None) -> ScanResult:
    spec = target if isinstance(target, RequestSpec) else RequestSpec(method="GET", url=target)
    spec = _normalize_request_state(spec)
    parsed = urlparse(spec.url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    if spec.method == "GET":
        params = list(parse_qs(parsed.query, keep_blank_values=True).keys())
        fragment_params = list(_fragment_query(parsed.fragment).keys())
    elif spec.method == "POST":
        params = list((spec.form or {}).keys())
        fragment_params = []
    elif spec.method == "JSON":
        params = list(spec.parameters or (spec.json_body or {}).keys())
        fragment_params = []
    else:
        raise ValueError(f"unknown method {spec.method}")

    result = ScanResult(target=spec.url, reached_app=False)
    result.coverage.params_discovered = len(params) + len(fragment_params)
    pacer = _pacer or Pacer(budget=budget)
    owns_client = _client is None
    client = _client or TargetClient(origin, proxy=proxy)
    browser_headers = (
        {} if spec.method == "JSON" and spec.source_page else spec.headers
    )
    client.request_guard = pacer.reserve
    unaccounted_start = client.requests_unaccounted
    request_start = pacer.used
    def record_blocked(status: int, method: str, url: str) -> None:
        if status not in (401, 403, 429) and status < 500:
            return
        path = urlparse(url).path or "/"
        detail = f"{method} {path} -> {status}"
        if detail not in result.coverage.blocked_detail:
            result.coverage.blocked_detail.append(detail)
            result.coverage.blocked += 1
    if owns_client:
        await client.start(
            oracle_init_script=ORACLE_INIT_JS,
            request_guard=client.request_guard,
            headless=headless,
            storage_state=storage_state,
            headers=browser_headers,
            cookies=spec.cookies,
        )
    else:
        await client.configure_request_state(browser_headers, spec.cookies)
    try:
        if _warm:
            await pacer.pause()
            reached = await client.warm()
        else:
            reached = True
        result.reached_app = reached
        if not reached:
            return result
        if client.budget_exhausted:
            raise BudgetExhausted("request budget exhausted during browser warm-up")

        cookies = await client.cookies()
        fp = FastPath(proxy=proxy, request_guard=pacer.reserve)
        fp.set_allowed_domains({parsed.hostname or ""})
        fp_check = await check_fingerprint_match(client.page, fp.impersonate)
        result.fingerprint = {
            "browser": fp_check.browser_version,
            "impersonate": fp_check.impersonate_version,
            "matches": fp_check.matches,
            "warning": fp_check.warning,
        }
        if fp_check.warning:
            log.warning(fp_check.warning)

        # Server-visible parameters use the HTTP fast path.
        candidates: list[tuple[str, Candidate, str, str]] = []
        for param in params:
            marker = _marker_for(param)
            if spec.method == "JSON" and spec.source_page:
                # These headers belong to the replayed API call, not the page
                # navigation. Refresh them from the live source-page request.
                await client.configure_request_state({}, spec.cookies)
                refreshed = await refresh_api_headers(
                    client.page, spec.source_page, spec.url,
                    interaction=spec.source_interaction,
                )
                if refreshed:
                    spec.headers = {**(spec.headers or {}), **refreshed}
                    cookies = await client.cookies()
            probe_spec = _apply_marker(spec, param, marker)
            await pacer.pause()
            if probe_spec.method == "GET":
                c = fp.find_reflection(
                    probe_spec.url, marker, cookies,
                    headers=probe_spec.headers,
                    spec_cookies=probe_spec.cookies,
                )
                body = fp.fetch_body(
                    probe_spec.url, cookies,
                    headers=probe_spec.headers,
                    spec_cookies=probe_spec.cookies,
                ) if c else ""
            elif probe_spec.method == "POST" and spec.form_page:
                body = await submit_form_from_page(
                    client.page, spec.form_page, probe_spec.url, param, marker
                )
                if client.budget_exhausted:
                    raise BudgetExhausted("request budget exhausted during POST form discovery")
                offset = body.find(marker)
                c = Candidate(
                    url=probe_spec.url, marker=marker, offset=offset,
                    status=200, param=param,
                ) if offset >= 0 else None
            elif probe_spec.method == "POST":
                c = fp.find_reflection_post_form(
                    probe_spec.url, probe_spec.form or {}, marker, cookies,
                    headers=probe_spec.headers,
                    spec_cookies=probe_spec.cookies,
                )
                body = fp.fetch_body_post_form(
                    probe_spec.url, probe_spec.form or {}, cookies,
                    headers=probe_spec.headers,
                    spec_cookies=probe_spec.cookies,
                ) if c else ""
            elif probe_spec.method == "JSON" and spec.source_page:
                body = await submit_json_from_page(
                    client.page, probe_spec.url, probe_spec.json_body or {},
                    headers=probe_spec.headers,
                )
                offset = body.find(marker)
                c = Candidate(
                    url=probe_spec.url, marker=marker, offset=offset,
                    status=200, param=param,
                ) if offset >= 0 else None
            else:
                c = fp.find_reflection_post_json(
                    probe_spec.url, probe_spec.json_body or {}, marker, cookies,
                    headers=probe_spec.headers,
                    spec_cookies=probe_spec.cookies,
                )
                body = fp.fetch_body_post_json(
                    probe_spec.url, probe_spec.json_body or {}, cookies,
                    headers=probe_spec.headers,
                    spec_cookies=probe_spec.cookies,
                ) if c else ""
            if fp.last_status is not None:
                record_blocked(
                    fp.last_status,
                    probe_spec.method,
                    probe_spec.url,
                )
            if c:
                c.param = param
                result.reflections.append(c)
                candidates.append((
                    param, c, body,
                    "browser-post-form" if probe_spec.method == "POST" and spec.form_page else "http",
                ))
            result.coverage.params_tested += 1

        # Fragment values are browser-only: browsers do not send fragments over HTTP.
        for param in fragment_params:
            marker = _marker_for(param)
            marker_url = _with_fragment_param(spec.url, param, marker)
            await pacer.pause()
            try:
                await client.page.goto(
                    marker_url, wait_until="domcontentloaded", timeout=15000
                )
            except Exception:
                pass
            body = await client.page.content()
            offset = body.find(marker)
            if offset >= 0:
                c = Candidate(
                    url=marker_url, marker=marker, offset=offset,
                    status=200, param=param,
                )
                result.reflections.append(c)
                candidates.append((param, c, body, "fragment"))
            result.coverage.params_tested += 1

        # Prove only candidates that actually reflected in the relevant context.
        for param, cand, body, source in candidates:
            det = detect_context(body, cand.offset)
            result.coverage.reflections += 1
            result.coverage.contexts[det.context.value] = (
                result.coverage.contexts.get(det.context.value, 0) + 1
            )
            payload_templates = payloads_for(det.context)
            for payload_index in range(len(payload_templates)):
                payload_id = make_payload_id()
                payload = payloads_for(
                    det.context, pid_marker=payload_id
                )[payload_index]
                await pacer.pause()
                pr, payload_url = await _run_probe(
                    client, spec, param, payload, payload_id, source
                )
                if client.budget_exhausted:
                    raise BudgetExhausted(
                        "request budget exhausted during browser oracle probe"
                    )
                if not pr.proven:
                    continue

                # A positive execution must survive a paired benign control.
                # Reusing the proof ID means stale/persisted execution from the
                # active probe is visible during the control and is not silently
                # attributed as a fresh differential result.
                control_payload = control_payload_for(payload)
                if control_payload is None:
                    result.findings.append(Finding(
                        param=param, url=payload_url, payload=payload,
                        probe=pr, context=det.context.value,
                        confidence="executed_without_control",
                    ))
                    result.coverage.findings_uncontrolled += 1
                    break

                await pacer.pause()
                control_pr, _ = await _run_probe(
                    client, spec, param, control_payload, payload_id, source
                )
                if client.budget_exhausted:
                    result.findings.append(Finding(
                        param=param, url=payload_url, payload=payload,
                        probe=pr, context=det.context.value,
                        confidence="executed_without_control",
                    ))
                    result.coverage.findings_uncontrolled += 1
                    raise BudgetExhausted(
                        "request budget exhausted during differential control"
                    )
                if not control_pr.proven:
                    result.findings.append(Finding(
                        param=param, url=payload_url, payload=payload,
                        probe=pr, context=det.context.value,
                        confidence="proven_execution",
                        control_probe=control_pr,
                    ))
                    result.coverage.findings_proven += 1
                    break

        result.requests_used = pacer.used - request_start
        return result
    except BudgetExhausted:
        result.budget_exhausted = True
        result.requests_used = pacer.used - request_start
        return result
    finally:
        result.requests_used = pacer.used - request_start
        result.budget_exhausted = (
            result.budget_exhausted or pacer.exhausted or client.budget_exhausted
        )
        result.coverage.budget_used = pacer.used - request_start
        result.coverage.budget_limit = pacer.budget
        result.coverage.budget_exhausted = result.budget_exhausted
        result.coverage.requests_unaccounted = (
            client.requests_unaccounted - unaccounted_start
        )
        accounted = (
            result.coverage.params_tested
            + result.coverage.params_skipped
        )
        missing = result.coverage.params_discovered - accounted
        if missing > 0:
            result.coverage.params_skipped += missing
            reason = "budget" if result.budget_exhausted else "static"
            result.coverage.skip_reasons[reason] = (
                result.coverage.skip_reasons.get(reason, 0) + missing
            )
        elif missing < 0:
            result.coverage.params_skipped = max(
                0, result.coverage.params_skipped
            )
        if owns_client:
            await client.close()
