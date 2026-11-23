"""Orchestration: reflection discovery -> browser-confirmed execution."""
from dataclasses import dataclass, field
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
import hashlib
import logging

from hx.client import TargetClient
from hx.oracle import (
    probe, probe_post_form, probe_post_json, ORACLE_INIT_JS,
    ProbeResult, make_payload_id,
)
from hx.fastpath import FastPath, Candidate
from hx.pacer import Pacer, BudgetExhausted
from hx.payloads import detect_context, payloads_for
from hx.fingerprint import check_fingerprint_match

log = logging.getLogger("hx")


@dataclass
class Finding:
    param: str
    url: str
    payload: str
    probe: ProbeResult
    context: str = "unknown"


@dataclass
class RequestSpec:
    method: str = "GET"
    url: str = ""
    form: dict[str, str] | None = None
    json_body: dict | None = None


@dataclass
class ScanResult:
    target: str
    reached_app: bool
    reflections: list[Candidate] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    budget_exhausted: bool = False
    requests_used: int = 0
    fingerprint: dict = field(default_factory=dict)


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


def _apply_marker(spec: RequestSpec, param: str, value: str) -> RequestSpec:
    if spec.method == "GET":
        return RequestSpec(method="GET", url=_with_param(spec.url, param, value))
    if spec.method == "POST":
        form = dict(spec.form or {})
        form[param] = value
        return RequestSpec(method="POST", url=spec.url, form=form)
    if spec.method == "JSON":
        body = dict(spec.json_body or {})
        body[param] = value
        return RequestSpec(method="JSON", url=spec.url, json_body=body)
    raise ValueError(f"unknown method {spec.method}")


async def scan(target: str | RequestSpec, *, proxy: str | None = None,
               budget: int = 120, headless: bool = True) -> ScanResult:
    spec = target if isinstance(target, RequestSpec) else RequestSpec(method="GET", url=target)
    parsed = urlparse(spec.url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    if spec.method == "GET":
        params = list(parse_qs(parsed.query, keep_blank_values=True).keys())
        fragment_params = list(_fragment_query(parsed.fragment).keys())
    elif spec.method == "POST":
        params = list((spec.form or {}).keys())
        fragment_params = []
    elif spec.method == "JSON":
        params = list((spec.json_body or {}).keys())
        fragment_params = []
    else:
        raise ValueError(f"unknown method {spec.method}")

    result = ScanResult(target=spec.url, reached_app=False)
    pacer = Pacer(budget=budget)
    client = TargetClient(origin, proxy=proxy)
    await client.start(
        oracle_init_script=ORACLE_INIT_JS,
        request_guard=pacer.reserve,
        headless=headless,
    )
    try:
        await pacer.pause()
        reached = await client.warm()
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
            probe_spec = _apply_marker(spec, param, marker)
            await pacer.pause()
            if probe_spec.method == "GET":
                c = fp.find_reflection(probe_spec.url, marker, cookies)
                body = fp.fetch_body(probe_spec.url, cookies) if c else ""
            elif probe_spec.method == "POST":
                c = fp.find_reflection_post_form(
                    probe_spec.url, probe_spec.form or {}, marker, cookies
                )
                body = fp.fetch_body_post_form(
                    probe_spec.url, probe_spec.form or {}, cookies
                ) if c else ""
            else:
                c = fp.find_reflection_post_json(
                    probe_spec.url, probe_spec.json_body or {}, marker, cookies
                )
                body = fp.fetch_body_post_json(
                    probe_spec.url, probe_spec.json_body or {}, cookies
                ) if c else ""
            if c:
                c.param = param
                result.reflections.append(c)
                candidates.append((param, c, body, "http"))

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

        # Prove only candidates that actually reflected in the relevant context.
        for param, cand, body, source in candidates:
            det = detect_context(body, cand.offset)
            payload_templates = payloads_for(det.context)
            for payload_index in range(len(payload_templates)):
                payload_id = make_payload_id()
                payload = payloads_for(
                    det.context, pid_marker=payload_id
                )[payload_index]
                if source == "fragment":
                    payload_url = _with_fragment_param(spec.url, param, payload)
                    payload_spec = RequestSpec(method="GET", url=payload_url)
                else:
                    payload_spec = _apply_marker(spec, param, payload)
                await pacer.pause()
                if payload_spec.method == "GET":
                    pr = await probe(
                        client.page, payload_spec.url, payload,
                        payload_id=payload_id,
                    )
                elif payload_spec.method == "POST":
                    pr = await probe_post_form(
                        client.page, payload_spec.url, payload_spec.form or {},
                        payload_id=payload_id,
                    )
                else:
                    pr = await probe_post_json(
                        client.page, payload_spec.url,
                        payload_spec.json_body or {}, payload_id=payload_id,
                    )
                if client.budget_exhausted:
                    raise BudgetExhausted(
                        "request budget exhausted during browser oracle probe"
                    )
                if pr.proven:
                    result.findings.append(Finding(
                        param=param, url=payload_spec.url, payload=payload,
                        probe=pr, context=det.context.value,
                    ))
                    break

        result.requests_used = pacer.used
        return result
    except BudgetExhausted:
        result.budget_exhausted = True
        result.requests_used = pacer.used
        return result
    finally:
        result.requests_used = pacer.used
        result.budget_exhausted = (
            result.budget_exhausted or pacer.exhausted or client.budget_exhausted
        )
        await client.close()
