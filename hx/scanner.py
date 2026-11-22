"""Orchestration: warm -> fast-path reflection map -> browser probe on candidates.

Separation of concerns is load-bearing:
  - fast path finds reflections (cheap, many requests, pacer-gated)
  - browser proves execution (expensive, few requests, pacer-gated)
The scanner only reports a finding when the browser oracle proves it.
"""
from dataclasses import dataclass, field
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
import hashlib

from hx.client import TargetClient
from hx.oracle import (
    probe,
    probe_post_form,
    probe_post_json,
    ORACLE_INIT_JS,
    ProbeResult,
    make_payload_id,
)
from hx.fastpath import FastPath, Candidate
from hx.pacer import Pacer, BudgetExhausted
from hx.payloads import detect_context, payloads_for
from hx.fingerprint import check_fingerprint_match
import logging

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
    elif spec.method == "POST":
        params = list((spec.form or {}).keys())
    elif spec.method == "JSON":
        params = list((spec.json_body or {}).keys())
    else:
        raise ValueError(f"unknown method {spec.method}")

    result = ScanResult(target=spec.url, reached_app=False)
    pacer = Pacer(budget=budget)

    client = TargetClient(origin, proxy=proxy)
    await client.start(
        oracle_init_script=ORACLE_INIT_JS,
        request_guard=pacer.reserve,
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
        fp.set_allowed_domains({parsed.netloc.split(":")[0]})
        fp_check = await check_fingerprint_match(client.page, fp.impersonate)
        result.fingerprint = {
            "browser": fp_check.browser_version,
            "impersonate": fp_check.impersonate_version,
            "matches": fp_check.matches,
            "warning": fp_check.warning,
        }
        if fp_check.warning:
            log.warning(fp_check.warning)

        # Phase A: cheap reflection mapping with unique markers
        candidates: list[tuple[str, Candidate, str]] = []
        for param in params:
            marker = _marker_for(param)
            probe_spec = _apply_marker(spec, param, marker)
            await pacer.pause()
            if probe_spec.method == "GET":
                c = fp.find_reflection(probe_spec.url, marker, cookies)
                if c:
                    await pacer.pause()
                    body = fp.fetch_body(probe_spec.url, cookies)
                else:
                    body = ""
            elif probe_spec.method == "POST":
                c = fp.find_reflection_post_form(
                    probe_spec.url, probe_spec.form or {}, marker, cookies
                )
                if c:
                    await pacer.pause()
                    body = fp.fetch_body_post_form(
                        probe_spec.url, probe_spec.form or {}, cookies
                    )
                else:
                    body = ""
            else:
                c = fp.find_reflection_post_json(
                    probe_spec.url, probe_spec.json_body or {}, marker, cookies
                )
                if c:
                    await pacer.pause()
                    body = fp.fetch_body_post_json(
                        probe_spec.url, probe_spec.json_body or {}, cookies
                    )
                else:
                    body = ""
            if c:
                result.reflections.append(c)
                candidates.append((param, c, body))

        # Phase B: prove only reflected params with context-aware payloads
        for param, cand, body in candidates:
            det = detect_context(body, cand.offset)

            payload_templates = payloads_for(det.context)
            for payload_index in range(len(payload_templates)):
                payload_id = make_payload_id()
                payload = payloads_for(
                    det.context, pid_marker=payload_id
                )[payload_index]
                payload_spec = _apply_marker(spec, param, payload)
                await pacer.pause()
                if payload_spec.method == "GET":
                    pr = await probe(
                        client.page, payload_spec.url, payload,
                        payload_id=payload_id,
                    )
                    finding_url = payload_spec.url
                elif payload_spec.method == "POST":
                    pr = await probe_post_form(
                        client.page, payload_spec.url, payload_spec.form or {},
                        payload_id=payload_id,
                    )
                    finding_url = payload_spec.url
                else:
                    pr = await probe_post_json(
                        client.page,
                        payload_spec.url,
                        payload_spec.json_body or {},
                        payload_id=payload_id,
                    )
                    finding_url = payload_spec.url
                if client.budget_exhausted:
                    raise BudgetExhausted(
                        "request budget exhausted during browser oracle probe"
                    )
                if pr.proven:
                    result.findings.append(Finding(
                        param=param,
                        url=finding_url,
                        payload=payload,
                        probe=pr,
                        context=det.context.value,
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
            result.budget_exhausted
            or pacer.exhausted
            or client.budget_exhausted
        )
        await client.close()