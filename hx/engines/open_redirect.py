"""HTTP Location-header open-redirect detection.

The engine sends one canary GET per recognized redirect parameter and never
follows the response. A finding requires the target to return an HTTP redirect
to hx's reserved .invalid canary host.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from hx.engines.base import AttackSurface, EngineContext
from hx.fastpath import FastPath
from hx.pacer import BudgetExhausted


REDIRECT_PARAMETERS = {
    "next", "url", "redirect", "redirect_url", "redirect_uri",
    "return", "return_url", "returnto", "return_to", "continue",
    "dest", "destination", "target", "goto", "out", "view",
    "callback", "success", "failure", "cancel", "to", "link",
    "forward", "forward_url",
}
CANARY_HOST = "hx.invalid"
CANARY_PATH = "/hx-open-redirect-check"


@dataclass
class OpenRedirectFinding:
    parameter: str
    tested_url: str
    status: int
    location: str
    destination: str
    evidence: str


@dataclass
class OpenRedirectResult:
    target: str
    findings: list[OpenRedirectFinding] = field(default_factory=list)
    requests_used: int = 0
    budget_exhausted: bool = False
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "requests_used": self.requests_used,
            "budget_exhausted": self.budget_exhausted,
            "errors": self.errors,
            "findings": [asdict(item) for item in self.findings],
        }


def _with_query_value(url: str, name: str, value: str) -> str:
    parts = urlsplit(url)
    query = [(key, current) for key, current in parse_qsl(
        parts.query, keep_blank_values=True
    ) if key != name]
    query.append((name, value))
    return urlunsplit(parts._replace(query=urlencode(query, doseq=True)))


class OpenRedirectEngine:
    engine_id = "open_redirect"

    def supports(self, surface: AttackSurface) -> bool:
        query_parameters = {
            name for name, _ in parse_qsl(
                urlsplit(surface.url).query, keep_blank_values=True
            )
        }
        return (
            surface.method.upper() == "GET"
            and any(name.lower() in REDIRECT_PARAMETERS for name in query_parameters)
        )

    async def run(
        self, surface: AttackSurface, context: EngineContext
    ) -> OpenRedirectResult:
        result = OpenRedirectResult(target=surface.url)
        start_used = context.pacer.used if context.pacer else 0
        parsed = urlsplit(surface.url)
        if not parsed.hostname:
            return result

        client = FastPath(
            proxy=context.proxy,
            request_guard=context.pacer.reserve if context.pacer else None,
        )
        client.set_allowed_domains({parsed.hostname})
        cookies = await context.client.cookies() if context.client else []
        canary = f"https://{CANARY_HOST}{CANARY_PATH}"

        try:
            query_parameters = {
                name for name, _ in parse_qsl(
                    urlsplit(surface.url).query, keep_blank_values=True
                )
            }
            for parameter in query_parameters:
                if parameter.lower() not in REDIRECT_PARAMETERS:
                    continue
                tested_url = _with_query_value(surface.url, parameter, canary)
                status, location = client.inspect_redirect(tested_url, cookies)
                if status not in (301, 302, 303, 307, 308) or not location:
                    continue
                destination = urljoin(tested_url, location)
                destination_parts = urlsplit(destination)
                if (
                    destination_parts.scheme in ("http", "https")
                    and destination_parts.hostname == CANARY_HOST
                ):
                    result.findings.append(OpenRedirectFinding(
                        parameter=parameter,
                        tested_url=tested_url,
                        status=status,
                        location=location,
                        destination=destination,
                        evidence=(
                            f"HTTP {status} Location header points to "
                            f"{destination}"
                        ),
                    ))
        except BudgetExhausted:
            result.budget_exhausted = True
        except Exception as exc:
            result.errors.append(f"{type(exc).__name__}: {str(exc)[:160]}")
        finally:
            result.requests_used = (
                context.pacer.used - start_used if context.pacer else 0
            )
        return result
