"""curl_cffi fast path for volume probing.

IMPORTANT: the fast path CANNOT prove XSS. It only detects that payload
bytes appear in the response body (a 'candidate'). Proof stays in the
browser oracle. Never let this module emit a 'found' — only 'candidate'.

cf_clearance handoff gotcha: the cookie is bound to (IP, UA, TLS fingerprint).
The impersonation profile MUST match the Playwright Chromium version, or the
cookie is invalidated -> 403. Pin both to the same chrome version string.
"""
from dataclasses import dataclass
from curl_cffi import requests as cffi
from hx.versions import CURL_CFFI_IMPERSONATE


@dataclass
class Candidate:
    url: str
    marker: str          # the unique string we searched for
    offset: int          # where it appeared in the body
    status: int


class FastPath:
    def __init__(self, impersonate: str = CURL_CFFI_IMPERSONATE, proxy: str | None = None,
                 request_guard=None):
        self.impersonate = impersonate
        self.request_guard = request_guard
        self.proxies = {"https": proxy, "http": proxy} if proxy else None
        self._allowed_domains: set[str] = set()

    def _reserve_request(self) -> None:
        if self.request_guard:
            self.request_guard()

    def _cookies(self, browser_cookies: list[dict]) -> dict:
        return {c["name"]: c["value"] for c in browser_cookies
                if c.get("domain", "").lstrip(".") in self._allowed_domains}

    def set_allowed_domains(self, domains: set[str]):
        # e.g. {"localhost", "example.com"} — derived from the target origin
        self._allowed_domains = {d.lstrip(".") for d in domains}

    def fetch_body(self, url: str, browser_cookies: list[dict]) -> str:
        """Fetch a response body for context detection; never prove execution."""
        self._reserve_request()
        r = cffi.get(
            url,
            impersonate=self.impersonate,
            cookies=self._cookies(browser_cookies) if browser_cookies else None,
            proxies=self.proxies,
            http_version="v1",
            timeout=15,
            allow_redirects=False,
        )
        return r.text or ""

    def find_reflection_post_form(self, url: str, fields: dict[str, str],
                                  marker: str,
                                  browser_cookies: list[dict]) -> Candidate | None:
        self._reserve_request()
        r = cffi.post(
            url,
            data=fields,
            impersonate=self.impersonate,
            cookies=self._cookies(browser_cookies) if browser_cookies else None,
            proxies=self.proxies,
            http_version="v1",
            timeout=15,
            allow_redirects=True,
        )
        idx = (r.text or "").find(marker)
        if idx == -1:
            return None
        return Candidate(url=url, marker=marker, offset=idx, status=r.status_code)

    def find_reflection_post_json(self, url: str, body: dict,
                                  marker: str,
                                  browser_cookies: list[dict]) -> Candidate | None:
        r = cffi.post(
            url,
            json=body,
            impersonate=self.impersonate,
            cookies=self._cookies(browser_cookies) if browser_cookies else None,
            proxies=self.proxies,
            http_version="v1",
            timeout=15,
            allow_redirects=True,
        )
        idx = (r.text or "").find(marker)
        if idx == -1:
            return None
        return Candidate(url=url, marker=marker, offset=idx, status=r.status_code)

    def fetch_body_post_form(self, url: str, fields: dict[str, str],
                             browser_cookies: list[dict]) -> str:
        r = cffi.post(
            url,
            data=fields,
            impersonate=self.impersonate,
            cookies=self._cookies(browser_cookies) if browser_cookies else None,
            proxies=self.proxies,
            http_version="v1",
            timeout=15,
            allow_redirects=True,
        )
        return r.text or ""

    def fetch_body_post_json(self, url: str, body: dict,
                             browser_cookies: list[dict]) -> str:
        r = cffi.post(
            url,
            json=body,
            impersonate=self.impersonate,
            cookies=self._cookies(browser_cookies) if browser_cookies else None,
            proxies=self.proxies,
            http_version="v1",
            timeout=15,
            allow_redirects=True,
        )
        return r.text or ""

    def find_reflection(self, url: str, marker: str,
                        browser_cookies: list[dict]) -> Candidate | None:
        """Return a Candidate if `marker` appears verbatim in the body, else None."""
        r = cffi.get(
            url,
            impersonate=self.impersonate,
            cookies=self._cookies(browser_cookies) if browser_cookies else None,
            proxies=self.proxies,
            http_version="v1",
            timeout=15,
            allow_redirects=True,
        )
        body = r.text or ""
        idx = body.find(marker)
        if idx == -1:
            return None
        return Candidate(url=url, marker=marker, offset=idx, status=r.status_code)
