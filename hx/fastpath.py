"""curl_cffi fast path for volume probing.

IMPORTANT: the fast path CANNOT prove XSS. It only detects that payload
bytes appear in the response body (a 'candidate'). Proof stays in the
browser oracle. Never let this module emit a 'found' — only 'candidate'.

cf_clearance handoff gotcha: the cookie is bound to (IP, UA, TLS fingerprint).
The impersonation profile MUST match the Playwright Chromium version, or the
cookie is invalidated -> 403. Pin both to the same chrome version string.
"""
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse
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

    def _request(self, method: str, url: str, **kwargs):
        """Send requests one hop at a time so redirects consume budget too."""
        original_host = urlparse(url).hostname
        request_kwargs = dict(kwargs)
        for redirect_count in range(11):
            self._reserve_request()
            response = cffi.request(
                method, url, allow_redirects=False, **request_kwargs
            )
            location = response.headers.get("Location")
            if response.status_code not in (301, 302, 303, 307, 308) or not location:
                return response
            if redirect_count == 10:
                return response

            next_url = urljoin(url, location)
            if urlparse(next_url).hostname != original_host:
                request_kwargs["cookies"] = None
            if response.status_code == 303 or (
                response.status_code in (301, 302) and method.upper() == "POST"
            ):
                method = "GET"
                request_kwargs.pop("data", None)
                request_kwargs.pop("json", None)
            url = next_url
        return response

    def _cookies(self, browser_cookies: list[dict]) -> dict:
        return {c["name"]: c["value"] for c in browser_cookies
                if c.get("domain", "").lstrip(".") in self._allowed_domains}

    def set_allowed_domains(self, domains: set[str]):
        # e.g. {"localhost", "example.com"} — derived from the target origin
        self._allowed_domains = {d.lstrip(".") for d in domains}

    def fetch_body(self, url: str, browser_cookies: list[dict]) -> str:
        """Fetch a response body for context detection; never prove execution."""
        r = self._request("GET",
            url,
            impersonate=self.impersonate,
            cookies=self._cookies(browser_cookies) if browser_cookies else None,
            proxies=self.proxies,
            http_version="v1",
            timeout=15,
        )
        return r.text or ""

    def find_reflection_post_form(self, url: str, fields: dict[str, str],
                                  marker: str,
                                  browser_cookies: list[dict]) -> Candidate | None:
        r = self._request("POST",
            url,
            data=fields,
            impersonate=self.impersonate,
            cookies=self._cookies(browser_cookies) if browser_cookies else None,
            proxies=self.proxies,
            http_version="v1",
            timeout=15,
        )
        idx = (r.text or "").find(marker)
        if idx == -1:
            return None
        return Candidate(url=url, marker=marker, offset=idx, status=r.status_code)

    def find_reflection_post_json(self, url: str, body: dict,
                                  marker: str,
                                  browser_cookies: list[dict]) -> Candidate | None:
        r = self._request("POST",
            url,
            json=body,
            impersonate=self.impersonate,
            cookies=self._cookies(browser_cookies) if browser_cookies else None,
            proxies=self.proxies,
            http_version="v1",
            timeout=15,
        )
        idx = (r.text or "").find(marker)
        if idx == -1:
            return None
        return Candidate(url=url, marker=marker, offset=idx, status=r.status_code)

    def fetch_body_post_form(self, url: str, fields: dict[str, str],
                             browser_cookies: list[dict]) -> str:
        r = self._request("POST",
            url,
            data=fields,
            impersonate=self.impersonate,
            cookies=self._cookies(browser_cookies) if browser_cookies else None,
            proxies=self.proxies,
            http_version="v1",
            timeout=15,
        )
        return r.text or ""

    def fetch_body_post_json(self, url: str, body: dict,
                             browser_cookies: list[dict]) -> str:
        r = self._request("POST",
            url,
            json=body,
            impersonate=self.impersonate,
            cookies=self._cookies(browser_cookies) if browser_cookies else None,
            proxies=self.proxies,
            http_version="v1",
            timeout=15,
        )
        return r.text or ""

    def find_reflection(self, url: str, marker: str,
                        browser_cookies: list[dict]) -> Candidate | None:
        """Return a Candidate if `marker` appears verbatim in the body, else None."""
        r = self._request("GET",
            url,
            impersonate=self.impersonate,
            cookies=self._cookies(browser_cookies) if browser_cookies else None,
            proxies=self.proxies,
            http_version="v1",
            timeout=15,
        )
        body = r.text or ""
        idx = body.find(marker)
        if idx == -1:
            return None
        return Candidate(url=url, marker=marker, offset=idx, status=r.status_code)
