"""curl_cffi fast path for volume probing.

IMPORTANT: the fast path CANNOT prove XSS. It only detects that payload
bytes appear in the response body (a 'candidate'). Proof stays in the
browser oracle. Never let this module emit a 'found' — only 'candidate'.

cf_clearance handoff gotcha: the cookie is bound to (IP, UA, TLS fingerprint).
The impersonation profile MUST match the Playwright Chromium version, or the
cookie is invalidated -> 403. Pin both to the same chrome version string.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import logging
from urllib.parse import urljoin, urlparse
from curl_cffi import requests as cffi
from curl_cffi.requests.cookies import Cookies as CurlCookies
from hx.versions import CURL_CFFI_IMPERSONATE

log = logging.getLogger("hx")


@dataclass
class Candidate:
    url: str
    marker: str          # the unique string we searched for
    offset: int          # where it appeared in the body
    status: int
    param: str = ""


class FastPath:
    def __init__(self, impersonate: str = CURL_CFFI_IMPERSONATE, proxy: str | None = None,
                 request_guard=None):
        self.impersonate = impersonate
        self.request_guard = request_guard
        self.proxies = {"https": proxy, "http": proxy} if proxy else None
        self._allowed_domains: set[str] = set()
        self.last_status: int | None = None

    def _reserve_request(self) -> None:
        if self.request_guard:
            self.request_guard()

    def _request(self, method: str, url: str, **kwargs):
        """Send requests one hop at a time so redirects consume budget too."""
        browser_cookies = kwargs.pop("browser_cookies", None)
        spec_cookies = kwargs.pop("spec_cookies", None)
        spec_headers = kwargs.pop("headers", None)
        base_kwargs = dict(kwargs)
        initial_host = (urlparse(url).hostname or "").lower().rstrip(".")
        for redirect_count in range(11):
            self._reserve_request()
            host = (urlparse(url).hostname or "").lower().rstrip(".")
            allowed_host = host in self._allowed_domains if self._allowed_domains else host == initial_host
            request_kwargs = dict(base_kwargs)
            if spec_headers and allowed_host:
                request_kwargs["headers"] = spec_headers

            browser_jar = (
                self._cookies(browser_cookies, url)
                if browser_cookies is not None else {}
            )
            explicit_jar = spec_cookies if spec_cookies and allowed_host else {}
            conflicts = browser_jar.keys() & explicit_jar.keys()
            if conflicts:
                log.debug(
                    "RequestSpec cookies override browser cookies for: %s",
                    ", ".join(sorted(conflicts)),
                )
            if browser_cookies is not None or spec_cookies is not None:
                merged_cookies = {**browser_jar, **explicit_jar}
                if host == "localhost" and merged_cookies:
                    # curl-impersonate infers "localhost.local" for a bare
                    # cookie dict; bind these to the actual loopback host.
                    cookie_jar = CurlCookies()
                    for name, value in merged_cookies.items():
                        cookie_jar.set(name, value, domain=host)
                    request_kwargs["cookies"] = cookie_jar
                else:
                    request_kwargs["cookies"] = merged_cookies
            response = cffi.request(
                method, url, allow_redirects=False, **request_kwargs
            )
            self.last_status = response.status_code
            location = response.headers.get("Location")
            if response.status_code not in (301, 302, 303, 307, 308) or not location:
                return response
            if redirect_count == 10:
                return response

            next_url = urljoin(url, location)
            # Cookie scope is recalculated for every redirect destination.
            # The target-domain allowlist prevents cross-origin cookie leakage.
            if response.status_code == 303 or (
                response.status_code in (301, 302) and method.upper() == "POST"
            ):
                method = "GET"
                base_kwargs.pop("data", None)
                base_kwargs.pop("json", None)
            url = next_url
        return response

    @staticmethod
    def _domain_matches(host: str, domain: str) -> bool:
        """RFC-style domain match: exact host or a dot-delimited subdomain."""
        host = host.lower().rstrip(".")
        domain = domain.lower().lstrip(".").rstrip(".")
        return host == domain or host.endswith("." + domain)

    def _cookies(self, browser_cookies: list[dict], url: str | None = None) -> dict:
        """Return only cookies valid for this request URL and target domain.

        The optional URL preserves the older inspection helper API; network
        requests always pass their actual destination URL.
        """
        if url is None:
            if not self._allowed_domains:
                return {}
            url = f"http://{sorted(self._allowed_domains)[0]}/"
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower().rstrip(".")
        path = parsed.path or "/"
        is_secure = parsed.scheme.lower() == "https"
        now = datetime.now(timezone.utc).timestamp()
        selected = {}

        for cookie in browser_cookies:
            raw_domain = cookie.get("domain", "")
            if not raw_domain:
                continue
            domain_cookie = raw_domain.startswith(".")
            cookie_domain = raw_domain.lstrip(".").lower().rstrip(".")
            if not cookie_domain:
                continue

            # Domain cookies may cover subdomains; host-only cookies may not.
            request_match = (
                self._domain_matches(host, cookie_domain)
                if domain_cookie else host == cookie_domain
            )
            target_match = any(
                self._domain_matches(allowed, cookie_domain)
                if domain_cookie else allowed == cookie_domain
                for allowed in self._allowed_domains
            )
            if not request_match or not target_match:
                continue
            if cookie.get("secure") and not is_secure:
                continue
            cookie_path = cookie.get("path") or "/"
            if not path.startswith(cookie_path):
                continue
            if (len(path) > len(cookie_path)
                    and not cookie_path.endswith("/")
                    and path[len(cookie_path)] != "/"):
                continue
            expires = cookie.get("expires", -1)
            if expires not in (None, -1) and expires <= now:
                continue
            selected[cookie["name"]] = cookie["value"]
        return selected

    def set_allowed_domains(self, domains: set[str]):
        # Hosts belonging to the scanned target; cookie scope is checked separately.
        self._allowed_domains = {d.lower().lstrip(".").rstrip(".") for d in domains}

    def inspect_redirect(
        self, url: str, browser_cookies: list[dict]
    ) -> tuple[int, str | None]:
        """Inspect one GET response without following its Location header."""
        self._reserve_request()
        response = cffi.get(
            url,
            allow_redirects=False,
            impersonate=self.impersonate,
            cookies=self._cookies(browser_cookies, url),
            proxies=self.proxies,
            http_version="v1",
            timeout=15,
        )
        return response.status_code, response.headers.get("Location")

    def fetch_body(self, url: str, browser_cookies: list[dict], *,
                   headers: dict[str, str] | None = None,
                   spec_cookies: dict[str, str] | None = None) -> str:
        """Fetch a response body for context detection; never prove execution."""
        r = self._request("GET",
            url,
            impersonate=self.impersonate,
            browser_cookies=browser_cookies,
            headers=headers,
            spec_cookies=spec_cookies,
            proxies=self.proxies,
            http_version="v1",
            timeout=15,
        )
        return r.text or ""

    def find_reflection_post_form(self, url: str, fields: dict[str, str],
                                  marker: str,
                                  browser_cookies: list[dict], *,
                                  headers: dict[str, str] | None = None,
                                  spec_cookies: dict[str, str] | None = None) -> Candidate | None:
        r = self._request("POST",
            url,
            data=fields,
            headers=headers,
            impersonate=self.impersonate,
            browser_cookies=browser_cookies,
            spec_cookies=spec_cookies,
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
                                  browser_cookies: list[dict],
                                  headers: dict[str, str] | None = None,
                                  spec_cookies: dict[str, str] | None = None) -> Candidate | None:
        r = self._request("POST",
            url,
            json=body,
            headers=headers,
            impersonate=self.impersonate,
            browser_cookies=browser_cookies,
            spec_cookies=spec_cookies,
            proxies=self.proxies,
            http_version="v1",
            timeout=15,
        )
        idx = (r.text or "").find(marker)
        if idx == -1:
            return None
        return Candidate(url=url, marker=marker, offset=idx, status=r.status_code)

    def fetch_body_post_form(self, url: str, fields: dict[str, str],
                             browser_cookies: list[dict], *,
                             headers: dict[str, str] | None = None,
                             spec_cookies: dict[str, str] | None = None) -> str:
        r = self._request("POST",
            url,
            data=fields,
            headers=headers,
            impersonate=self.impersonate,
            browser_cookies=browser_cookies,
            spec_cookies=spec_cookies,
            proxies=self.proxies,
            http_version="v1",
            timeout=15,
        )
        return r.text or ""

    def fetch_body_post_json(self, url: str, body: dict,
                             browser_cookies: list[dict],
                             headers: dict[str, str] | None = None,
                             spec_cookies: dict[str, str] | None = None) -> str:
        r = self._request("POST",
            url,
            json=body,
            headers=headers,
            impersonate=self.impersonate,
            browser_cookies=browser_cookies,
            spec_cookies=spec_cookies,
            proxies=self.proxies,
            http_version="v1",
            timeout=15,
        )
        return r.text or ""

    def find_reflection(self, url: str, marker: str,
                        browser_cookies: list[dict], *,
                        headers: dict[str, str] | None = None,
                        spec_cookies: dict[str, str] | None = None) -> Candidate | None:
        """Return a Candidate if `marker` appears verbatim in the body, else None."""
        r = self._request("GET",
            url,
            impersonate=self.impersonate,
            browser_cookies=browser_cookies,
            headers=headers,
            spec_cookies=spec_cookies,
            proxies=self.proxies,
            http_version="v1",
            timeout=15,
        )
        body = r.text or ""
        idx = body.find(marker)
        if idx == -1:
            return None
        return Candidate(url=url, marker=marker, offset=idx, status=r.status_code)
