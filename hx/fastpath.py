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
from urllib.parse import urljoin, urlparse
from curl_cffi import requests as cffi
from hx.versions import CURL_CFFI_IMPERSONATE


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

    def _reserve_request(self) -> None:
        if self.request_guard:
            self.request_guard()

    def _request(self, method: str, url: str, **kwargs):
        """Send requests one hop at a time so redirects consume budget too."""
        browser_cookies = kwargs.pop("browser_cookies", None)
        request_kwargs = dict(kwargs)
        for redirect_count in range(11):
            self._reserve_request()
            if browser_cookies is not None:
                request_kwargs["cookies"] = self._cookies(browser_cookies, url)
            response = cffi.request(
                method, url, allow_redirects=False, **request_kwargs
            )
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
                request_kwargs.pop("data", None)
                request_kwargs.pop("json", None)
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

    def fetch_body(self, url: str, browser_cookies: list[dict]) -> str:
        """Fetch a response body for context detection; never prove execution."""
        r = self._request("GET",
            url,
            impersonate=self.impersonate,
            browser_cookies=browser_cookies,
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
            browser_cookies=browser_cookies,
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
            browser_cookies=browser_cookies,
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
            browser_cookies=browser_cookies,
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
            browser_cookies=browser_cookies,
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
            browser_cookies=browser_cookies,
            proxies=self.proxies,
            http_version="v1",
            timeout=15,
        )
        body = r.text or ""
        idx = body.find(marker)
        if idx == -1:
            return None
        return Candidate(url=url, marker=marker, offset=idx, status=r.status_code)
