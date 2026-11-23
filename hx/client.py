"""TargetClient: one persistent Chromium context per target.

The context routes every network request through a shared budget guard so
navigation, redirects, and subresources are counted individually.
"""
import asyncio
import json
import logging
import shutil
import tempfile
from pathlib import Path
from urllib.parse import urlparse
from playwright.async_api import async_playwright, BrowserContext, Page
from hx.pacer import BudgetExhausted


STEALTH_JS = """
Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
Object.defineProperty(navigator, 'plugins', { get: () => [1,2,3,4,5] });
Object.defineProperty(navigator, 'languages', { get: () => ['en-US','en'] });
const _q = window.navigator.permissions.query;
window.navigator.permissions.query = (p) => (
  p.name === 'notifications'
    ? Promise.resolve({ state: Notification.permission })
    : _q(p)
);
window.chrome = window.chrome || { runtime: {} };
"""

CHALLENGE_MARKERS = ("Just a moment", "Verifying you are human", "cf-challenge")
log = logging.getLogger("hx")


class TargetClient:
    def __init__(self, origin: str, proxy: str | None = None,
                 profile_dir: str | None = None):
        self.origin = origin.rstrip("/")
        self.proxy = proxy
        # Private temporary profiles prevent concurrent scans sharing Chromium state.
        self._owns_profile = profile_dir is None
        self.profile_dir = profile_dir
        self._pw = None
        self._context: BrowserContext | None = None
        self.page: Page | None = None
        self.request_guard = None
        self.requests_unaccounted = 0
        self.budget_exhausted = False
        self.last_response_status: int | None = None
        self._request_headers: dict[str, str] = {}
        self._target_host = (urlparse(self.origin).hostname or "").lower().rstrip(".")

    async def start(self, oracle_init_script: str, request_guard=None,
                    headless: bool = True, navigation_guard=None,
                    request_filter=None,
                    storage_state: str | None = None,
                    headers: dict[str, str] | None = None,
                    cookies: dict[str, str] | None = None):
        self.request_guard = request_guard
        if self.profile_dir is None:
            self.profile_dir = tempfile.mkdtemp(prefix="hx-profile-")
        else:
            Path(self.profile_dir).mkdir(parents=True, exist_ok=True)
        try:
            self._pw = await async_playwright().start()
            launch_kwargs = dict(
                headless=headless,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                ],
                viewport={"width": 1366, "height": 768},
                locale="en-US",
                timezone_id="America/New_York",
            )
            if self.proxy:
                launch_kwargs["proxy"] = {"server": self.proxy}
            self._context = await self._pw.chromium.launch_persistent_context(
                user_data_dir=self.profile_dir, **launch_kwargs
            )
    
            async def guard_route(route):
                request_url = route.request.url
                if (navigation_guard
                        and route.request.is_navigation_request()
                        and not navigation_guard(request_url)):
                    await route.abort(error_code="blockedbyclient")
                    return
                # A mapper may reject non-essential subresources before they
                # consume the scan's request budget.
                if request_filter and not request_filter(route.request):
                    await route.abort(error_code="blockedbyclient")
                    return
                if request_url.startswith(("http://", "https://")):
                    if self.request_guard is None:
                        self.requests_unaccounted += 1
                    else:
                        try:
                            self.request_guard()
                        except BudgetExhausted:
                            self.budget_exhausted = True
                            await route.abort(error_code="blockedbyclient")
                            return
                request_host = (urlparse(request_url).hostname or "").lower().rstrip(".")
                if request_host != self._target_host and self._request_headers:
                    request_headers = await route.request.all_headers()
                    for name in self._request_headers:
                        request_headers.pop(name.lower(), None)
                    await route.continue_(headers=request_headers)
                    return
                await route.continue_()
    
            await self._context.route("**/*", guard_route)
    
            # Restore an explicitly supplied Playwright storage state before
            # the first page is opened. Cookie and localStorage state stay local.
            if storage_state:
                state_path = Path(storage_state).expanduser()
                state = json.loads(state_path.read_text(encoding="utf-8"))
                if not isinstance(state, dict):
                    raise ValueError("storage state must be a Playwright JSON object")
                storage_cookies = state.get("cookies", [])
                if storage_cookies:
                    await self._context.add_cookies(storage_cookies)
                origins = state.get("origins", [])
                if origins:
                    local_storage = {
                        item.get("origin", ""): item.get("localStorage", [])
                        for item in origins
                        if item.get("origin")
                    }
                    serialized = json.dumps(local_storage)
                    await self._context.add_init_script(
                        f"""(() => {{
                          const stores = {serialized};
                          const entries = stores[location.origin] || [];
                          for (const item of entries) {{
                            try {{ localStorage.setItem(item.name, item.value); }}
                            catch (_) {{}}
                          }}
                        }})();"""
                    )

            await self.configure_request_state(headers, cookies)

            # Install stealth + oracle BEFORE any navigation.
            await self._context.add_init_script(STEALTH_JS)
            await self._context.add_init_script(oracle_init_script)
            self.page = await self._context.new_page()
        except BaseException:
            await self._cleanup_start_failure()
            raise

    async def configure_request_state(
        self,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
    ) -> None:
        """Install RequestSpec headers and cookies before the next navigation."""
        if not self._context:
            raise RuntimeError("TargetClient must be started before request state is set")
        self._request_headers = dict(headers or {})
        set_headers = getattr(self._context, "set_extra_http_headers", None)
        if set_headers:
            await set_headers(self._request_headers)

        if not cookies:
            return
        target_cookies = dict(cookies)
        existing = await self._context.cookies()
        conflicting = []
        for cookie in existing:
            if cookie.get("name") not in target_cookies:
                continue
            domain = (cookie.get("domain") or "").lower().lstrip(".").rstrip(".")
            if not domain:
                cookie_url = urlparse(cookie.get("url", ""))
                domain = (cookie_url.hostname or "").lower().rstrip(".")
            if (
                self._target_host == domain
                or self._target_host.endswith("." + domain)
            ):
                conflicting.append(cookie)
        for cookie in conflicting:
            await self._context.clear_cookies(
                name=cookie["name"],
                domain=cookie.get("domain"),
                path=cookie.get("path", "/"),
            )
        if conflicting:
            log.debug(
                "RequestSpec cookies override storage-state/browser cookies for: %s",
                ", ".join(sorted({item["name"] for item in conflicting})),
            )
        await self._context.add_cookies([
            {"name": name, "value": value, "url": self.origin + "/"}
            for name, value in target_cookies.items()
        ])

    async def _cleanup_start_failure(self):
        """Release partially initialized resources when startup fails."""
        try:
            if self._context:
                await self._context.close()
        finally:
            self._context = None
            self.page = None
            try:
                if self._pw:
                    await self._pw.stop()
            finally:
                self._pw = None
                if self._owns_profile and self.profile_dir:
                    shutil.rmtree(self.profile_dir, ignore_errors=True)
                    self.profile_dir = None

    async def warm(self, timeout_ms: int = 20000, url: str | None = None) -> bool:
        """Navigate once to the requested target and wait out JS challenges."""
        self.last_response_status = None
        try:
            response = await self.page.goto(
                url or self.origin,
                wait_until="domcontentloaded",
                timeout=timeout_ms,
            )
            self.last_response_status = response.status if response else None
        except Exception:
            return False
        return await self._wait_past_challenge()

    async def _wait_past_challenge(self, max_polls: int = 40) -> bool:
        for _ in range(max_polls):
            try:
                title = await self.page.title()
                body = await self.page.content()
            except Exception:
                await asyncio.sleep(0.5)
                continue
            if not any(m in title or m in body for m in CHALLENGE_MARKERS):
                return True
            await asyncio.sleep(0.5)
        return False

    async def cookies(self) -> list[dict]:
        assert self._context
        return await self._context.cookies()

    async def save_storage_state(self, path: str) -> None:
        """Save cookies and localStorage for an explicitly authenticated session."""
        assert self._context
        destination = Path(path).expanduser()
        destination.parent.mkdir(parents=True, exist_ok=True)
        await self._context.storage_state(path=str(destination))
        destination.chmod(0o600)

    async def close(self):
        """Close Chromium and remove only profiles created by this client."""
        try:
            if self._context:
                await self._context.close()
                self._context = None
        finally:
            try:
                if self._pw:
                    await self._pw.stop()
                    self._pw = None
            finally:
                if self._owns_profile and self.profile_dir:
                    shutil.rmtree(self.profile_dir, ignore_errors=True)
                    self.profile_dir = None
