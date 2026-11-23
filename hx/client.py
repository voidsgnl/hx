"""TargetClient: one persistent Chromium context per target.

The context routes every network request through a shared budget guard so
navigation, redirects, and subresources are counted individually.
"""
import asyncio
import shutil
import tempfile
from pathlib import Path
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
        self.budget_exhausted = False

    async def start(self, oracle_init_script: str, request_guard=None,
                    headless: bool = True, navigation_guard=None):
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
    
            if self.request_guard:
                async def guard_route(route):
                    request_url = route.request.url
                    if (route.request.is_navigation_request()
                            and navigation_guard
                            and not navigation_guard(request_url)):
                        await route.abort(error_code="blockedbyclient")
                        return
                    if request_url.startswith(("http://", "https://")):
                        try:
                            self.request_guard()
                        except BudgetExhausted:
                            self.budget_exhausted = True
                            await route.abort(error_code="blockedbyclient")
                            return
                    await route.continue_()
    
                await self._context.route("**/*", guard_route)
    
            # Install stealth + oracle BEFORE any navigation.
            await self._context.add_init_script(STEALTH_JS)
            await self._context.add_init_script(oracle_init_script)
            self.page = await self._context.new_page()
        except BaseException:
            await self._cleanup_start_failure()
            raise

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

    async def warm(self, timeout_ms: int = 20000) -> bool:
        """Hit origin, wait out JS challenge. True if we reached app content."""
        try:
            await self.page.goto(self.origin, wait_until="domcontentloaded",
                                 timeout=timeout_ms)
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
