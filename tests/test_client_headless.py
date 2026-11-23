import pytest

from hx.client import TargetClient


class FakeContext:
    async def route(self, pattern, handler):
        pass

    async def add_init_script(self, script):
        pass

    async def new_page(self):
        return object()

    async def close(self):
        pass


class FakeChromium:
    def __init__(self):
        self.launch_kwargs = None

    async def launch_persistent_context(self, **kwargs):
        self.launch_kwargs = kwargs
        return FakeContext()


class FakePlaywright:
    def __init__(self):
        self.chromium = FakeChromium()

    async def stop(self):
        pass


class FakePlaywrightManager:
    def __init__(self, playwright):
        self.playwright = playwright

    async def start(self):
        return self.playwright


@pytest.mark.asyncio
@pytest.mark.parametrize("headless", [True, False])
async def test_target_client_respects_headless_setting(monkeypatch, tmp_path, headless):
    fake = FakePlaywright()
    monkeypatch.setattr(
        "hx.client.async_playwright",
        lambda: FakePlaywrightManager(fake),
    )
    client = TargetClient(
        "http://localhost:5000",
        profile_dir=str(tmp_path / "profile"),
    )

    await client.start("/* test init */", headless=headless)

    assert fake.chromium.launch_kwargs["headless"] is headless
    await client.close()
