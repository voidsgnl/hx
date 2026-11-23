import pytest

from hx.client import TargetClient


class FakeContext:
    async def add_init_script(self, script):
        pass

    async def new_page(self):
        return object()

    async def close(self):
        pass


class FakeChromium:
    def __init__(self):
        self.profile_dirs = []

    async def launch_persistent_context(self, user_data_dir, **kwargs):
        self.profile_dirs.append(user_data_dir)
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
async def test_default_clients_get_distinct_profiles_and_remove_them_on_close(
    monkeypatch,
):
    fake = FakePlaywright()
    monkeypatch.setattr(
        "hx.client.async_playwright",
        lambda: FakePlaywrightManager(fake),
    )
    first = TargetClient("http://localhost:5000")
    second = TargetClient("http://localhost:5000")

    await first.start("/* init */")
    await second.start("/* init */")

    first_profile = first.profile_dir
    second_profile = second.profile_dir
    assert first_profile != second_profile
    assert first_profile != "/tmp/hx-profile"
    assert second_profile != "/tmp/hx-profile"

    await first.close()
    assert first.profile_dir is None
    assert not __import__("pathlib").Path(first_profile).exists()
    assert __import__("pathlib").Path(second_profile).exists()

    await second.close()
    assert not __import__("pathlib").Path(second_profile).exists()


@pytest.mark.asyncio
async def test_explicit_profile_is_preserved_on_close(monkeypatch, tmp_path):
    fake = FakePlaywright()
    monkeypatch.setattr(
        "hx.client.async_playwright",
        lambda: FakePlaywrightManager(fake),
    )
    profile = tmp_path / "persistent-profile"
    client = TargetClient("http://localhost:5000", profile_dir=str(profile))

    await client.start("/* init */")
    await client.close()

    assert profile.is_dir()
