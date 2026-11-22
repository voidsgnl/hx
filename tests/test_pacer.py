import asyncio
import pytest
from hx.pacer import Pacer, BudgetExhausted


@pytest.mark.asyncio
async def test_budget_exhaustion_raises():
    p = Pacer(min_delay=0.0, max_delay=0.0, budget=3)
    for _ in range(3):
        await p.wait()
    assert p.remaining == 0
    with pytest.raises(BudgetExhausted):
        await p.wait()
    assert p.used == 3
    assert p.exhausted


@pytest.mark.asyncio
async def test_jitter_within_bounds(monkeypatch):
    sleeps = []

    async def fake_sleep(s):
        sleeps.append(s)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)
    p = Pacer(min_delay=0.8, max_delay=3.5, budget=10)
    for _ in range(10):
        await p.wait()
    assert len(sleeps) == 10
    assert all(0.8 <= s <= 3.5 for s in sleeps)
    assert len(set(sleeps)) > 1


@pytest.mark.asyncio
async def test_pause_does_not_consume_budget(monkeypatch):
    async def fake_sleep(_):
        pass

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)
    p = Pacer(min_delay=0.0, max_delay=0.0, budget=1)
    await p.pause()
    assert p.used == 0
    p.reserve()
    assert p.used == 1


def test_reserve_counts_actual_requests():
    p = Pacer(budget=2)
    p.reserve()
    p.reserve()
    assert p.used == 2
    with pytest.raises(BudgetExhausted):
        p.reserve()
    assert p.used == 2
    assert p.exhausted


def test_bad_bounds():
    with pytest.raises(ValueError):
        Pacer(min_delay=5, max_delay=1)
    with pytest.raises(ValueError):
        Pacer(budget=-1)
