"""Request pacing + hard budget. Keeps you under Cloudflare bot scoring.

Rules that matter:
  - jittered delays, never fixed cadence (fixed cadence is a bot tell)
  - hard budget per host: exhaust it and you stop, you don't "try a bit more"
  - single-threaded by construction; the caller awaits wait() before each request
"""
import asyncio
import random
import time


class BudgetExhausted(RuntimeError):
    pass


class Pacer:
    def __init__(self, min_delay: float = 0.8, max_delay: float = 3.5,
                 budget: int = 200):
        if min_delay > max_delay:
            raise ValueError("min_delay must be <= max_delay")
        self.min, self.max = min_delay, max_delay
        self.budget = budget
        self.used = 0
        self.started = time.monotonic()

    async def wait(self) -> None:
        if self.used >= self.budget:
            raise BudgetExhausted(
                f"request budget ({self.budget}) exhausted after "
                f"{time.monotonic() - self.started:.1f}s — stop and reassess"
            )
        # jitter: no two gaps identical
        await asyncio.sleep(random.uniform(self.min, self.max))
        self.used += 1

    @property
    def remaining(self) -> int:
        return max(0, self.budget - self.used)