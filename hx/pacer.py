"""Request pacing and a strict per-scan outbound request budget."""
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
        if budget < 0:
            raise ValueError("budget must be >= 0")
        self.min, self.max = min_delay, max_delay
        self.budget = budget
        self.used = 0
        self.exhausted = False
        self.started = time.monotonic()

    def reserve(self) -> None:
        """Reserve one outbound HTTP request before it is sent."""
        if self.used >= self.budget:
            self.exhausted = True
            raise BudgetExhausted(
                f"request budget ({self.budget}) exhausted after "
                f"{time.monotonic() - self.started:.1f}s — stop and reassess"
            )
        self.used += 1

    async def pause(self) -> None:
        """Apply jitter without changing the request count."""
        await asyncio.sleep(random.uniform(self.min, self.max))

    async def wait(self) -> None:
        """Compatibility helper: pause, then reserve one request."""
        await self.pause()
        self.reserve()

    @property
    def remaining(self) -> int:
        return max(0, self.budget - self.used)
