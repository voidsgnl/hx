"""Shared contracts for vulnerability engines."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class AttackSurface:
    """A discovered input or endpoint that one or more engines can assess."""

    url: str
    method: str
    parameters: tuple[str, ...]
    behaviour: str
    source: str


@dataclass(frozen=True)
class EngineContext:
    """Runtime controls shared with each engine."""

    proxy: str | None
    budget: int
    headless: bool


class VulnerabilityEngine(Protocol):
    """Contract implemented by each independent vulnerability engine."""

    engine_id: str

    def supports(self, surface: AttackSurface) -> bool:
        """Return whether this engine can test the supplied surface."""

    async def run(self, surface: AttackSurface, context: EngineContext) -> Any:
        """Execute the engine's checks and return its structured result."""
