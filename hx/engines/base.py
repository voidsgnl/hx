"""Shared contracts for vulnerability engines."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from hx.client import TargetClient
from hx.pacer import Pacer


@dataclass(frozen=True)
class AttackSurface:
    """A discovered input or endpoint that one or more engines can assess."""

    url: str
    method: str
    parameters: tuple[str, ...]
    behaviour: str
    source: str
    form_page: str | None = None


@dataclass(frozen=True)
class EngineContext:
    """Runtime controls and shared session resources passed to each engine."""

    proxy: str | None
    budget: int
    headless: bool
    client: TargetClient | None = None
    pacer: Pacer | None = None
    client_ready: bool = False


class VulnerabilityEngine(Protocol):
    """Contract implemented by each independent vulnerability engine."""

    engine_id: str

    def supports(self, surface: AttackSurface) -> bool:
        """Return whether this engine can test the supplied surface."""

    async def run(self, surface: AttackSurface, context: EngineContext) -> Any:
        """Execute the engine's checks and return its structured result."""
