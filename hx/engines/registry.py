"""Registry for independently selectable vulnerability engines."""
from __future__ import annotations

from hx.engines.base import AttackSurface, VulnerabilityEngine
from hx.engines.xss import XSSEngine
from hx.engines.open_redirect import OpenRedirectEngine


class EngineRegistry:
    def __init__(self) -> None:
        self._engines: dict[str, VulnerabilityEngine] = {}

    def register(self, engine: VulnerabilityEngine) -> None:
        if not engine.engine_id or engine.engine_id in self._engines:
            raise ValueError(f"duplicate or empty engine id: {engine.engine_id!r}")
        self._engines[engine.engine_id] = engine

    def select(self, surface: AttackSurface) -> list[VulnerabilityEngine]:
        return [
            engine for engine in self._engines.values()
            if engine.supports(surface)
        ]

    @property
    def engine_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._engines))


def default_registry() -> EngineRegistry:
    """Return the engines currently implemented by hx."""
    registry = EngineRegistry()
    registry.register(XSSEngine())
    registry.register(OpenRedirectEngine())
    return registry
