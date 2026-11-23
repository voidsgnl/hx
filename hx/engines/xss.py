"""Adapter exposing the existing execution-oracle scanner as an engine."""
from __future__ import annotations

from hx.engines.base import AttackSurface, EngineContext
from hx.scanner import ScanResult, scan


class XSSEngine:
    engine_id = "xss"

    def supports(self, surface: AttackSurface) -> bool:
        return surface.method.upper() == "GET" and bool(surface.parameters)

    async def run(self, surface: AttackSurface, context: EngineContext) -> ScanResult:
        return await scan(
            surface.url,
            proxy=context.proxy,
            budget=context.budget,
            headless=context.headless,
            _client=context.client,
            _pacer=context.pacer,
            _warm=not context.client_ready,
        )
