"""Adapter exposing the existing execution-oracle scanner as an engine."""
from __future__ import annotations

from hx.engines.base import AttackSurface, EngineContext
from hx.scanner import RequestSpec, ScanResult, scan


class XSSEngine:
    engine_id = "xss"

    def supports(self, surface: AttackSurface) -> bool:
        return surface.method.upper() in {"GET", "POST", "JSON"} and bool(surface.parameters)

    async def run(self, surface: AttackSurface, context: EngineContext) -> ScanResult:
        target = surface.url
        if surface.source == "browser-api" and surface.method.upper() == "POST":
            spec = RequestSpec(
                method="JSON", url=surface.url,
                json_body=dict(surface.request_body or {}),
                headers=surface.headers,
                parameters=surface.parameters,
                source_page=surface.source_page,
                source_interaction=surface.source_interaction,
            )
            target = spec
        elif surface.method.upper() == "POST":
            spec = RequestSpec(
                method="POST",
                url=surface.url,
                form={name: "" for name in surface.parameters},
                form_page=surface.form_page,
            )
            target = spec
        return await scan(
            target,
            proxy=context.proxy,
            budget=context.budget,
            headless=context.headless,
            _client=context.client,
            _pacer=context.pacer,
            _warm=not context.client_ready,
        )
