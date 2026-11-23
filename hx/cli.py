"""hx — execution-oracle XSS scanner with browser WAF pass."""
import asyncio
import json
import logging
import random
from dataclasses import asdict
from importlib.resources import files
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from hx import __version__
from hx.client import TargetClient
from hx.discover import FieldRole, discover_forms
from hx.oracle import ORACLE_INIT_JS
from hx.scanner import RequestSpec, scan
from hx.website_scan import scan_website
from urllib.parse import urlparse

app = typer.Typer(add_completion=False, help="Website vulnerability scanner with browser-verified findings.")
console = Console()
log = logging.getLogger("hx")


def _parse_cookie_pair(raw: str) -> tuple[str, str]:
    name, separator, value = raw.partition("=")
    name = name.strip()
    value = value.strip()
    if (
        not separator
        or not name
        or any(char.isspace() or char in "=;" for char in name)
        or any(char in "\r\n;" for char in value)
    ):
        raise typer.BadParameter("malformed cookie; expected name=value")
    return name, value


def _parse_request_state(
    header_values: list[str] | None,
    cookie_values: list[str] | None,
) -> tuple[dict[str, str], dict[str, str]]:
    headers: dict[str, str] = {}
    header_cookies: dict[str, str] = {}
    for raw in header_values or []:
        name, separator, value = raw.partition(":")
        name = name.strip()
        value = value.strip()
        if (
            not separator
            or not name
            or any(char.isspace() or char == ":" for char in name)
            or any(char in "\r\n" for char in value)
        ):
            raise typer.BadParameter("malformed header; expected 'Name: Value'")
        if name.lower() == "cookie":
            for pair in value.split(";"):
                if not pair.strip():
                    continue
                cookie_name, cookie_value = _parse_cookie_pair(pair)
                header_cookies[cookie_name] = cookie_value
            continue
        for existing in list(headers):
            if existing.lower() == name.lower():
                del headers[existing]
        headers[name] = value

    explicit_cookies: dict[str, str] = {}
    for raw in cookie_values or []:
        name, value = _parse_cookie_pair(raw)
        explicit_cookies[name] = value
    conflicts = header_cookies.keys() & explicit_cookies.keys()
    if conflicts:
        log.debug(
            "--cookie values override Cookie header values for: %s",
            ", ".join(sorted(conflicts)),
        )
    return headers, {**header_cookies, **explicit_cookies}


def _random_banner() -> str:
    banners = tuple(
        banner.read_text(encoding="utf-8").strip()
        for banner in files("hx.banners").iterdir()
        if banner.name.endswith(".txt")
    )
    if not banners:
        raise RuntimeError("No hx banners are installed")
    return random.choice(banners)


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """Browser-verified website vulnerability scanner."""
    if ctx.invoked_subcommand is None and not ctx.args:
        console.print(_random_banner(), style="bold cyan", markup=False)
        typer.echo(ctx.get_help())


@app.command()
def version():
    """Print version."""
    console.print(f"hx {__version__}")


@app.command(name="scan")
def scan_cmd(
    url: str = typer.Argument(..., help="Target URL, e.g. http://localhost:5000/reflect?q=test"),
    data: Optional[str] = typer.Option(None, "--data", help="form-encoded POST body, e.g. 'q=test'"),
    json_body: Optional[str] = typer.Option(None, "--json-body", help="JSON POST body, e.g. '{\"q\":\"test\"}'"),
    budget: int = typer.Option(120, help="Max requests per scan"),
    proxy: Optional[str] = typer.Option(None, help="Proxy URL, e.g. http://127.0.0.1:8080"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON instead of a table"),
    headed: bool = typer.Option(False, "--headed", help="Show the Chromium browser window"),
    mode: str = typer.Option("auto", "--mode", help="Scan mode: auto, target, or website"),
    max_pages: int = typer.Option(30, "--max-pages", help="Website mode: maximum pages to map"),
    max_depth: int = typer.Option(2, "--max-depth", help="Website mode: maximum link depth"),
    interaction_limit: int = typer.Option(3, "--interaction-limit", min=0, max=10, help="Maximum safe UI steps in each mapped page's interaction chain (0 disables exploration)"),
    active_post: bool = typer.Option(False, "--active-post", help="Opt in to testing discovered HTML POST forms"),
    active_api: bool = typer.Option(False, "--active-api", help="Opt in to replaying discovered JSON POST APIs with captured auth and CSRF headers"),
    include_auth_forms: bool = typer.Option(False, "--include-auth-forms", help="Also test authentication forms; may trigger lockouts or alter login state"),
    storage_state: Optional[str] = typer.Option(None, "--storage-state", help="Playwright storage-state JSON for an authenticated session"),
    header: list[str] | None = typer.Option(None, "--header", "-H", help="Header 'Name: Value'. Repeatable. Applied to both paths."),
    cookie: list[str] | None = typer.Option(None, "--cookie", help="Cookie 'name=value'. Repeatable. Shorthand for a Cookie header."),
):
    """Scan an explicit input or automatically map and scan a website."""
    if data and json_body:
        raise typer.BadParameter("--data and --json-body are mutually exclusive")
    request_headers, request_cookies = _parse_request_state(header, cookie)
    mode = mode.lower()
    if mode not in {"auto", "target", "website"}:
        raise typer.BadParameter("--mode must be auto, target, or website")
    if include_auth_forms and not active_post:
        raise typer.BadParameter("--include-auth-forms requires --active-post")
    parsed_target = urlparse(url)
    has_fragment_input = "?" in parsed_target.fragment or "=" in parsed_target.fragment
    selected_mode = mode
    if selected_mode == "auto":
        selected_mode = (
            "target" if data or json_body or parsed_target.query or has_fragment_input or header or cookie
            else "website"
        )
    if (active_post or active_api) and selected_mode != "website":
        raise typer.BadParameter("--active-post and --active-api are only available in website mode")
    if selected_mode == "website":
        if header or cookie:
            raise typer.BadParameter("--header and --cookie are only available in target mode")
        if data or json_body:
            raise typer.BadParameter("--data and --json-body are only valid in target mode")
        result = asyncio.run(scan_website(
            url, proxy=proxy, budget=budget, headless=not headed,
            max_pages=max_pages, max_depth=max_depth,
            interaction_limit=interaction_limit,
            active_post=active_post, active_api=active_api, include_auth_forms=include_auth_forms,
            storage_state=storage_state,
        ))
        if json_out:
            typer.echo(json.dumps(result.to_dict(), indent=2))
            return
        console.print(f"[bold]Website scan:[/bold] {result.target}")
        console.print(
            f"[dim]pages mapped: {len(result.site_map.pages)} | "
            f"UI interactions explored: {result.site_map.interactions_attempted} | "
            f"targets tested: {len(result.tested_targets)} | "
            f"requests used: {result.requests_used}"
            f"{' (BUDGET EXHAUSTED)' if result.budget_exhausted else ''}[/dim]"
        )
        console.print(
            f"[dim]POST forms mapped but not submitted: {result.skipped_post_forms} | "
            f"POST API endpoints mapped but not tested: {result.skipped_post_endpoints} | "
            f"POST forms tested: {result.post_forms_tested} | "
            f"JSON POST APIs tested: {result.post_apis_tested}[/dim]"
        )
        if result.mapping_budget_exhausted:
            console.print("[yellow]Discovery request allowance reached; testing continued with the reserved budget.[/yellow]")
        if result.site_map.errors:
            for error in result.site_map.errors:
                console.print(f"[yellow]Mapping note: {error}[/yellow]")
        for engine_result in result.engine_results:
            for error in engine_result.get("errors", []):
                console.print(
                    f"[yellow]{engine_result.get('engine')} note: {error}[/yellow]"
                )
        if result.engines_run:
            console.print(f"[dim]engines executed: {', '.join(sorted(set(result.engines_run)))}[/dim]")
        if result.site_map.groups:
            group_table = Table(title="Discovered behaviour groups")
            group_table.add_column("behaviour")
            group_table.add_column("pages", justify="right")
            for group in result.site_map.groups:
                group_table.add_row(group.name, str(len(group.pages)))
            console.print(group_table)
        redirect_findings = [
            finding
            for engine_result in result.engine_results
            if engine_result.get("engine") == "open_redirect"
            for finding in engine_result.get("findings", [])
        ]
        if not result.findings and not redirect_findings:
            if not result.tested_targets:
                console.print("[yellow]no testable input surfaces were discovered[/yellow]")
            else:
                console.print("[yellow]no proven vulnerabilities on the tested inputs[/yellow]")
            return
        if result.findings:
            table = Table(title="Website scan — proven XSS", show_lines=True)
            table.add_column("param")
            table.add_column("context")
            table.add_column("payload_id")
            table.add_column("URL")
            for finding in result.findings:
                table.add_row(
                    finding.param, finding.context, finding.probe.payload_id,
                    finding.url,
                )
            console.print(table)
        if redirect_findings:
            redirects = Table(title="Website scan — verified open redirects", show_lines=True)
            redirects.add_column("parameter")
            redirects.add_column("HTTP")
            redirects.add_column("destination")
            redirects.add_column("evidence")
            for finding in redirect_findings:
                redirects.add_row(
                    finding["parameter"],
                    str(finding["status"]),
                    finding["destination"],
                    finding["evidence"],
                )
            console.print(redirects)
        return

    if json_body:
        spec = RequestSpec(
            method="JSON", url=url, json_body=json.loads(json_body),
            headers=request_headers, cookies=request_cookies,
        )
    elif data:
        form = dict(
            pair.split("=", 1)
            for pair in data.split("&")
            if "=" in pair
        )
        spec = RequestSpec(
            method="POST", url=url, form=form,
            headers=request_headers, cookies=request_cookies,
        )
    else:
        spec = RequestSpec(
            method="GET", url=url,
            headers=request_headers, cookies=request_cookies,
        )
    res = asyncio.run(scan(
        spec, proxy=proxy, budget=budget, headless=not headed,
        storage_state=storage_state,
    ))

    if json_out:
        payload = {
            "target": res.target,
            "reached_app": res.reached_app,
            "requests_used": res.requests_used,
            "budget_exhausted": res.budget_exhausted,
            "fingerprint": res.fingerprint,
            "coverage": asdict(res.coverage),
            "reflections": [asdict(c) for c in res.reflections],
            "findings": [
                {"param": f.param, "url": f.url, "payload": f.payload,
                 "payload_id": f.probe.payload_id,
                 "context": f.context,
                 "confidence": f.confidence,
                 "hits": [asdict(h) for h in f.probe.hits],
                 "control_hits": (
                     [asdict(h) for h in f.control_probe.hits]
                     if f.control_probe else None
                 )}
                for f in res.findings
            ],
        }
        typer.echo(json.dumps(payload, indent=2))
        return

    if not res.reached_app:
        console.print("[red]✗ could not reach application (challenge not passed?)[/red]")
        return

    fp = res.fingerprint or {}
    if fp and not fp.get("matches", True):
        console.print(f"[yellow]⚠ {fp['warning']}[/yellow]")

    console.print(f"[dim]requests used: {res.requests_used}"
                  f"{' (BUDGET EXHAUSTED)' if res.budget_exhausted else ''}[/dim]")
    console.print(f"[dim]reflections found: {len(res.reflections)}[/dim]")
    coverage = res.coverage
    skip_text = (
        ", ".join(
            f"{reason}={count}"
            for reason, count in sorted(coverage.skip_reasons.items())
        )
        or "none"
    )
    finding_count = (
        coverage.findings_proven + coverage.findings_uncontrolled
    )
    console.print(
        f"[dim]coverage: {coverage.params_tested} tested, "
        f"{coverage.params_skipped} skipped ({skip_text}), "
        f"{coverage.reflections} reflections, {finding_count} finding(s), "
        f"{coverage.budget_used}/{coverage.budget_limit} requests"
        f"{', blocked' if coverage.blocked else ', not blocked'}[/dim]"
    )

    if not res.findings:
        console.print("[yellow]no proven XSS[/yellow]")
        return

    table = Table(title="Proven XSS", show_lines=True)
    table.add_column("param"); table.add_column("context"); table.add_column("confidence")
    table.add_column("payload_id"); table.add_column("kind"); table.add_column("evidence")
    for f in res.findings:
        kinds = ",".join(sorted({h.kind for h in f.probe.hits
                                 if h.payload_id == f.probe.payload_id}))
        evid = "; ".join(h.detail[:40] for h in f.probe.hits
                         if h.payload_id == f.probe.payload_id)
        table.add_row(
            f.param, f.context, f.confidence, f.probe.payload_id,
            kinds or "?", evid,
        )
    console.print(table)


@app.command(name="session")
def session_cmd(
    url: str = typer.Argument(..., help="Application origin or login page"),
    output: str = typer.Option(".hx/session.json", "--output", help="Private storage-state output path"),
    proxy: Optional[str] = typer.Option(None, help="Proxy URL"),
):
    """Open Chromium for manual login and save an authenticated browser session."""

    async def capture():
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise typer.BadParameter("URL must be an absolute http:// or https:// URL")
        origin = f"{parsed.scheme}://{parsed.netloc}"
        client = TargetClient(origin, proxy=proxy)
        await client.start(
            oracle_init_script=ORACLE_INIT_JS,
            headless=False,
        )
        try:
            try:
                await client.page.goto(
                    url, wait_until="domcontentloaded", timeout=20000
                )
            except Exception:
                pass
            console.print("[bold]Log in using the Chromium window.[/bold]")
            console.print("When the application is authenticated, return here and press Enter.")
            input()
            await client.save_storage_state(output)
        finally:
            await client.close()

    asyncio.run(capture())
    console.print(f"[green]Authenticated session saved to {output}[/green]")
    console.print("[yellow]Treat this file like a password. Do not commit or share it.[/yellow]")


@app.command(name="discover")
def discover_cmd(
    url: str = typer.Argument(..., help="Page URL whose forms should be listed"),
    proxy: Optional[str] = typer.Option(None, help="Proxy URL"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON instead of a table"),
    headed: bool = typer.Option(False, "--headed", help="Show the Chromium browser window"),
    storage_state: Optional[str] = typer.Option(None, "--storage-state", help="Playwright storage-state JSON"),
):
    """List forms and field metadata without submitting them."""

    async def discover():
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        client = TargetClient(origin, proxy=proxy)
        await client.start(
            oracle_init_script=ORACLE_INIT_JS,
            headless=not headed,
            storage_state=storage_state,
        )
        try:
            if not await client.warm():
                return None
            await client.page.goto(
                url, wait_until="domcontentloaded", timeout=20000
            )
            return await discover_forms(client.page)
        finally:
            await client.close()

    forms = asyncio.run(discover())
    if forms is None:
        console.print("[red]✗ could not reach application[/red]")
        raise typer.Exit(1)

    if json_out:
        typer.echo(json.dumps([
            {
                "action": form.action,
                "method": form.method,
                "enctype": form.enctype,
                "fields": [
                    {
                        "name": item.name,
                        "type": item.type,
                        "role": item.role.value,
                    }
                    for item in form.fields
                ],
            }
            for form in forms
        ], indent=2))
        return

    if not forms:
        console.print("[yellow]no forms with eligible fields found[/yellow]")
        return

    for index, form in enumerate(forms, start=1):
        console.print(
            f"[bold]{index}. {form.method} {form.action}[/bold] "
            f"({form.enctype})"
        )
        for item in form.fields:
            color = {
                FieldRole.INJECTABLE: "green",
                FieldRole.STATIC: "yellow",
                FieldRole.SKIP: "dim",
            }[item.role]
            console.print(
                f"    [{color}]{item.role.value:10}[/{color}] "
                f"{item.name} ({item.type})"
            )




if __name__ == "__main__":
    app()
