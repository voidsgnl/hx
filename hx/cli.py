"""hx — execution-oracle XSS scanner with browser WAF pass."""
import asyncio
import json
from dataclasses import asdict
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from hx import __version__
from hx.client import TargetClient
from hx.discover import FieldRole, discover_forms
from hx.oracle import ORACLE_INIT_JS
from hx.scanner import RequestSpec, scan
from hx.site_mapper import map_site
from hx.website_scan import scan_website
from urllib.parse import urlparse

app = typer.Typer(add_completion=False, help="Website vulnerability scanner with browser-verified findings.")
console = Console()


@app.command()
def version():
    """Print version."""
    console.print(f"hx {__version__}")


@app.command()
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
    active_post: bool = typer.Option(False, "--active-post", help="Opt in to testing discovered POST forms"),
    include_auth_forms: bool = typer.Option(False, "--include-auth-forms", help="Also test authentication forms; may trigger lockouts or alter login state"),
    storage_state: Optional[str] = typer.Option(None, "--storage-state", help="Playwright storage-state JSON for an authenticated session"),
):
    """Scan an explicit input or automatically map and scan a website."""
    if data and json_body:
        raise typer.BadParameter("--data and --json-body are mutually exclusive")
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
            "target" if data or json_body or parsed_target.query or has_fragment_input
            else "website"
        )
    if active_post and selected_mode != "website":
        raise typer.BadParameter("--active-post is only available in website mode")
    if selected_mode == "website":
        if data or json_body:
            raise typer.BadParameter("--data and --json-body are only valid in target mode")
        result = asyncio.run(scan_website(
            url, proxy=proxy, budget=budget, headless=not headed,
            max_pages=max_pages, max_depth=max_depth,
            active_post=active_post, include_auth_forms=include_auth_forms,
            storage_state=storage_state,
        ))
        if json_out:
            typer.echo(json.dumps(result.to_dict(), indent=2))
            return
        console.print(f"[bold]Website scan:[/bold] {result.target}")
        console.print(
            f"[dim]pages mapped: {len(result.site_map.pages)} | "
            f"targets tested: {len(result.tested_targets)} | "
            f"requests used: {result.requests_used}"
            f"{' (BUDGET EXHAUSTED)' if result.budget_exhausted else ''}[/dim]"
        )
        console.print(
            f"[dim]POST forms mapped but not submitted: {result.skipped_post_forms} | "
            f"POST API endpoints mapped but not tested: {result.skipped_post_endpoints} | "
            f"POST forms tested: {result.post_forms_tested}[/dim]"
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
        spec = RequestSpec(method="JSON", url=url, json_body=json.loads(json_body))
    elif data:
        form = dict(
            pair.split("=", 1)
            for pair in data.split("&")
            if "=" in pair
        )
        spec = RequestSpec(method="POST", url=url, form=form)
    else:
        spec = RequestSpec(method="GET", url=url)
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
            "reflections": [asdict(c) for c in res.reflections],
            "findings": [
                {"param": f.param, "url": f.url, "payload": f.payload,
                 "payload_id": f.probe.payload_id,
                 "context": f.context,
                 "hits": [asdict(h) for h in f.probe.hits]}
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

    if not res.findings:
        console.print("[yellow]no proven XSS[/yellow]")
        return

    table = Table(title="Proven XSS", show_lines=True)
    table.add_column("param"); table.add_column("context"); table.add_column("payload_id")
    table.add_column("kind"); table.add_column("evidence")
    for f in res.findings:
        kinds = ",".join(sorted({h.kind for h in f.probe.hits
                                 if h.payload_id == f.probe.payload_id}))
        evid = "; ".join(h.detail[:40] for h in f.probe.hits
                         if h.payload_id == f.probe.payload_id)
        table.add_row(f.param, f.context, f.probe.payload_id, kinds or "?", evid)
    console.print(table)


app.command(name="scan")(scan_cmd)


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


@app.command(name="map")
def map_cmd(
    url: str = typer.Argument(..., help="Base URL of the website to map"),
    budget: int = typer.Option(300, help="Maximum outbound HTTP requests"),
    max_pages: int = typer.Option(100, "--max-pages", help="Maximum pages to visit"),
    max_depth: int = typer.Option(3, "--max-depth", help="Maximum link depth from the start URL"),
    proxy: Optional[str] = typer.Option(None, help="Proxy URL"),
    json_out: bool = typer.Option(False, "--json", help="Emit the complete site map as JSON"),
    headed: bool = typer.Option(False, "--headed", help="Show the Chromium browser window"),
    storage_state: Optional[str] = typer.Option(None, "--storage-state", help="Playwright storage-state JSON"),
):
    """Map same-origin pages, forms, and browser-observed API endpoints without submitting forms."""
    result = asyncio.run(map_site(
        url, proxy=proxy, budget=budget, max_pages=max_pages,
        max_depth=max_depth, headless=not headed,
        storage_state=storage_state,
    ))
    if json_out:
        typer.echo(json.dumps(result.to_dict(), indent=2))
        return

    console.print(f"[bold]Website map:[/bold] {result.target}")
    console.print(
        f"[dim]pages: {len(result.pages)} | API endpoints: {len(result.endpoints)} | "
        f"requests: {result.requests_used}"
        f"{' | REQUEST BUDGET EXHAUSTED' if result.budget_exhausted else ''}[/dim]"
    )
    if result.pages:
        table = Table(title="Discovered pages", show_lines=True)
        table.add_column("depth", justify="right")
        table.add_column("status", justify="right")
        table.add_column("behaviour")
        table.add_column("parameters")
        table.add_column("URL")
        for page in result.pages:
            table.add_row(
                str(page.depth), str(page.status or "-"), page.behaviour,
                ", ".join(page.query_parameters) or "-",
                page.url,
            )
        console.print(table)

    if result.groups:
        groups = Table(title="Behaviour groups")
        groups.add_column("group")
        groups.add_column("pages", justify="right")
        groups.add_column("form patterns", justify="right")
        groups.add_column("API endpoints", justify="right")
        for group in result.groups:
            groups.add_row(
                group.name, str(len(group.pages)),
                str(len(group.form_signatures)), str(len(group.endpoint_urls)),
            )
        console.print(groups)

    if result.errors:
        console.print("[yellow]Mapping notes:[/yellow]")
        for error in result.errors:
            console.print(f"  - {error}")


if __name__ == "__main__":
    app()