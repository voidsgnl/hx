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
from urllib.parse import urlparse

app = typer.Typer(add_completion=False, help="Execution-oracle XSS scanner.")
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
):
    """Scan a URL for reflected/DOM XSS, proving findings via browser execution."""
    if data and json_body:
        raise typer.BadParameter("--data and --json-body are mutually exclusive")
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
        spec, proxy=proxy, budget=budget, headless=not headed
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


@app.command(name="discover")
def discover_cmd(
    url: str = typer.Argument(..., help="Page URL whose forms should be listed"),
    proxy: Optional[str] = typer.Option(None, help="Proxy URL"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON instead of a table"),
    headed: bool = typer.Option(False, "--headed", help="Show the Chromium browser window"),
):
    """List forms and field metadata without submitting them."""

    async def discover():
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        client = TargetClient(origin, proxy=proxy)
        await client.start(
            oracle_init_script=ORACLE_INIT_JS,
            headless=not headed,
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