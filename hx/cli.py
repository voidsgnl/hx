"""hx — execution-oracle XSS scanner with browser WAF pass."""
import asyncio
import json
from dataclasses import asdict
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from hx import __version__
from hx.scanner import RequestSpec, scan

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
    res = asyncio.run(scan(spec, proxy=proxy, budget=budget))

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

if __name__ == "__main__":
    app()