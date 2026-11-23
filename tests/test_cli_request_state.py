import json

import pytest
import typer
from typer.testing import CliRunner

from hx import cli
from hx.scanner import ScanResult


def test_cli_passes_repeatable_headers_and_cookies_to_request_spec(monkeypatch):
    captured = {}

    async def fake_scan(spec, **kwargs):
        captured["spec"] = spec
        return ScanResult(target=spec.url, reached_app=False)

    monkeypatch.setattr(cli, "scan", fake_scan)
    result = CliRunner().invoke(cli.app, [
        "scan", "http://example.test/page?q=x",
        "--header", "X-Test-Auth: secret",
        "-H", "Cookie: sid=header; shared=header",
        "--cookie", "sid=flag",
        "--cookie", "other=value",
        "--json",
    ])

    assert result.exit_code == 0, result.stdout
    assert captured["spec"].headers == {"X-Test-Auth": "secret"}
    assert captured["spec"].cookies == {
        "sid": "flag",
        "shared": "header",
        "other": "value",
    }
    assert json.loads(result.stdout)["reached_app"] is False


@pytest.mark.parametrize("option,value", [
    ("--header", "missing-colon"),
    ("--cookie", "missing-equals"),
])
def test_cli_rejects_malformed_auth_options(option, value):
    result = CliRunner().invoke(
        cli.app,
        ["scan", "http://example.test/?q=x", option, value],
    )

    assert result.exit_code == 2
    assert "malformed" in result.output.lower()
