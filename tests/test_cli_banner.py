from typer.testing import CliRunner

from hx import cli


def test_no_arguments_prints_a_banner_and_command_help(monkeypatch):
    monkeypatch.setattr(cli, "_random_banner", lambda: "TEST HX BANNER")

    result = CliRunner().invoke(cli.app, [])

    assert result.exit_code == 0
    assert "TEST HX BANNER" in result.stdout
    assert "Usage:" in result.stdout
    assert "scan" in result.stdout
    assert "scan-cmd" not in result.stdout
    assert "discover" in result.stdout
    assert "version" in result.stdout


def test_explicit_help_does_not_print_banner(monkeypatch):
    monkeypatch.setattr(cli, "_random_banner", lambda: "TEST HX BANNER")

    result = CliRunner().invoke(cli.app, ["--help"])

    assert result.exit_code == 0
    assert "TEST HX BANNER" not in result.stdout
    assert "Usage:" in result.stdout


def test_banner_selection_can_change_between_runs(monkeypatch):
    monkeypatch.setattr(cli.random, "choice", lambda banners: banners[0])
    first = cli._random_banner()
    monkeypatch.setattr(cli.random, "choice", lambda banners: banners[-1])

    assert cli._random_banner() != first
