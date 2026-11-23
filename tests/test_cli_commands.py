from hx.cli import app


def test_site_mapping_is_not_exposed_as_a_manual_cli_command():
    command_names = {command.name for command in app.registered_commands}
    assert "scan" in command_names
    assert "map" not in command_names
