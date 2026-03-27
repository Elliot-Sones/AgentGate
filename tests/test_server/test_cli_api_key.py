import pytest
from click.testing import CliRunner

from agentgate.cli import cli


def test_api_key_create_command_exists():
    runner = CliRunner()
    result = runner.invoke(cli, ["api-key", "create", "--help"])
    assert result.exit_code == 0
    assert "--name" in result.output
