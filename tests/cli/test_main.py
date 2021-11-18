# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long

from click.testing import CliRunner

from eze import __version__
from eze.cli.main import cli
from tests.__fixtures__.fixture_helper import get_snapshot_directory


class TestMain:
    def test_cli_base(self, snapshot):
        """Test that the help message appears ok"""
        runner = CliRunner()
        result = runner.invoke(cli, [])
        assert result.exit_code == 0
        snapshot.snapshot_dir = get_snapshot_directory()
        snapshot.assert_match(result.output, "cli_commands/base.txt")

    def test_cli_base__version(self):
        """Test that the version message appears ok"""
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        normalised_output = result.output.strip()
        assert normalised_output == f"cli, version {__version__}"

    def test_cli_base__help(self, snapshot):
        """Test that the help message appears ok with explicit --help flag"""
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        snapshot.snapshot_dir = get_snapshot_directory()
        snapshot.assert_match(result.output, "cli_commands/base_help.txt")
