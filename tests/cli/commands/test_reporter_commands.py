# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long

from click.testing import CliRunner

from eze.cli.commands.reporter_commands import reporters_group
from tests.__fixtures__.fixture_helper import get_snapshot_directory
from tests.__test_helpers__.mock_helper import setup_mock, teardown_mock


class TestReporterCommand:
    def setup_method(self):
        """Clean up method"""
        setup_mock()

    def teardown_module(self):
        """teardown any state that was previously setup with a setup_module method."""
        teardown_mock()

    def test_reporter_base_help(self, snapshot):
        runner = CliRunner()
        result = runner.invoke(reporters_group, ["--help"])
        assert result.exit_code == 0
        snapshot.snapshot_dir = get_snapshot_directory()
        snapshot.assert_match(result.output, "cli_reporter_commands/report_base_help.txt")

    def test_reporter_list(self, snapshot):
        runner = CliRunner()
        result = runner.invoke(reporters_group, ["list"])
        assert result.exit_code == 0
        snapshot.snapshot_dir = get_snapshot_directory()
        snapshot.assert_match(result.output, "cli_reporter_commands/report_list.txt")

    def test_reporter_help(self, snapshot):
        runner = CliRunner()
        result = runner.invoke(reporters_group, ["help", "testee-reporter"])
        assert result.exit_code == 0
        snapshot.snapshot_dir = get_snapshot_directory()
        snapshot.assert_match(result.output, "cli_reporter_commands/report_help.txt")
