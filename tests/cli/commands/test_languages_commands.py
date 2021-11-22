# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long

from unittest import mock

from click.testing import CliRunner

from eze.cli.commands.language_commands import languages_group
from tests.__fixtures__.fixture_helper import get_snapshot_directory
from tests.__test_helpers__.mock_helper import setup_mock as setup_mock, teardown_mock


class TestReporterCommand:
    def setup_method(self):
        """Clean up method"""
        setup_mock()

    def teardown_module(self):
        """teardown any state that was previously setup with a setup_module method."""
        teardown_mock()

    @mock.patch("eze.plugins.languages.python.extract_cmd_version", mock.MagicMock(return_value="X.X.X"))
    def test_language_base_help(self, snapshot):
        runner = CliRunner()
        result = runner.invoke(languages_group, ["--help"])
        # assert result.exit_code == 0
        snapshot.snapshot_dir = get_snapshot_directory()
        snapshot.assert_match(result.output, "cli_language_commands/report_base_help.txt")

    @mock.patch("eze.plugins.languages.python.extract_cmd_version", mock.MagicMock(return_value="X.X.X"))
    def test_language_list(self, snapshot):
        runner = CliRunner()
        result = runner.invoke(languages_group, ["list"])
        # assert result.exit_code == 0
        snapshot.snapshot_dir = get_snapshot_directory()
        snapshot.assert_match(result.output, "cli_language_commands/report_list.txt")

    @mock.patch("eze.plugins.languages.python.extract_cmd_version", mock.MagicMock(return_value="X.X.X"))
    def test_language_help(self, snapshot):
        runner = CliRunner()
        result = runner.invoke(languages_group, ["help", "testee-language"])
        # assert result.exit_code == 0
        snapshot.snapshot_dir = get_snapshot_directory()
        snapshot.assert_match(result.output, "cli_language_commands/report_help.txt")
