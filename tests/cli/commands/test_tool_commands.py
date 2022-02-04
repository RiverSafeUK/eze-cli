# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long
import re
from unittest import mock

import pytest
from click.testing import CliRunner

from eze.cli.commands.tool_commands import tools_group
from tests.__fixtures__.fixture_helper import get_snapshot_directory
from tests.__test_helpers__.mock_helper import setup_mock, teardown_mock


class TestToolCommand:
    def setup_method(self):
        """Clean up method"""
        setup_mock()

    def teardown_module(self):
        """teardown any state that was previously setup with a setup_module method."""
        teardown_mock()

    def test_tool_base_help(self, snapshot):
        runner = CliRunner()
        result = runner.invoke(tools_group, ["--help"])
        snapshot.snapshot_dir = get_snapshot_directory()
        snapshot.assert_match(result.output, "cli_tool_commands/tool_base_help.txt")
        assert result.exit_code == 0

    def test_tool_list(self, snapshot):
        runner = CliRunner()
        result = runner.invoke(tools_group, ["list"])
        snapshot.snapshot_dir = get_snapshot_directory()
        snapshot.assert_match(result.output, "cli_tool_commands/tool_list.txt")
        assert result.exit_code == 0

    def test_tool_list__invalid_tool_type(self):
        runner = CliRunner()
        result = runner.invoke(tools_group, ["list", "-t", "NOT_SCA"])
        assert (
            result.output
            == """Could not find tool type 'NOT_SCA'
Available tool types are (SBOM,SCA,SAST,SECRET,MISC)
"""
        )
        assert result.exit_code == 1

    def test_tool_list__invalid_source_type(self):
        runner = CliRunner()
        result = runner.invoke(tools_group, ["list", "-s", "NOT_PYTHON"])
        assert (
            result.output
            == """Could not find source type 'NOT_PYTHON'
Available source types are (ALL,PYTHON,BASH,NODE,JAVA,GRADLE,SBT,RUBY,GO,PHP,CONTAINER)
"""
        )
        assert result.exit_code == 1

    def test_tool_help(self, snapshot):
        runner = CliRunner()
        result = runner.invoke(tools_group, ["help", "success-tool"])
        snapshot.snapshot_dir = get_snapshot_directory()
        snapshot.assert_match(result.output, "cli_tool_commands/tool_help.txt")
        assert result.exit_code == 0

    @pytest.mark.asyncio
    @mock.patch("eze.cli.commands.tool_commands.EzeConfig.refresh_ezerc_config", mock.MagicMock(return_value=None))
    def test_tool_run(self, snapshot):
        # Given
        # When
        runner = CliRunner()
        result = runner.invoke(tools_group, ["run", "success-tool", "-r", "testee-reporter"])
        # Then
        output = re.sub("took [0-9.]+ seconds", "took xxx seconds", result.output)
        snapshot.snapshot_dir = get_snapshot_directory()
        snapshot.assert_match(output, "cli_tool_commands/tool_run.txt")
        assert result.exit_code == 0
