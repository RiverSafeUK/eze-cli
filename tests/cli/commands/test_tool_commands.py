# pylint: disable=missing-module-docstring,missing-class-docstring

from click.testing import CliRunner

from eze.cli.commands.tool_commands import tools_group
from tests.__fixtures__.fixture_helper import get_snapshot_directory
from tests.__test_helpers__.mock_helper import setup_mock, teardown_mock


class TestToolCommand:
    def setup_method(module):
        """Clean up method"""
        setup_mock()

    def teardown_module(module):
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

    def test_tool_list__invalid_tool_type(self, snapshot):
        runner = CliRunner()
        result = runner.invoke(tools_group, ["list", "-t", "NOT_SCA"])
        assert (
            result.output
            == """Could not find tool type 'NOT_SCA'
Available tool types are (SBOM,SCA,SAST,SECRET,MISC)
"""
        )
        assert result.exit_code == 1

    def test_tool_list__invalid_source_type(self, snapshot):
        runner = CliRunner()
        result = runner.invoke(tools_group, ["list", "-s", "NOT_PYTHON"])
        assert (
            result.output
            == """Could not find source type 'NOT_PYTHON'
Available source types are (ALL,PYTHON,NODE,JAVA,GRADLE,SBT,RUBY,GO,PHP,CONTAINER)
"""
        )
        assert result.exit_code == 1

    def test_tool_help(self, snapshot):
        runner = CliRunner()
        result = runner.invoke(tools_group, ["help", "success-tool"])
        snapshot.snapshot_dir = get_snapshot_directory()
        snapshot.assert_match(result.output, "cli_tool_commands/tool_help.txt")
        assert result.exit_code == 0
