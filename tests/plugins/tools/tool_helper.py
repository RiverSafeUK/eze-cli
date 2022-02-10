# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long,missing-function-docstring,invalid-name
import shlex

from eze.core.enums import ToolType, SourceType
from eze.core.tool import ToolMeta, ScanResult
from eze.utils.io import pretty_print_json
from tests.__fixtures__.fixture_helper import get_snapshot_directory, load_json_fixture


def throw_exception(cmd):
    full_cmd = shlex.join(cmd)
    raise Exception(full_cmd)


class ToolMetaTestBase:
    ToolMetaClass: ToolMeta = ToolMeta
    SNAPSHOT_PREFIX = "tool-meta"

    def test_help_text_fields(self, snapshot):
        # When
        short_description_output = self.ToolMetaClass.short_description()
        config_output = self.ToolMetaClass.config_help()
        install_output = self.ToolMetaClass.install_help()
        more_info_output = self.ToolMetaClass.more_info()
        # Then
        output = f"""short_description:
======================
{short_description_output}

config_help:
======================
{config_output}

install_help:
======================
{install_output}

more_info:
======================
{more_info_output}
"""
        # WARNING: this is a snapshot test, any changes to format will edit this and the snapshot will need to be updated
        snapshot.snapshot_dir = get_snapshot_directory()
        snapshot.assert_match(output, f"plugins_tools/{self.SNAPSHOT_PREFIX}-help_text.txt")

    def test_TOOL_TYPE__sanity(self):
        # When
        output_raw = self.ToolMetaClass.TOOL_TYPE
        output = self.ToolMetaClass.tool_type()
        # Then
        assert isinstance(output_raw, ToolType)
        assert isinstance(output, ToolType)

    def test_SOURCE_SUPPORT__sanity(self):
        # When
        output_raw = self.ToolMetaClass.SOURCE_SUPPORT
        output = self.ToolMetaClass.source_support()
        # Then
        assert isinstance(output_raw, list)
        assert isinstance(output, list)
        for source_type in output:
            assert isinstance(source_type, SourceType)

    def assert_parse_report_snapshot_test(
        self,
        snapshot,
        input_config: dict = None,
        input_fixture_location: str = None,
        output_fixture_location: str = None,
    ) -> ScanResult:
        """Help function to take a input fixture, and test output matches given snapshot

        Default Input Fixture:
            tests/__fixtures__/plugins_tools/raw-XXX-report.json

        Default Output Snapshot:
            tests/plugins_tools/XXX-result-output.json"""
        # Given
        if not input_config:
            input_config = {}
        if not input_fixture_location:
            input_fixture_location = f"__fixtures__/plugins_tools/raw-{self.SNAPSHOT_PREFIX}-report.json"
        if not output_fixture_location:
            output_fixture_location = f"plugins_tools/{self.SNAPSHOT_PREFIX}-result-output.json"

        input_report = load_json_fixture(input_fixture_location)
        testee = self.ToolMetaClass(input_config)
        # When
        output = testee.parse_report(input_report)
        output_snapshot = pretty_print_json(output)
        print(output_snapshot)
        # Then
        # WARNING: this is a snapshot test, any changes to format will edit this and the snapshot will need to be updated
        snapshot.snapshot_dir = get_snapshot_directory()
        snapshot.assert_match(output_snapshot, output_fixture_location)

        return output

    async def assert_run_scan_command(
        self, input_config: dict = None, expected_command: str = None, mock_async_subprocess_run=None, expected_cwd=None
    ):
        """Help function to take a input config, and test command ran from commandline
        async_subprocess_run = @mock.patch("eze.utils.cli.async_subprocess_run")
        """
        exception_message = "Expected async_subprocess_run called"
        mock_async_subprocess_run.reset_mock()
        mock_async_subprocess_run.side_effect = Exception(exception_message)
        testee = self.ToolMetaClass(input_config)
        # When
        has_errored = False
        try:
            await testee.run_scan()
        except Exception as err:
            assert err.args[0] == exception_message
            has_errored = True

        if not has_errored:
            assert "run_scan did not run any command line programs, async_subprocess_run not called" == "..."

        cmd_as_str = shlex.join(mock_async_subprocess_run.call_args.args[0])
        expected_command_as_list = shlex.split(expected_command)

        # Workaround: DIFF IS TERRIBLE FOR xxx.assert_called_with
        # print assertion fail for debugging
        # see https://github.com/pytest-dev/pytest-asyncio/issues/218
        if cmd_as_str != expected_command:
            print(f"""assert error "{cmd_as_str}" != "{expected_command}" """)
        # Way that assertion should be done, but message is hard to understand
        mock_async_subprocess_run.assert_called_with(expected_command_as_list, cwd=expected_cwd)
