# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long
from unittest import mock

import pytest

from eze.plugins.tools.semgrep import SemGrepTool
from eze.utils.error import EzeError
from eze.utils.io import create_tempfile_path
from tests.plugins.tools.tool_helper import ToolMetaTestBase
from tests.__test_helpers__.mock_helper import mock_run_cmd


class TestSemGrepTool(ToolMetaTestBase):
    ToolMetaClass = SemGrepTool
    SNAPSHOT_PREFIX = "semgrep"

    def test_creation__no_config(self):
        # Given
        expected_config = {
            "CONFIGS": ["p/ci"],
            "EXCLUDE": [],
            "INCLUDE": [],
            "PRINT_TIMING_INFO": False,
            "REPORT_FILE": create_tempfile_path("tmp-semgrep-report.json"),
            "SOURCE": None,
            #
            "ADDITIONAL_ARGUMENTS": "",
            "IGNORED_FILES": None,
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = SemGrepTool()
        # Then
        assert testee.config == expected_config

    def test_creation__with_config(self):
        # Given
        input_config = {
            "ADDITIONAL_ARGUMENTS": "--something foo",
        }
        expected_config = {
            "CONFIGS": ["p/ci"],
            "EXCLUDE": [],
            "INCLUDE": [],
            "PRINT_TIMING_INFO": False,
            "REPORT_FILE": create_tempfile_path("tmp-semgrep-report.json"),
            "SOURCE": None,
            #
            "ADDITIONAL_ARGUMENTS": "--something foo",
            "IGNORED_FILES": None,
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = SemGrepTool(input_config)
        # Then
        assert testee.config == expected_config

    @mock.patch("eze.plugins.tools.semgrep.extract_cmd_version", mock.MagicMock(return_value="1.10.3"))
    def test_check_installed__success(self):
        # When
        expected_output = "1.10.3"
        output = SemGrepTool.check_installed()
        # Then
        assert output == expected_output

    @mock.patch("eze.plugins.tools.semgrep.extract_cmd_version", mock.MagicMock(return_value=False))
    def test_check_installed__failure_unavailable(self):
        # When
        expected_output = False
        output = SemGrepTool.check_installed()
        # Then
        assert output == expected_output

    def test_parse_report__snapshot(self, snapshot):
        # Test container fixture and snapshot
        self.assert_parse_report_snapshot_test(snapshot)

    @mock.patch("eze.utils.cli.async_subprocess_run")
    @mock.patch("eze.utils.cli.is_windows_os", mock.MagicMock(return_value=True))
    @pytest.mark.asyncio
    async def test_run_scan__cli_command__std(self, mock_async_subprocess_run):
        # Given
        input_config = {"ADDITIONAL_ARGUMENTS": "--something foo", "REPORT_FILE": "foo_report.json"}

        expected_cmd = (
            "semgrep --optimizations all --json --time --disable-metrics -q -c p/ci -o foo_report.json --something foo"
        )

        # Test run calls correct program
        await self.assert_run_scan_command(input_config, expected_cmd, mock_async_subprocess_run)

    @mock.patch(
        "eze.plugins.tools.semgrep.extract_cmd_version",
        mock.MagicMock(return_value="ModuleNotFoundError: No module named 'resource'"),
    )
    def test_check_semgrep_not_installed(self):
        # Given
        expected_output = "ModuleNotFoundError: No module named 'resource'"
        # When
        output = SemGrepTool.check_installed()
        # Then
        assert expected_output in output

    @mock.patch("eze.utils.cli.run_cmd")
    @mock.patch("eze.utils.cli.is_windows_os", mock.MagicMock(return_value=True))
    @pytest.mark.asyncio
    async def test_run_scan_without_semgrep_locally_installed_raise_eze_error(self, mocked_run_cmd):
        # Given
        input_config = {}
        input_stdout = "Semgrep ran into an issue"
        # When
        mock_run_cmd(mocked_run_cmd, input_stdout, "ModuleNotFoundError: No module named 'resource'")
        expected_error_message = """[semgrep] semgrep crashed while running, this is likely because semgrep doesn't support native windows yet

As of 2021 semgrep support for windows is limited, until support added you can use eze inside wsl2 to run semgrep on windows
https://github.com/returntocorp/semgrep/issues/1330"""
        # Test run calls correct program
        testee = self.ToolMetaClass(input_config)
        # Then
        with pytest.raises(EzeError) as thrown_exception:
            await testee.run_scan()
        assert expected_error_message == thrown_exception.value.message
