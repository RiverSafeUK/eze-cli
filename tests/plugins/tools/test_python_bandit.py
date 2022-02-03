# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long
from unittest import mock

import pytest

from eze.plugins.tools.python_bandit import BanditTool
from eze.utils.io import create_tempfile_path
from eze.utils.error import EzeConfigError
from tests.plugins.tools.tool_helper import ToolMetaTestBase


class TestBanditTool(ToolMetaTestBase):
    ToolMetaClass = BanditTool
    SNAPSHOT_PREFIX = "python-bandit"

    def test_creation__with_config(self):
        # Given
        input_config = {
            "SOURCE": "src",
            "ADDITIONAL_ARGUMENTS": "--something foo",
        }
        expected_config = {
            "SOURCE": "src",
            #
            "REPORT_FILE": create_tempfile_path("tmp-bandit-report.json"),
            #
            "CONFIG_FILE": "",
            "EXCLUDE": "",
            "INI_PATH": "",
            "INCLUDE_FULL_REASON": True,
            #
            "ADDITIONAL_ARGUMENTS": "--something foo",
            "IGNORED_FILES": None,
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = BanditTool(input_config)
        # Then
        assert testee.config == expected_config

    @mock.patch("eze.plugins.tools.python_bandit.extract_cmd_version", mock.MagicMock(return_value="1.7.0"))
    def test_check_installed__success(self):
        # When
        expected_output = "1.7.0"
        output = BanditTool.check_installed()
        # Then
        assert output == expected_output

    @mock.patch("eze.plugins.tools.python_bandit.extract_cmd_version", mock.MagicMock(return_value=False))
    def test_check_installed__failure_unavailable(self):
        # When
        expected_output = False
        output = BanditTool.check_installed()
        # Then
        assert output == expected_output

    def test_parse_report__snapshot(self, snapshot):
        # Given
        input_config = {"SOURCE": "src"}
        # Test container fixture and snapshot
        self.assert_parse_report_snapshot_test(snapshot, input_config)

    def test_parse_report__error_case_snapshot(self, snapshot):
        # Given
        input_config = {"SOURCE": "src"}
        # Test container fixture and snapshot
        self.assert_parse_report_snapshot_test(
            snapshot,
            input_config,
            "__fixtures__/plugins_tools/raw-python-bandit-with-errors-report.json",
            "plugins_tools/python-bandit-with-errors-output.json",
        )

    @mock.patch("eze.utils.cli.async_subprocess_run")
    @mock.patch("eze.utils.cli.is_windows_os", mock.MagicMock(return_value=True))
    @pytest.mark.asyncio
    async def test_run_scan__cli_command__std(self, mock_async_subprocess_run):
        # Given
        input_config = {"SOURCE": "src", "REPORT_FILE": "foo_report.json"}

        expected_cmd = "bandit -f json -o foo_report.json -r src"

        # Test run calls correct program
        await self.assert_run_scan_command(input_config, expected_cmd, mock_async_subprocess_run)
