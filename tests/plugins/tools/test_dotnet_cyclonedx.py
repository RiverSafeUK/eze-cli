# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long
import os
from pathlib import Path
from unittest import mock

import pytest

from eze.plugins.tools.dotnet_cyclonedx import DotnetCyclonedxTool
from eze.utils.io.file import create_tempfile_path
from tests.plugins.tools.tool_helper import ToolMetaTestBase


class TestDotnetCyclonedxTool(ToolMetaTestBase):
    ToolMetaClass = DotnetCyclonedxTool
    SNAPSHOT_PREFIX = "dotnet-cyclonedx"

    def test_creation__no_config(self):
        # Given
        input_config = {}
        expected_config = {
            "REPORT_FILE": create_tempfile_path("tmp-dotnet-cyclonedx-bom"),
            "ADDITIONAL_ARGUMENTS": "",
            "DEFAULT_SEVERITY": None,
            "EXCLUDE": [],
            "IGNORED_FILES": None,
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "LICENSE_ALLOWLIST": [],
            "LICENSE_CHECK": "PROPRIETARY",
            "LICENSE_DENYLIST": [],
            #
            "INCLUDE_DEV": False,
            "_INCLUDE_TEST": False,
        }
        # When
        testee = DotnetCyclonedxTool(input_config)
        # Then
        assert testee.config == expected_config

    def test_creation__with_config(self):
        # Given
        input_config = {
            "INCLUDE_DEV": True,
        }
        expected_config = {
            "REPORT_FILE": create_tempfile_path("tmp-dotnet-cyclonedx-bom"),
            "ADDITIONAL_ARGUMENTS": "",
            "DEFAULT_SEVERITY": None,
            "EXCLUDE": [],
            "IGNORED_FILES": None,
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "LICENSE_ALLOWLIST": [],
            "LICENSE_CHECK": "PROPRIETARY",
            "LICENSE_DENYLIST": [],
            #
            "INCLUDE_DEV": True,
            "_INCLUDE_TEST": True,
        }
        # When
        testee = DotnetCyclonedxTool(input_config)
        # Then
        assert testee.config == expected_config

    @mock.patch("eze.core.config.extract_cmd_version", mock.MagicMock(return_value="6.14.11"))
    def test_check_installed__success(self):
        # When
        expected_output = "6.14.11"
        output = DotnetCyclonedxTool.check_installed()
        # Then
        assert output == expected_output

    @mock.patch("eze.core.config.extract_cmd_version", mock.MagicMock(return_value=False))
    def test_check_installed__failure_unavailable(self):
        # When
        expected_output = False
        output = DotnetCyclonedxTool.check_installed()
        # Then
        assert output == expected_output

    @mock.patch("eze.utils.cli.run.async_subprocess_run")
    @mock.patch("eze.utils.cli.run.is_windows_os", mock.MagicMock(return_value=True))
    @mock.patch("eze.utils.language.dotnet.find_files_by_name", mock.MagicMock(return_value=["Ezeproject.csproj"]))
    @mock.patch(
        "eze.plugins.tools.dotnet_cyclonedx.create_absolute_path",
        mock.MagicMock(return_value="OS_NON_SPECIFIC_ABSOLUTE/foo_report.json"),
    )
    @pytest.mark.asyncio
    async def test_run_scan__cli_command__std(self, mock_async_subprocess_run):
        # Given
        input_config = {"REPORT_FILE": "foo_report.json", "INCLUDE_DEV": False}
        expected_cwd = Path(".")
        expected_cmd = "dotnet CycloneDX --json Ezeproject.csproj -o OS_NON_SPECIFIC_ABSOLUTE/foo_report.json"

        # Test run calls correct program
        await self.assert_run_scan_command(input_config, expected_cmd, mock_async_subprocess_run, expected_cwd)

    @mock.patch("eze.utils.cli.run.async_subprocess_run")
    @mock.patch("eze.utils.cli.run.is_windows_os", mock.MagicMock(return_value=True))
    @mock.patch("eze.utils.language.dotnet.find_files_by_name", mock.MagicMock(return_value=["Ezeproject.csproj"]))
    @mock.patch(
        "eze.plugins.tools.dotnet_cyclonedx.create_absolute_path",
        mock.MagicMock(return_value="OS_NON_SPECIFIC_ABSOLUTE/foo_report.json"),
    )
    @pytest.mark.asyncio
    async def test_run_scan__cli_command__non_prod(self, mock_async_subprocess_run):
        # Given
        input_config = {"REPORT_FILE": "foo_report.json", "INCLUDE_DEV": True}
        expected_cwd = Path(".")
        expected_cmd = "dotnet CycloneDX --json Ezeproject.csproj -d -t -o OS_NON_SPECIFIC_ABSOLUTE/foo_report.json"

        # Test run calls correct program
        await self.assert_run_scan_command(input_config, expected_cmd, mock_async_subprocess_run, expected_cwd)
