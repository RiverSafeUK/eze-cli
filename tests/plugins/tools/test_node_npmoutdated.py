# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long
import os
from pathlib import Path
from unittest import mock

import pytest

from eze.plugins.tools.node_npmoutdated import NpmOutdatedTool
from eze.utils.io.file import create_tempfile_path
from tests.plugins.tools.tool_helper import ToolMetaTestBase


class TestNpmOutdatedTool(ToolMetaTestBase):
    ToolMetaClass = NpmOutdatedTool
    SNAPSHOT_PREFIX = "node-npmoutdated"

    def test_creation__no_config(self):
        # Given
        input_config = {}
        expected_config = {
            "REPORT_FILE": create_tempfile_path("tmp-npmoutdated-report.json"),
            "NEWER_MAJOR_SEMVERSION_SEVERITY": "medium",
            "NEWER_MINOR_SEMVERSION_SEVERITY": "low",
            "NEWER_PATCH_SEMVERSION_SEVERITY": "none",
            #
            "ADDITIONAL_ARGUMENTS": "",
            "IGNORED_FILES": None,
            "EXCLUDE": [],
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = NpmOutdatedTool(input_config)
        # Then
        assert testee.config == expected_config

    def test_creation__with_config(self):
        # Given
        input_config = {}
        expected_config = {
            "REPORT_FILE": create_tempfile_path("tmp-npmoutdated-report.json"),
            "NEWER_MAJOR_SEMVERSION_SEVERITY": "medium",
            "NEWER_MINOR_SEMVERSION_SEVERITY": "low",
            "NEWER_PATCH_SEMVERSION_SEVERITY": "none",
            #
            "ADDITIONAL_ARGUMENTS": "",
            "IGNORED_FILES": None,
            "EXCLUDE": [],
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = NpmOutdatedTool(input_config)
        # Then
        assert testee.config == expected_config

    @mock.patch("eze.core.config.extract_cmd_version", mock.MagicMock(return_value="6.14.11"))
    def test_check_installed__success(self):
        # When
        expected_output = "6.14.11"
        output = NpmOutdatedTool.check_installed()
        # Then
        assert output == expected_output

    @mock.patch("eze.core.config.extract_cmd_version", mock.MagicMock(return_value="5.12.11"))
    def test_check_installed__failure_version_low(self):
        # When
        expected_output = ""
        output = NpmOutdatedTool.check_installed()
        # Then
        assert output == expected_output

    @mock.patch("eze.core.config.extract_cmd_version", mock.MagicMock(return_value=False))
    def test_check_installed__failure_unavailable(self):
        # When
        expected_output = False
        output = NpmOutdatedTool.check_installed()
        # Then
        assert output == expected_output

    def test_parse_report_snapshot(self, snapshot):
        # Test container fixture and snapshot
        self.assert_parse_report_snapshot_test(snapshot)

    @mock.patch("eze.utils.cli.run.async_subprocess_run")
    @mock.patch("eze.utils.cli.run.is_windows_os", mock.MagicMock(return_value=True))
    @mock.patch("eze.plugins.tools.node_npmoutdated.find_files_by_name", mock.MagicMock(return_value=["package.json"]))
    @mock.patch("eze.utils.language.node.install_npm_in_path", mock.MagicMock(return_value=True))
    @pytest.mark.asyncio
    async def test_run_scan__cli_command__std(self, mock_async_subprocess_run):
        # Given
        input_config = {"REPORT_FILE": "foo_report.json"}
        expected_cwd = Path(os.getcwd())

        expected_cmd = "npm outdated --json"

        # Test run calls correct program
        await self.assert_run_scan_command(input_config, expected_cmd, mock_async_subprocess_run, expected_cwd)
