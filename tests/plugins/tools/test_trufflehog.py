# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long
from unittest import mock

import pytest

from eze.plugins.tools.trufflehog import TruffleHogTool
from eze.utils.io import create_tempfile_path
from tests.plugins.tools.tool_helper import ToolMetaTestBase


class TestTruffleHogTool(ToolMetaTestBase):
    ToolMetaClass = TruffleHogTool
    SNAPSHOT_PREFIX = "trufflehog"

    def test_creation__no_config(self):
        # Given
        input_config = {"SOURCE": "eze"}
        expected_config = {
            "SOURCE": ["eze"],
            "EXCLUDE": [],
            "CONFIG_FILE": None,
            "REPORT_FILE": create_tempfile_path("tmp-truffleHog-report.json"),
            "INCLUDE_FULL_REASON": True,
            "NO_ENTROPY": False,
            #
            "ADDITIONAL_ARGUMENTS": "",
            "IGNORED_FILES": None,
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = TruffleHogTool(input_config)
        # Then
        assert testee.config == expected_config

    def test_creation__with_config(self):
        # Given
        input_config = {
            "SOURCE": ["eze"],
            "ADDITIONAL_ARGUMENTS": "--something foo",
            "CONFIG_FILE": "truffle-config.yaml",
            "INCLUDE_FULL_REASON": False,
        }
        expected_config = {
            "SOURCE": ["eze"],
            "EXCLUDE": [],
            "CONFIG_FILE": "truffle-config.yaml",
            "REPORT_FILE": create_tempfile_path("tmp-truffleHog-report.json"),
            "INCLUDE_FULL_REASON": False,
            "NO_ENTROPY": False,
            #
            "ADDITIONAL_ARGUMENTS": "--something foo",
            "IGNORED_FILES": None,
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = TruffleHogTool(input_config)
        # Then
        assert testee.config == expected_config

    @mock.patch("eze.plugins.tools.trufflehog.is_windows_os", mock.MagicMock(return_value=True))
    def test_creation__with_windows_exclude_config(self):
        # Given
        input_config = {
            "SOURCE": ["eze"],
            "EXCLUDE": [
                "PATH-TO-EXCLUDED-FOLDER/.*",
                "PATH-TO-NESTED-FOLDER/SOME_NESTING/.*",
                "PATH-TO-EXCLUDED-FILE.js",
            ],
        }
        expected_config = {
            "SOURCE": ["eze"],
            "CONFIG_FILE": None,
            "EXCLUDE": [
                "PATH-TO-EXCLUDED-FOLDER\\\\.*",
                "PATH-TO-NESTED-FOLDER\\\\SOME_NESTING\\\\.*",
                "PATH-TO-EXCLUDED-FILE.js",
            ],
            "INCLUDE_FULL_REASON": True,
            "REPORT_FILE": create_tempfile_path("tmp-truffleHog-report.json"),
            "NO_ENTROPY": False,
            #
            "ADDITIONAL_ARGUMENTS": "",
            "IGNORED_FILES": None,
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = TruffleHogTool(input_config)
        # Then
        assert testee.config == expected_config

    @mock.patch("eze.plugins.tools.trufflehog.is_windows_os", mock.MagicMock(return_value=False))
    def test_creation__with_linux_exclude_config(self):
        # Given
        input_config = {
            "SOURCE": ["eze"],
            "EXCLUDE": [
                "PATH-TO-EXCLUDED-FOLDER/.*",
                "PATH-TO-NESTED-FOLDER/SOME_NESTING/.*",
                "PATH-TO-EXCLUDED-FILE.js",
            ],
        }
        expected_config = {
            "SOURCE": ["eze"],
            "CONFIG_FILE": None,
            "EXCLUDE": [
                "PATH-TO-EXCLUDED-FOLDER/.*",
                "PATH-TO-NESTED-FOLDER/SOME_NESTING/.*",
                "PATH-TO-EXCLUDED-FILE.js",
            ],
            "INCLUDE_FULL_REASON": True,
            "REPORT_FILE": create_tempfile_path("tmp-truffleHog-report.json"),
            "NO_ENTROPY": False,
            #
            "ADDITIONAL_ARGUMENTS": "",
            "IGNORED_FILES": None,
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = TruffleHogTool(input_config)
        # Then
        assert testee.config == expected_config

    @mock.patch("eze.plugins.tools.trufflehog.detect_pip_executable_version", mock.MagicMock(return_value="2.0.5"))
    def test_check_installed__success(self):
        # When
        expected_output = "2.0.5"
        output = TruffleHogTool.check_installed()
        # Then
        assert output == expected_output

    @mock.patch("eze.plugins.tools.trufflehog.detect_pip_executable_version", mock.MagicMock(return_value=False))
    def test_check_installed__failure_unavailable(self):
        # When
        expected_output = False
        output = TruffleHogTool.check_installed()
        # Then
        assert output == expected_output

    def test_parse_report__version2_snapshot(self, snapshot):
        """ab-712: Pre Aug 2021 - Trufflehog3 v2 format parse support"""
        # Given
        input_config = {"SOURCE": "eze"}
        # Test container fixture and snapshot
        self.assert_parse_report_snapshot_test(
            snapshot,
            input_config,
            "__fixtures__/plugins_tools/raw-trufflehog-v2-report.json",
            "plugins_tools/trufflehog-result-v2-output.json",
        )

    def test_parse_report__version3_snapshot(self, snapshot):
        """ab-712: Post Aug 2021 - Trufflehog3 v3 format parse support"""
        # Given
        input_config = {"SOURCE": "eze"}
        # Test container fixture and snapshot
        self.assert_parse_report_snapshot_test(
            snapshot,
            input_config,
            "__fixtures__/plugins_tools/raw-trufflehog-v3-report.json",
            "plugins_tools/trufflehog-result-v3-output.json",
        )

    @mock.patch("eze.utils.cli.subprocess.run")
    @pytest.mark.asyncio
    async def test_run_scan__cli_command(self, mock_subprocess_run):
        # Given
        input_config = {"SOURCE": "eze", "REPORT_FILE": "tmp-truffleHog-report.json"}
        expected_cmd = "trufflehog3 --no-history -f json eze -o tmp-truffleHog-report.json"
        # Test run calls correct program
        await self.assert_run_scan_command(input_config, expected_cmd, mock_subprocess_run)

    @mock.patch("eze.utils.cli.subprocess.run")
    @mock.patch("eze.utils.cli.is_windows_os", mock.MagicMock(return_value=True))
    @mock.patch("eze.plugins.tools.trufflehog.is_windows_os", mock.MagicMock(return_value=True))
    @pytest.mark.asyncio
    async def test_run_scan__cli_command__windows_ab_699_multi_value_flag_with_windows_path_escaping(
        self, mock_subprocess_run
    ):
        # Given
        input_config = {
            "SOURCE": "eze",
            "REPORT_FILE": "tmp-truffleHog-report.json",
            "EXCLUDE": [
                "PATH-TO-EXCLUDED-FOLDER/.*",
                "PATH-TO-NESTED-FOLDER/SOME_NESTING/.*",
                "PATH-TO-EXCLUDED-FILE.js",
            ],
        }

        expected_cmd = 'trufflehog3 --no-history -f json eze -o tmp-truffleHog-report.json --exclude "PATH-TO-EXCLUDED-FOLDER\\\\.*" "PATH-TO-NESTED-FOLDER\\\\SOME_NESTING\\\\.*" PATH-TO-EXCLUDED-FILE.js'

        # Test run calls correct program
        await self.assert_run_scan_command(input_config, expected_cmd, mock_subprocess_run)

    @mock.patch("eze.utils.cli.subprocess.run")
    @mock.patch("eze.utils.cli.is_windows_os", mock.MagicMock(return_value=False))
    @mock.patch("eze.plugins.tools.trufflehog.is_windows_os", mock.MagicMock(return_value=False))
    @pytest.mark.asyncio
    async def test_run_scan__cli_command__ab_699_multi_value_flag_with_linux(self, mock_subprocess_run):
        # Given
        input_config = {
            "SOURCE": "eze",
            "REPORT_FILE": "tmp-truffleHog-report.json",
            "EXCLUDE": [
                "PATH-TO-EXCLUDED-FOLDER/.*",
                "PATH-TO-NESTED-FOLDER/SOME_NESTING/.*",
                "PATH-TO-EXCLUDED-FILE.js",
                "FILE WITH SPACES.js",
            ],
        }

        expected_cmd = "trufflehog3 --no-history -f json eze -o tmp-truffleHog-report.json --exclude 'PATH-TO-EXCLUDED-FOLDER/.*' 'PATH-TO-NESTED-FOLDER/SOME_NESTING/.*' PATH-TO-EXCLUDED-FILE.js 'FILE WITH SPACES.js'"
        # Test run calls correct program
        await self.assert_run_scan_command(input_config, expected_cmd, mock_subprocess_run)

    @mock.patch("eze.utils.cli.subprocess.run")
    @mock.patch("eze.utils.cli.is_windows_os", mock.MagicMock(return_value=False))
    @mock.patch("eze.plugins.tools.trufflehog.is_windows_os", mock.MagicMock(return_value=False))
    @pytest.mark.asyncio
    async def test_run_scan__cli_command__ab_699_short_flag(self, mock_subprocess_run):
        # Given
        input_config = {"SOURCE": "eze", "REPORT_FILE": "tmp-truffleHog-report.json", "NO_ENTROPY": True}
        expected_cmd = "trufflehog3 --no-history -f json eze --no-entropy -o tmp-truffleHog-report.json"
        # Test run calls correct program
        await self.assert_run_scan_command(input_config, expected_cmd, mock_subprocess_run)
