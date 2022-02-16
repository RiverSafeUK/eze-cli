# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long
from unittest import mock

import pytest

from eze.core.tool import ScanResult
from eze.plugins.tools.python_safety import SafetyTool
from eze.utils.io.file import create_tempfile_path
from eze.utils.error import EzeNetworkingError
from tests.__fixtures__.fixture_helper import (
    create_mocked_stream,
)
from tests.plugins.tools.tool_helper import ToolMetaTestBase


class TestSafetyTool(ToolMetaTestBase):
    ToolMetaClass = SafetyTool
    SNAPSHOT_PREFIX = "python-safety"

    def test_creation__no_config(self):
        # Given
        expected_config = {
            "APIKEY": "",
            "REPORT_FILE": create_tempfile_path("tmp-safety-report.json"),
            "REQUIREMENTS_FILES": [],
            #
            "ADDITIONAL_ARGUMENTS": "",
            "IGNORED_FILES": None,
            "EXCLUDE": [],
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = SafetyTool()
        # Then
        assert testee.config == expected_config

    def test_creation__with_config(self):
        # Given
        input_config = {
            "APIKEY": "xxxx-aaaa-bbbb-cccc",
            "REQUIREMENTS_FILES": ["requirements.txt", "requirements-dev.txt"],
            "ADDITIONAL_ARGUMENTS": "--something foo",
        }
        expected_config = {
            "APIKEY": "xxxx-aaaa-bbbb-cccc",
            "REPORT_FILE": create_tempfile_path("tmp-safety-report.json"),
            "REQUIREMENTS_FILES": ["requirements.txt", "requirements-dev.txt"],
            #
            "ADDITIONAL_ARGUMENTS": "--something foo",
            "IGNORED_FILES": None,
            "EXCLUDE": [],
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = SafetyTool(input_config)
        # Then
        assert testee.config == expected_config

    @mock.patch("eze.core.config.extract_cmd_version", mock.MagicMock(return_value="1.10.3"))
    def test_check_installed__success(self):
        # When
        expected_output = "1.10.3"
        output = SafetyTool.check_installed()
        # Then
        assert output == expected_output

    @mock.patch("eze.core.config.extract_cmd_version", mock.MagicMock(return_value=False))
    def test_check_installed__failure_unavailable(self):
        # When
        expected_output = False
        output = SafetyTool.check_installed()
        # Then
        assert output == expected_output

    @mock.patch("urllib.request.urlopen")
    def test_parse_report__snapshot(self, mock_request_json, snapshot):
        # Given
        mock_request_json.side_effect = create_mocked_stream(
            "__fixtures__/cve/services_nvd_nist_gov_rest_json_cve_1_0_CVE_2014_8991.json"
        )

        # Test container fixture and snapshot
        self.assert_parse_report_snapshot_test(snapshot)

    @mock.patch("urllib.request.urlopen")
    def test_parse_report__networking_error__snapshot(self, mock_request_json, snapshot):
        # Given
        mock_request_json.side_effect = EzeNetworkingError("mocked error on networking")

        # Test container fixture and snapshot
        output_scan_result: ScanResult = self.assert_parse_report_snapshot_test(
            snapshot, {}, None, f"plugins_tools/{self.SNAPSHOT_PREFIX}-networking-error-result-output.json"
        )
        assert output_scan_result.warnings == [
            "unable to get cve data for CVE-2013-5123, Error: mocked error on networking"
        ]

    @mock.patch("eze.utils.cli.run.async_subprocess_run")
    @mock.patch("eze.utils.cli.run.is_windows_os", mock.MagicMock(return_value=True))
    @mock.patch("eze.plugins.tools.python_safety.find_files_by_name", mock.MagicMock(return_value=[]))
    @pytest.mark.asyncio
    async def test_run_scan__cli_command__std(self, mock_async_subprocess_run):
        # Given
        input_config = {
            "APIKEY": "xxxx-aaaa-bbbb-cccc",
            "REQUIREMENTS_FILES": ["requirements.txt", "requirements-dev.txt"],
            "ADDITIONAL_ARGUMENTS": "--something foo",
            "REPORT_FILE": "foo_report.json",
        }

        expected_cmd = "safety check --full-report --api=xxxx-aaaa-bbbb-cccc -r requirements.txt -r requirements-dev.txt --json --output foo_report.json --something foo"

        # Test run calls correct program
        await self.assert_run_scan_command(input_config, expected_cmd, mock_async_subprocess_run)
