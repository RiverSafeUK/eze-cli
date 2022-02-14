# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long
from unittest import mock

import os
import pytest
from eze.plugins.tools.checkmarx_kics import KicsTool
from eze.utils.io import create_tempfile_path
from tests.plugins.tools.tool_helper import ToolMetaTestBase


class TestKicsTool(ToolMetaTestBase):
    ToolMetaClass = KicsTool
    SNAPSHOT_PREFIX = "kics"

    def test_creation__no_config(self):
        # Given
        input_config = {}
        expected_config = {
            "SOURCE": ".",
            "CONFIG_FILE": None,
            "REPORT_FILE": create_tempfile_path("tmp-kics-report.json"),
            "REPORT_PATH": os.path.dirname(create_tempfile_path("tmp-kics-report.json")),
            "REPORT_FILENAME": "tmp-kics-report.json",
            "INCLUDE_FULL_REASON": True,
            "DISABLE_SECRET_SCANNING": False,
            "ENABLE_SBOM": False,
            "EXCLUDE": [".terraform"],
            "WINDOWS_DOCKER_WORKAROUND": False,
            #
            "ADDITIONAL_ARGUMENTS": "",
            "IGNORED_FILES": None,
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = KicsTool(input_config)
        # Then
        assert testee.config == expected_config

    def test_creation__with_config(self):
        # Given
        input_config = {
            "SOURCE": "eze",
            "ADDITIONAL_ARGUMENTS": "--something foo",
            "REPORT_FILE": "C:/Users/User1/temp-kics-file.json",
            "CONFIG_FILE": None,
            "INCLUDE_FULL_REASON": True,
        }
        expected_config = {
            "SOURCE": "eze",
            "REPORT_PATH": "C:/Users/User1",
            "REPORT_FILENAME": "temp-kics-file.json",
            "REPORT_FILE": "C:/Users/User1/temp-kics-file.json",
            "CONFIG_FILE": None,
            "INCLUDE_FULL_REASON": True,
            "DISABLE_SECRET_SCANNING": False,
            "ENABLE_SBOM": False,
            "EXCLUDE": [".terraform"],
            "WINDOWS_DOCKER_WORKAROUND": False,
            #
            "ADDITIONAL_ARGUMENTS": "--something foo",
            "IGNORED_FILES": None,
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = KicsTool(input_config)
        # Then
        assert testee.config == expected_config

    @mock.patch("eze.plugins.tools.checkmarx_kics.extract_cmd_version", mock.MagicMock(return_value="""1.4.4"""))
    def test_check_installed__success(self):
        # When
        expected_output = "1.4.4"
        output = KicsTool.check_installed()
        # Then
        assert output == expected_output

    def test_parse_report__snapshot(self, snapshot):
        # Test container fixture and snapshot
        self.assert_parse_report_snapshot_test(snapshot)

    @mock.patch("eze.utils.cli.async_subprocess_run")
    @mock.patch("eze.utils.cli.is_windows_os", mock.MagicMock(return_value=True))
    @pytest.mark.asyncio
    async def test_run_scan__cli_command__multi_value_flag_exclude_and_no_folder_path_given(
        self, mock_async_subprocess_run
    ):
        # Given
        input_config = {
            "SOURCE": "eze",
            "REPORT_FILE": "tmp-kics-report.json",
            "EXCLUDE": [
                "PATH-TO-EXCLUDED-FOLDER/.*",
                "PATH-TO-NESTED-FOLDER/SOME_NESTING/.*",
                "PATH-TO-EXCLUDED-FILE.js",
            ],
        }

        expected_cmd = 'kics scan -s --report-formats json,cyclonedx -p eze --output-path . --output-name tmp-kics-report.json -e= "PATH-TO-EXCLUDED-FOLDER/.*" "PATH-TO-NESTED-FOLDER/SOME_NESTING/.*" PATH-TO-EXCLUDED-FILE.js .terraform'

        # Test run calls correct program
        await self.assert_run_scan_command(input_config, expected_cmd, mock_async_subprocess_run)

    @mock.patch("eze.utils.cli.async_subprocess_run")
    @pytest.mark.asyncio
    async def test_run_scan__cli_command_with_multi_sources_and_report(self, mock_async_subprocess_run):
        # Given
        input_config = {
            "SOURCE": "Dockerfile,azure-pipelines.yml",
            "REPORT_FILE": "C:/Users/User1/tmp-kics-report.json",
        }
        expected_cmd = "kics scan -s --report-formats json,cyclonedx -p Dockerfile,azure-pipelines.yml --output-path C:/Users/User1 --output-name tmp-kics-report.json -e= .terraform"
        # Test run calls correct program
        await self.assert_run_scan_command(input_config, expected_cmd, mock_async_subprocess_run)
