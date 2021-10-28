# pylint: disable=missing-module-docstring,missing-class-docstring
from unittest import mock

import pytest

from eze.plugins.tools.container_trivy import TrivyTool
from eze.utils.io import create_tempfile_path
from eze.utils.config import ConfigException
from tests.plugins.tools.tool_helper import ToolMetaTestBase


class TestTrivyTool(ToolMetaTestBase):
    ToolMetaClass = TrivyTool
    SNAPSHOT_PREFIX = "container-trivy"

    def test_creation__no_image_fail_needs_source(self):
        # Given
        expected_error_message = "required param 'IMAGE_NAME' or 'IMAGE_FILE' missing from configuration"
        # When
        with pytest.raises(ConfigException) as thrown_exception:
            testee = TrivyTool()
        # Then
        assert thrown_exception.value.message == expected_error_message

    def test_creation__with_IMAGE_FILE_config(self):
        # Given
        input_config = {
            "IMAGE_FILE": "python_3_8_slim.tar",
        }
        expected_config = {
            "IMAGE_NAME": "",
            "IMAGE_FILE": "python_3_8_slim.tar",
            "REPORT_FILE": create_tempfile_path("tmp-trivy-report.json"),
            "TRIVY_IGNORE_UNFIXED": "false",
            "TRIVY_VULN_TYPE": "os,library",
            #
            "ADDITIONAL_ARGUMENTS": "",
            "IGNORED_FILES": None,
            "EXCLUDE": [],
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = TrivyTool(input_config)
        # Then
        assert testee.config == expected_config

    def test_creation__with_IMAGE_config(self):
        # Given
        input_config = {
            "IMAGE_NAME": "python:3.8-slim",
            "TRIVY_VULN_TYPE": ["os"],
            "TRIVY_IGNORE_UNFIXED": "true",
            "ADDITIONAL_ARGUMENTS": "--something foo",
        }
        expected_config = {
            "IMAGE_NAME": "python:3.8-slim",
            "IMAGE_FILE": "",
            "REPORT_FILE": create_tempfile_path("tmp-trivy-report.json"),
            "TRIVY_IGNORE_UNFIXED": "true",
            "TRIVY_VULN_TYPE": "os",
            #
            "ADDITIONAL_ARGUMENTS": "--something foo",
            "IGNORED_FILES": None,
            "EXCLUDE": [],
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = TrivyTool(input_config)
        # Then
        assert testee.config == expected_config

    @mock.patch("eze.plugins.tools.container_trivy.extract_cmd_version", mock.MagicMock(return_value="1.7.0"))
    def test_check_installed__success(self):
        # When
        expected_output = "1.7.0"
        output = TrivyTool.check_installed()
        # Then
        assert output == expected_output

    @mock.patch("eze.plugins.tools.container_trivy.extract_cmd_version", mock.MagicMock(return_value=False))
    def test_check_installed__failure_unavailable(self):
        # When
        expected_output = False
        output = TrivyTool.check_installed()
        # Then
        assert output == expected_output

    def test_parse_report__snapshot(self, snapshot):
        # Test container fixture and snapshot
        input_config = {
            "IMAGE_FILE": "python_3_8_slim.tar",
        }
        self.assert_parse_report_snapshot_test(snapshot, input_config)

    @mock.patch("eze.utils.cli.subprocess.run")
    @mock.patch("eze.utils.cli.is_windows_os", mock.MagicMock(return_value=True))
    @pytest.mark.asyncio
    async def test_run_scan_command__std(self, mock_subprocess_run):
        # Given
        input_config = {
            "IMAGE_NAME": "python:3.8-slim",
            "TRIVY_VULN_TYPE": ["os"],
            "TRIVY_IGNORE_UNFIXED": "true",
            "ADDITIONAL_ARGUMENTS": "--something foo",
            "REPORT_FILE": "foo_report.json",
        }

        expected_cmd = "trivy image --no-progress --format=json --vuln-type=os --ignore-unfixed=true -o=foo_report.json python:3.8-slim --something foo"

        # Test run calls correct program
        await self.assert_run_scan_command(input_config, expected_cmd, mock_subprocess_run)
