# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long
from unittest import mock

import pytest

from eze.plugins.tools.python_cyclonedx import PythonCyclonedxTool
from eze.utils.io import create_tempfile_path
from tests.__fixtures__.fixture_helper import (
    create_mocked_stream,
)
from tests.plugins.tools.tool_helper import ToolMetaTestBase


class TestPythonCyclonedxTool(ToolMetaTestBase):
    ToolMetaClass = PythonCyclonedxTool
    SNAPSHOT_PREFIX = "python-cyclonedx"

    def test_creation__no_config(self):
        # Given
        expected_config = {
            "REPORT_FILE": create_tempfile_path("tmp-python-cyclonedx-bom.json"),
            "REQUIREMENTS_FILE": "",
            "LICENSE_ALLOWLIST": [],
            "LICENSE_CHECK": "PROPRIETARY",
            "LICENSE_DENYLIST": [],
            #
            "ADDITIONAL_ARGUMENTS": "",
            "IGNORED_FILES": None,
            "EXCLUDE": [],
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = PythonCyclonedxTool()
        # Then
        assert testee.config == expected_config

    def test_creation__with_config(self):
        # Given
        input_config = {
            "REQUIREMENTS_FILE": "requirements-dev.txt",
            "ADDITIONAL_ARGUMENTS": "--something foo",
            "REPORT_FILE": "foo-python-cyclonedx-bom.json",
        }
        expected_config = {
            "REQUIREMENTS_FILE": "requirements-dev.txt",
            "REPORT_FILE": "foo-python-cyclonedx-bom.json",
            #
            "ADDITIONAL_ARGUMENTS": "--something foo",
            "IGNORED_FILES": None,
            "EXCLUDE": [],
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
            "LICENSE_ALLOWLIST": [],
            "LICENSE_CHECK": "PROPRIETARY",
            "LICENSE_DENYLIST": [],
        }
        # When
        testee = PythonCyclonedxTool(input_config)
        # Then
        assert testee.config == expected_config

    @mock.patch(
        "eze.plugins.tools.python_cyclonedx.detect_pip_executable_version", mock.MagicMock(return_value="1.10.3")
    )
    def test_check_installed__success(self):
        # When
        expected_output = "1.10.3"
        output = PythonCyclonedxTool.check_installed()
        # Then
        assert output == expected_output

    @mock.patch("eze.plugins.tools.python_cyclonedx.detect_pip_executable_version", mock.MagicMock(return_value=False))
    def test_check_installed__failure_unavailable(self):
        # When
        expected_output = False
        output = PythonCyclonedxTool.check_installed()
        # Then
        assert output == expected_output

    @mock.patch("urllib.request.urlopen")
    def test_parse_report__snapshot(self, mock_urlopen, snapshot):
        # Given
        mock_urlopen.side_effect = create_mocked_stream("__fixtures__/cve/cve_circl_lu_api_cve_cve_2014_8991.json")

        # Test container fixture and snapshot
        self.assert_parse_report_snapshot_test(snapshot)

    @mock.patch("eze.utils.cli.async_subprocess_run")
    @mock.patch("eze.utils.cli.is_windows_os", mock.MagicMock(return_value=True))
    @pytest.mark.asyncio
    async def test_run_scan__cli_command__std(self, mock_async_subprocess_run):
        # Given
        input_config = {
            "REQUIREMENTS_FILE": "requirements-dev.txt",
            "ADDITIONAL_ARGUMENTS": "--something foo",
            "REPORT_FILE": "foo-python-cyclonedx-bom.json",
        }

        expected_cmd = "cyclonedx-py -r --format=json --force -i=requirements-dev.txt -o=foo-python-cyclonedx-bom.json --something foo"

        # Test run calls correct program
        await self.assert_run_scan_command(input_config, expected_cmd, mock_async_subprocess_run)
