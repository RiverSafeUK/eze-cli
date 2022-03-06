# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long
from unittest import mock
from unittest.mock import Mock

import pytest

from eze.plugins.tools.python_cyclonedx import PythonCyclonedxTool
from eze.utils.io.file import create_tempfile_path
from tests.__fixtures__.fixture_helper import (
    load_json_fixture,
)
from tests.plugins.tools.tool_helper import ToolMetaTestBase


class TestPythonCyclonedxTool(ToolMetaTestBase):
    ToolMetaClass = PythonCyclonedxTool
    SNAPSHOT_PREFIX = "python-cyclonedx"

    def test_creation__no_config(self):
        # Given
        expected_config = {
            "REPORT_FILE": create_tempfile_path("tmp-python-cyclonedx-bom.json"),
            "REQUIREMENTS_FILES": [],
            "LICENSE_ALLOWLIST": [],
            "LICENSE_CHECK": "PROPRIETARY",
            "LICENSE_DENYLIST": [],
            #
            "ADDITIONAL_ARGUMENTS": "",
            "IGNORED_FILES": None,
            "EXCLUDE": [],
            "INCLUDE_DEV": False,
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
            "SCA_ENABLED": True,
        }
        # When
        testee = PythonCyclonedxTool()
        # Then
        assert testee.config == expected_config

    def test_creation__with_config(self):
        # Given
        input_config = {
            "REQUIREMENTS_FILES": ["requirements-dev.txt"],
            "ADDITIONAL_ARGUMENTS": "--something foo",
            "REPORT_FILE": "foo-python-cyclonedx-bom.json",
        }
        expected_config = {
            "REQUIREMENTS_FILES": ["requirements-dev.txt"],
            "REPORT_FILE": "foo-python-cyclonedx-bom.json",
            #
            "INCLUDE_DEV": False,
            "ADDITIONAL_ARGUMENTS": "--something foo",
            "IGNORED_FILES": None,
            "EXCLUDE": [],
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
            "LICENSE_ALLOWLIST": [],
            "LICENSE_CHECK": "PROPRIETARY",
            "LICENSE_DENYLIST": [],
            "SCA_ENABLED": True,
        }
        # When
        testee = PythonCyclonedxTool(input_config)
        # Then
        assert testee.config == expected_config

    @mock.patch("eze.core.config.detect_pip_executable_version", mock.MagicMock(return_value="1.10.3"))
    def test_check_installed__success(self):
        # When
        expected_output = "1.10.3"
        output = PythonCyclonedxTool.check_installed()
        # Then
        assert output == expected_output

    @mock.patch("eze.core.config.detect_pip_executable_version", mock.MagicMock(return_value=False))
    def test_check_installed__failure_unavailable(self):
        # When
        expected_output = False
        output = PythonCyclonedxTool.check_installed()
        # Then
        assert output == expected_output

    @mock.patch("eze.utils.data.pypi.request_json")
    @mock.patch("eze.utils.data.cve.request_json")
    def test_parse_report__sca_enabled_snapshot(self, mock_cve_request_json, mock_pypi_request_json, snapshot):
        # Given, mocked the pypi and cve results
        mock_pypi_request_json.return_value = load_json_fixture(
            "__fixtures__/pypi/pypi_org_pypi_aws-encryption-sdk_1_2_0.json"
        )
        mock_cve_request_json.return_value = load_json_fixture(
            "__fixtures__/cve/services_nvd_nist_gov_rest_json_cve_1_0_CVE_2013_5123.json"
        )
        input_fixture_location = f"__fixtures__/plugins_tools/raw-{self.SNAPSHOT_PREFIX}-report--as-sboms.json"
        # Test container fixture and snapshot
        self.assert_parse_report_snapshot_test(
            snapshot,
            {"SCA_ENABLED": True},
            input_fixture_location,
            f"plugins_tools/{self.SNAPSHOT_PREFIX}-result-with-sca-output.json",
        )

    def test_parse_report__sca_disabled_snapshot(self, snapshot):
        # Given
        # Test container fixture and snapshot
        input_fixture_location = f"__fixtures__/plugins_tools/raw-{self.SNAPSHOT_PREFIX}-report--as-sboms.json"
        self.assert_parse_report_snapshot_test(
            snapshot,
            {"SCA_ENABLED": False},
            input_fixture_location,
            f"plugins_tools/{self.SNAPSHOT_PREFIX}-result-without-sca-output.json",
        )

    @mock.patch("eze.utils.cli.run.async_subprocess_run")
    @mock.patch("eze.utils.cli.run.is_windows_os", mock.MagicMock(return_value=True))
    @mock.patch("eze.plugins.tools.python_cyclonedx.find_files_by_name", mock.MagicMock(return_value=[]))
    @mock.patch(
        "eze.plugins.tools.python_cyclonedx.create_absolute_path",
        mock.MagicMock(return_value="OS_NON_SPECIFIC_ABSOLUTE/foo-python-cyclonedx-bom.json"),
    )
    @pytest.mark.asyncio
    async def test_run_scan__cli_command__std_single_project(self, mock_async_subprocess_run):
        # Given
        input_config = {
            "REQUIREMENTS_FILES": ["requirements-dev.txt"],
            "ADDITIONAL_ARGUMENTS": "--something foo",
            "REPORT_FILE": "foo-python-cyclonedx-bom.json",
        }

        expected_cmd = "cyclonedx-py --format=json --force -r -i=requirements-dev.txt -o=OS_NON_SPECIFIC_ABSOLUTE/foo-python-cyclonedx-bom.json --something foo"

        # Test run calls correct program

        await self.assert_run_scan_command(input_config, expected_cmd, mock_async_subprocess_run)

    @mock.patch("eze.plugins.tools.python_cyclonedx.load_json")
    @mock.patch("eze.plugins.tools.python_cyclonedx.run_async_cli_command")
    @pytest.mark.asyncio
    async def test_run_scan_with_unpinned_requirments(self, mocked_run_async_cli_command, mocked_load_json):
        # Given
        run_cli_command_response = Mock()
        run_cli_command_response.stderr = ""
        run_cli_command_response.stdout = """
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!! Some of your dependencies do not have pinned version !!
!! numbers in your requirements.txt                     !!
!!                                                      !!
!! -> semantic-version                                  !!
!! -> toml                                              !!
!! -> xmltodict                                         !!
!!                                                      !!
!! The above will NOT be included in the generated      !!
!! CycloneDX as version is a mandatory field.           !!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
"""
        mocked_run_async_cli_command.return_value = run_cli_command_response

        input_config = {}

        expected_vulnerabilities_overview = [
            "unpinned requirement 'semantic-version' found",
            "unpinned requirement 'toml' found",
            "unpinned requirement 'xmltodict' found",
        ]

        # When
        testee = self.ToolMetaClass(input_config)
        report = await testee.run_scan()

        # Then
        # https://www.w3schools.com/python/ref_set_issubset.asp
        # report.warnings may contain other warnings so we can't assert by "=="
        vulnerabilities_overview = list(map(lambda i: i.overview, report.vulnerabilities))
        assert vulnerabilities_overview == expected_vulnerabilities_overview
