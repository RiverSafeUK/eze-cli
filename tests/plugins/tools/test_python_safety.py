# pylint: disable=missing-module-docstring,missing-class-docstring
from unittest import mock

from eze.plugins.tools.python_safety import SafetyTool
from eze.utils.io import create_tempfile_path
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
            "APIKEY": None,
            "REPORT_FILE": create_tempfile_path("tmp-sanity-report.json"),
            "REQUIREMENTS_FILES": [],
            #
            "ADDITIONAL_ARGUMENTS": "",
            "IGNORED_FILES": None,
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
            "REPORT_FILE": create_tempfile_path("tmp-sanity-report.json"),
            "REQUIREMENTS_FILES": ["requirements.txt", "requirements-dev.txt"],
            #
            "ADDITIONAL_ARGUMENTS": "--something foo",
            "IGNORED_FILES": None,
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = SafetyTool(input_config)
        # Then
        assert testee.config == expected_config

    @mock.patch("eze.plugins.tools.python_safety.extract_cmd_version", mock.MagicMock(return_value="1.10.3"))
    def test_check_installed__success(self):
        # When
        expected_output = "1.10.3"
        output = SafetyTool.check_installed()
        # Then
        assert output == expected_output

    @mock.patch("eze.plugins.tools.python_safety.extract_cmd_version", mock.MagicMock(return_value=False))
    def test_check_installed__failure_unavailable(self):
        # When
        expected_output = False
        output = SafetyTool.check_installed()
        # Then
        assert output == expected_output

    @mock.patch("eze.utils.cve.urllib.request.urlopen")
    def test_parse_report__snapshot(self, mock_urlopen, snapshot):
        # Given
        mock_urlopen.side_effect = create_mocked_stream("__fixtures__/cve/cve_circl_lu_api_cve_cve_2014_8991.json")

        # Test container fixture and snapshot
        self.assert_parse_report_snapshot_test(snapshot)
