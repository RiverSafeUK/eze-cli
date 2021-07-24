# pylint: disable=missing-module-docstring,missing-class-docstring
from unittest import mock

from eze.plugins.tools.python_piprot import PiprotTool
from eze.utils.io import create_tempfile_path, pretty_print_json
from tests.__fixtures__.fixture_helper import (
    get_snapshot_directory,
    load_text_fixture,
)
from tests.plugins.tools.tool_helper import ToolMetaTestBase


class TestPiprotTool(ToolMetaTestBase):
    ToolMetaClass = PiprotTool
    SNAPSHOT_PREFIX = "python-piprot"

    def test_creation__no_config(self):
        # Given
        expected_config = {
            "REPORT_FILE": create_tempfile_path("tmp-piprot-report.json"),
            "REQUIREMENTS_FILES": [],
            "HIGH_SEVERITY_AGE_THRESHOLD": 1095,
            "LOW_SEVERITY_AGE_THRESHOLD": 182,
            "MEDIUM_SEVERITY_AGE_THRESHOLD": 730,
            "NEWER_MAJOR_SEMVERSION_SEVERITY": "high",
            "NEWER_MINOR_SEMVERSION_SEVERITY": "medium",
            "NEWER_PATCH_SEMVERSION_SEVERITY": "low",
            #
            "ADDITIONAL_ARGUMENTS": "",
            "IGNORED_FILES": None,
            "IGNORED_VUNERABLITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = PiprotTool()
        # Then
        assert testee.config == expected_config

    def test_creation__with_config(self):
        # Given
        input_config = {
            "REQUIREMENTS_FILES": ["requirements.txt", "requirements-dev.txt"],
            "ADDITIONAL_ARGUMENTS": "--something foo",
        }
        expected_config = {
            "REPORT_FILE": create_tempfile_path("tmp-piprot-report.json"),
            "REQUIREMENTS_FILES": ["requirements.txt", "requirements-dev.txt"],
            "HIGH_SEVERITY_AGE_THRESHOLD": 1095,
            "LOW_SEVERITY_AGE_THRESHOLD": 182,
            "MEDIUM_SEVERITY_AGE_THRESHOLD": 730,
            "NEWER_MAJOR_SEMVERSION_SEVERITY": "high",
            "NEWER_MINOR_SEMVERSION_SEVERITY": "medium",
            "NEWER_PATCH_SEMVERSION_SEVERITY": "low",
            #
            "ADDITIONAL_ARGUMENTS": "--something foo",
            "IGNORED_FILES": None,
            "IGNORED_VUNERABLITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = PiprotTool(input_config)
        # Then
        assert testee.config == expected_config

    @mock.patch("eze.plugins.tools.python_piprot.detect_pip_executable_version", mock.MagicMock(return_value="1.7.0"))
    def test_check_installed__success(self):
        # When
        expected_output = "1.7.0"
        output = PiprotTool.check_installed()
        # Then
        assert output == expected_output

    @mock.patch("eze.plugins.tools.python_piprot.detect_pip_executable_version", mock.MagicMock(return_value=False))
    def test_check_installed__failure_unavailable(self):
        # When
        expected_output = False
        output = PiprotTool.check_installed()
        # Then
        assert output == expected_output

    def test_parse_report__snapshot(self, snapshot):
        # Given

        input_report = load_text_fixture("__fixtures__/plugins_tools/raw-python-piprot-report.txt")
        input_config = {}
        testee = PiprotTool(input_config)
        # When
        output = testee.parse_report(input_report)
        output_snapshot = pretty_print_json(output)
        # Then
        # WARNING: this is a snapshot test, any changes to format will edit this and the snapshot will need to be updated
        snapshot.snapshot_dir = get_snapshot_directory()
        snapshot.assert_match(output_snapshot, "plugins_tools/python-piprot-result-output.json")
