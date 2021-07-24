# pylint: disable=missing-module-docstring,missing-class-docstring
from unittest import mock

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
            "SOURCE": "eze",
            "EXCLUDE": "",
            "CONFIG_FILE": None,
            "REPORT_FILE": create_tempfile_path("tmp-truffleHog-report.json"),
            "INCLUDE_FULL_REASON": True,
            #
            "ADDITIONAL_ARGUMENTS": "",
            "IGNORED_FILES": None,
            "IGNORED_VUNERABLITIES": None,
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
            "SOURCE": "eze",
            "ADDITIONAL_ARGUMENTS": "--something foo",
            "CONFIG_FILE": "truffle-config.yaml",
            "INCLUDE_FULL_REASON": False,
        }
        expected_config = {
            "SOURCE": "eze",
            "EXCLUDE": "",
            "CONFIG_FILE": "truffle-config.yaml",
            "REPORT_FILE": create_tempfile_path("tmp-truffleHog-report.json"),
            "INCLUDE_FULL_REASON": False,
            #
            "ADDITIONAL_ARGUMENTS": "--something foo",
            "IGNORED_FILES": None,
            "IGNORED_VUNERABLITIES": None,
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
            "SOURCE": "eze",
            "EXCLUDE": [
                "PATH-TO-EXCLUDED-FOLDER/.*",
                "PATH-TO-NESTED-FOLDER/SOME_NESTING/.*",
                "PATH-TO-EXCLUDED-FILE.js",
            ],
        }
        expected_config = {
            "SOURCE": "eze",
            "CONFIG_FILE": None,
            "EXCLUDE": "PATH-TO-EXCLUDED-FOLDER\\\\.* "
            "PATH-TO-NESTED-FOLDER\\\\SOME_NESTING\\\\.* "
            "PATH-TO-EXCLUDED-FILE.js",
            "INCLUDE_FULL_REASON": True,
            "REPORT_FILE": create_tempfile_path("tmp-truffleHog-report.json"),
            #
            "ADDITIONAL_ARGUMENTS": "",
            "IGNORED_FILES": None,
            "IGNORED_VUNERABLITIES": None,
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
            "SOURCE": "eze",
            "EXCLUDE": [
                "PATH-TO-EXCLUDED-FOLDER/.*",
                "PATH-TO-NESTED-FOLDER/SOME_NESTING/.*",
                "PATH-TO-EXCLUDED-FILE.js",
            ],
        }
        expected_config = {
            "SOURCE": "eze",
            "CONFIG_FILE": None,
            "EXCLUDE": "PATH-TO-EXCLUDED-FOLDER/.* "
            "PATH-TO-NESTED-FOLDER/SOME_NESTING/.* "
            "PATH-TO-EXCLUDED-FILE.js",
            "INCLUDE_FULL_REASON": True,
            "REPORT_FILE": create_tempfile_path("tmp-truffleHog-report.json"),
            #
            "ADDITIONAL_ARGUMENTS": "",
            "IGNORED_FILES": None,
            "IGNORED_VUNERABLITIES": None,
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

    def test_parse_report__snapshot(self, snapshot):
        # Given
        input_config = {"SOURCE": "eze"}
        # Test container fixture and snapshot
        self.assert_parse_report_snapshot_test(snapshot, input_config)
