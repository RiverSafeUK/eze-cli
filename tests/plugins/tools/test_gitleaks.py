# pylint: disable=missing-module-docstring,missing-class-docstring
from unittest import mock

from eze.plugins.tools.gitleaks import GitLeaksTool
from eze.utils.io import create_tempfile_path
from tests.plugins.tools.tool_helper import ToolMetaTestBase


class TestGitLeaksTool(ToolMetaTestBase):
    ToolMetaClass = GitLeaksTool
    SNAPSHOT_PREFIX = "gitleaks"

    def test_creation__no_config(self):
        # Given
        input_config = {}
        expected_config = {
            "SOURCE": ".",
            "VERBOSE": True,
            "REPORT_FILE": create_tempfile_path("tmp-gitleaks-report.json"),
            "CONFIG_FILE": None,
            "INCLUDE_FULL_REASON": True,
            #
            "ADDITIONAL_ARGUMENTS": "",
            "IGNORED_FILES": None,
            "IGNORED_VUNERABLITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = GitLeaksTool(input_config)
        # Then
        assert testee.config == expected_config

    def test_creation__with_config(self):
        # Given
        input_config = {
            "SOURCE": "eze",
            "VERBOSE": True,
            "ADDITIONAL_ARGUMENTS": "--something foo",
            "REPORT_FILE": create_tempfile_path("tmp-gitleaks-report.json"),
            "CONFIG_FILE": None,
            "INCLUDE_FULL_REASON": True,
        }
        expected_config = {
            "SOURCE": "eze",
            "VERBOSE": True,
            "REPORT_FILE": create_tempfile_path("tmp-gitleaks-report.json"),
            "CONFIG_FILE": None,
            "INCLUDE_FULL_REASON": True,
            #
            "ADDITIONAL_ARGUMENTS": "--something foo",
            "IGNORED_FILES": None,
            "IGNORED_VUNERABLITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = GitLeaksTool(input_config)
        # Then
        assert testee.config == expected_config

    @mock.patch("eze.plugins.tools.gitleaks.extract_cmd_version", mock.MagicMock(return_value="""v7.5.0"""))
    def test_check_installed__success(self):
        # When
        expected_output = "v7.5.0"
        output = GitLeaksTool.check_installed()
        # Then
        assert output == expected_output

    @mock.patch("eze.plugins.tools.gitleaks.extract_cmd_version", mock.MagicMock(return_value=False))
    def test_check_installed__failure_unavailable(self):
        # When
        expected_output = False
        output = GitLeaksTool.check_installed()
        # Then
        assert output == expected_output

    def test_parse_report__snapshot(self, snapshot):
        # Test container fixture and snapshot
        self.assert_parse_report_snapshot_test(snapshot)

    # INFO: Gitleaks returns null when no results returned (not empty []) test to catch this behaviour
    def test_parse_report__empty_results_snapshot(self, snapshot):
        # Test container fixture and snapshot
        self.assert_parse_report_snapshot_test(
            snapshot,
            {},
            "__fixtures__/plugins_tools/raw-gitleaks-empty-report.json",
            "plugins_tools/gitleaks-empty-result-output.json",
        )
