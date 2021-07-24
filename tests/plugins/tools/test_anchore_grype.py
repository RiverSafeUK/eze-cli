# pylint: disable=missing-module-docstring,missing-class-docstring
from unittest import mock

from eze.plugins.tools.anchore_grype import GrypeTool
from eze.utils.io import create_tempfile_path
from tests.plugins.tools.tool_helper import ToolMetaTestBase


class TestGrypeTool(ToolMetaTestBase):
    ToolMetaClass = GrypeTool
    SNAPSHOT_PREFIX = "anchore-grype"

    def test_creation__no_config(self):
        # Given
        input_config = {}
        expected_config = {
            "CONFIG_FILE": None,
            "REPORT_FILE": create_tempfile_path("tmp-grype-report.json"),
            "SOURCE": ".",
            "GRYPE_IGNORE_UNFIXED": False,
            #
            "ADDITIONAL_ARGUMENTS": "",
            "IGNORED_FILES": None,
            "IGNORED_VUNERABLITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = GrypeTool(input_config)
        # Then
        assert testee.config == expected_config

    def test_creation__with_config(self):
        # Given
        input_config = {
            "SOURCE": "python",
            "CONFIG_FILE": "something.json",
            "ADDITIONAL_ARGUMENTS": "--something foo",
        }
        expected_config = {
            "CONFIG_FILE": "something.json",
            "REPORT_FILE": create_tempfile_path("tmp-grype-report.json"),
            "SOURCE": "python",
            "GRYPE_IGNORE_UNFIXED": False,
            #
            "ADDITIONAL_ARGUMENTS": "--something foo",
            "IGNORED_FILES": None,
            "IGNORED_VUNERABLITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = GrypeTool(input_config)
        # Then
        assert testee.config == expected_config

    @mock.patch("eze.plugins.tools.anchore_grype.extract_cmd_version", mock.MagicMock(return_value="1.7.0"))
    def test_check_installed__success(self):
        # When
        expected_output = "1.7.0"
        output = GrypeTool.check_installed()
        # Then
        assert output == expected_output

    @mock.patch("eze.plugins.tools.anchore_grype.extract_cmd_version", mock.MagicMock(return_value=False))
    def test_check_installed__failure_unavailable(self):
        # When
        expected_output = False
        output = GrypeTool.check_installed()
        # Then
        assert output == expected_output

    def test_parse_report__container_mode_snapshot(self, snapshot):
        # Test container fixture and snapshot
        self.assert_parse_report_snapshot_test(
            snapshot,
            {},
            "__fixtures__/plugins_tools/raw-anchore-grype-container-report.json",
            "plugins_tools/anchore-grype-result-container-output.json",
        )

    def test_parse_report__sca_mode_snapshot(self, snapshot):
        # Test container fixture and snapshot
        self.assert_parse_report_snapshot_test(
            snapshot,
            {},
            "__fixtures__/plugins_tools/raw-anchore-grype-sca-npm-report.json",
            "plugins_tools/anchore-grype-result-sca-npm-output.json",
        )
