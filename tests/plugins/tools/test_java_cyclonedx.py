# pylint: disable=missing-module-docstring,missing-class-docstring
from unittest import mock

from eze.plugins.tools.java_cyclonedx import JavaCyclonedxTool
from eze.utils.io import create_tempfile_path
from tests.plugins.tools.tool_helper import ToolMetaTestBase


class TestJavaCyclonedxTool(ToolMetaTestBase):
    ToolMetaClass = JavaCyclonedxTool
    SNAPSHOT_PREFIX = "java-cyclonedx"

    def test_creation__no_config(self):
        # Given
        input_config = {}
        expected_config = {
            "MVN_REPORT_FILE": "target/bom.json",
            "REPORT_FILE": create_tempfile_path("tmp-java-cyclonedx-bom.json"),
            #
            "ADDITIONAL_ARGUMENTS": "",
            "IGNORED_FILES": None,
            "EXCLUDE": [],
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = JavaCyclonedxTool(input_config)
        # Then
        assert testee.config == expected_config

    def test_creation__with_config(self):
        # Given
        input_config = {"ADDITIONAL_ARGUMENTS": "--foo", "REPORT_FILE": "tmp-java-cyclonedx-bom.json"}
        expected_config = {
            "MVN_REPORT_FILE": "target/bom.json",
            "REPORT_FILE": "tmp-java-cyclonedx-bom.json",
            #
            "ADDITIONAL_ARGUMENTS": "--foo",
            "IGNORED_FILES": None,
            "EXCLUDE": [],
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = JavaCyclonedxTool(input_config)
        # Then
        assert testee.config == expected_config

    @mock.patch("eze.plugins.tools.java_cyclonedx.extract_version_from_maven", mock.MagicMock(return_value="""3.8.1"""))
    def test_check_installed__success(self):
        # When
        expected_output = "3.8.1"
        output = JavaCyclonedxTool.check_installed()
        # Then
        assert output == expected_output

    @mock.patch("eze.plugins.tools.java_cyclonedx.extract_version_from_maven", mock.MagicMock(return_value=False))
    def test_check_installed__failure_unavailable(self):
        # When
        expected_output = False
        output = JavaCyclonedxTool.check_installed()
        # Then
        assert output == expected_output

    def test_parse_report_snapshot(self, snapshot):
        # Test default fixture and snapshot
        self.assert_parse_report_snapshot_test(snapshot)
