from unittest import mock

from eze.plugins.tools.java_dependencycheck import JavaDependencyCheckTool
from eze.utils.io import create_tempfile_path
from tests.__fixtures__.fixture_helper import (
    create_mocked_stream,
)
from tests.plugins.tools.tool_helper import ToolMetaTestBase


class TestJavaDependencyCheckTool(ToolMetaTestBase):
    ToolMetaClass = JavaDependencyCheckTool
    SNAPSHOT_PREFIX = "java-dependencycheck"

    def test_creation__no_config(self):
        # Given
        input_config = {}
        expected_config = {
            "MVN_REPORT_FILE": "target/dependency-check-report.json",
            "REPORT_FILE": create_tempfile_path("tmp-java-dependencycheck.json"),
            #
            "ADDITIONAL_ARGUMENTS": "",
            "IGNORED_FILES": None,
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = JavaDependencyCheckTool(input_config)
        # Then
        assert testee.config == expected_config

    def test_creation__with_config(self):
        # Given
        input_config = {"ADDITIONAL_ARGUMENTS": "--foo", "REPORT_FILE": "tmp-java-dependencycheck.json"}
        expected_config = {
            "MVN_REPORT_FILE": "target/dependency-check-report.json",
            "REPORT_FILE": "tmp-java-dependencycheck.json",
            #
            "ADDITIONAL_ARGUMENTS": "--foo",
            "IGNORED_FILES": None,
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = JavaDependencyCheckTool(input_config)
        # Then
        assert testee.config == expected_config

    @mock.patch(
        "eze.plugins.tools.java_dependencycheck.extract_version_from_maven", mock.MagicMock(return_value="""2.5.2""")
    )
    def test_check_installed__success(self):
        # When
        expected_output = "2.5.2"
        output = JavaDependencyCheckTool.check_installed()
        # Then
        assert output == expected_output

    @mock.patch("eze.plugins.tools.java_dependencycheck.extract_version_from_maven", mock.MagicMock(return_value=False))
    def test_check_installed__failure_unavailable(self):
        # When
        expected_output = False
        output = JavaDependencyCheckTool.check_installed()
        # Then
        assert output == expected_output

    @mock.patch("eze.utils.cve.urllib.request.urlopen")
    def test_parse_report__snapshot(self, mock_urlopen, snapshot):
        # Given
        mock_urlopen.side_effect = create_mocked_stream("__fixtures__/cve/cve_circl_lu_api_cve_cve_2014_8991.json")

        # Test default fixture and snapshot
        self.assert_parse_report_snapshot_test(snapshot)
