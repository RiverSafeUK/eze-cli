# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long
from unittest import mock

import pytest

from eze.plugins.tools.java_spotbugs import JavaSpotbugsTool
from eze.utils.io import create_tempfile_path
from tests.plugins.tools.tool_helper import ToolMetaTestBase


class TestJavaSpotbugsTool(ToolMetaTestBase):
    ToolMetaClass = JavaSpotbugsTool
    SNAPSHOT_PREFIX = "java-spotbugs"

    def test_creation__no_config(self):
        # Given
        input_config = {}
        expected_config = {
            "MVN_REPORT_FILE": "target/spotbugsXml.xml",
            "REPORT_FILE": create_tempfile_path("tmp-java-spotbugs.json"),
            #
            "ADDITIONAL_ARGUMENTS": "",
            "IGNORED_FILES": None,
            "EXCLUDE": [],
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "INCLUDE_FULL_REASON": True,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = JavaSpotbugsTool(input_config)
        # Then
        assert testee.config == expected_config

    def test_creation__with_config(self):
        # Given
        input_config = {"ADDITIONAL_ARGUMENTS": "--foo", "REPORT_FILE": "tmp-java-spotbugs.json"}
        expected_config = {
            "MVN_REPORT_FILE": "target/spotbugsXml.xml",
            "REPORT_FILE": "tmp-java-spotbugs.json",
            #
            "ADDITIONAL_ARGUMENTS": "--foo",
            "IGNORED_FILES": None,
            "EXCLUDE": [],
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "INCLUDE_FULL_REASON": True,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = JavaSpotbugsTool(input_config)
        # Then
        assert testee.config == expected_config

    @mock.patch("eze.plugins.tools.java_spotbugs.extract_version_from_maven", mock.MagicMock(return_value="""2.5.2"""))
    def test_check_installed__success(self):
        # When
        expected_output = "2.5.2"
        output = JavaSpotbugsTool.check_installed()
        # Then
        assert output == expected_output

    @mock.patch("eze.plugins.tools.java_spotbugs.extract_version_from_maven", mock.MagicMock(return_value=False))
    def test_check_installed__failure_unavailable(self):
        # When
        expected_output = False
        output = JavaSpotbugsTool.check_installed()
        # Then
        assert output == expected_output

    def test_parse_report__snapshot(self, snapshot):
        # Test default fixture and snapshot
        self.assert_parse_report_snapshot_test(snapshot)

    def test_parse_report__empty_case_snapshot(self, snapshot):
        # Test empty fixture and snapshot
        self.assert_parse_report_snapshot_test(
            snapshot,
            {},
            "__fixtures__/plugins_tools/raw-java-spotbugs-report.no-bugs-found.json",
            "plugins_tools/java-spotbugs-no-bugs-found-output.json",
        )

    @mock.patch("eze.utils.cli.subprocess.run")
    @mock.patch("eze.utils.cli.is_windows_os", mock.MagicMock(return_value=True))
    @pytest.mark.asyncio
    async def test_run_scan__cli_command__std(self, mock_subprocess_run):
        # Given
        input_config = {"REPORT_FILE": "foo_report.json"}

        expected_cmd = "mvn -Dmaven.javadoc.skip=true -Dmaven.test.skip=true install com.github.spotbugs:spotbugs-maven-plugin:check"

        # Test run calls correct program
        await self.assert_run_scan_command(input_config, expected_cmd, mock_subprocess_run)
