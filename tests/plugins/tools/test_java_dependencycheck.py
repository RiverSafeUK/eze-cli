# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long
import os
from pathlib import Path
from unittest import mock

import pytest

from eze.plugins.tools.java_dependencycheck import JavaDependencyCheckTool
from eze.utils.io import create_tempfile_path
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
            "EXCLUDE": [],
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
            "EXCLUDE": [],
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

    def test_parse_report__snapshot(self, snapshot):
        # Given

        # Test default fixture and snapshot
        self.assert_parse_report_snapshot_test(snapshot)

    def test_parse_report__container_mode_snapshot(self, snapshot):
        # Test container fixture and snapshot
        self.assert_parse_report_snapshot_test(
            snapshot,
            {},
            "__fixtures__/plugins_tools/raw-java-dependencycheck-report--log4j-example.json",
            "plugins_tools/raw-java-dependencycheck-report--log4j-example-output.json",
        )

    @mock.patch("eze.utils.cli.async_subprocess_run")
    @mock.patch("eze.plugins.tools.java_dependencycheck.find_files_by_name", mock.MagicMock(return_value=["pom.xml"]))
    @mock.patch("eze.utils.cli.is_windows_os", mock.MagicMock(return_value=True))
    @pytest.mark.asyncio
    async def test_run_scan__cli_command__std(self, mock_async_subprocess_run):
        # Given
        input_config = {"REPORT_FILE": "foo_report.json"}

        expected_cmd = "mvn -B -Dmaven.javadoc.skip=true -Dmaven.test.skip=true -Dformat=JSON -DprettyPrint install org.owasp:dependency-check-maven:check"
        expected_cwd = Path(os.getcwd())

        # Test run calls correct program
        await self.assert_run_scan_command(input_config, expected_cmd, mock_async_subprocess_run, expected_cwd)
