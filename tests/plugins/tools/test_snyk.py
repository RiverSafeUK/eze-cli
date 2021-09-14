# pylint: disable=missing-module-docstring,missing-class-docstring
from unittest import mock

from eze.plugins.tools.snyk import SnykTool, SnykContainerTool, SnykIacTool
from eze.utils.io import create_tempfile_path
from tests.plugins.tools.tool_helper import ToolMetaTestBase


class TestSnykTool(ToolMetaTestBase):
    ToolMetaClass = SnykTool
    SNAPSHOT_PREFIX = "snyk"

    def test_creation__no_config(self):
        # Given
        expected_config = {
            "PACKAGE_FILE": None,
            "PACKAGE_MANAGER": None,
            "REPORT_FILE": create_tempfile_path("tmp-snyk-report.json"),
            #
            "ADDITIONAL_ARGUMENTS": "",
            "IGNORED_FILES": None,
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = SnykTool()
        # Then
        assert testee.config == expected_config

    def test_creation__with_config(self):
        # Given
        input_config = {
            "ADDITIONAL_ARGUMENTS": "--something foo",
            "PACKAGE_FILE": "somewhere/package.json",
            "PACKAGE_MANAGER": "npm",
        }
        expected_config = {
            "PACKAGE_FILE": "somewhere/package.json",
            "PACKAGE_MANAGER": "npm",
            "REPORT_FILE": create_tempfile_path("tmp-snyk-report.json"),
            #
            "ADDITIONAL_ARGUMENTS": "--something foo",
            "IGNORED_FILES": None,
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = SnykTool(input_config)
        # Then
        assert testee.config == expected_config

    @mock.patch("eze.plugins.tools.snyk.extract_cmd_version", mock.MagicMock(return_value="1.531.0"))
    def test_check_installed__success(self):
        # When
        SnykTool._version_cache = None
        expected_output = "1.531.0"
        output = SnykTool.check_installed()
        # Then
        assert output == expected_output

    @mock.patch("eze.plugins.tools.snyk.extract_cmd_version", mock.MagicMock(return_value="NOT TO BE CALLED"))
    def test_check_installed__success_with_cache(self):
        # When
        SnykTool._version_cache = "1.531.Cache-Version"
        expected_output = "1.531.Cache-Version"
        output = SnykTool.check_installed()
        # Then
        assert output == expected_output

    @mock.patch("eze.plugins.tools.snyk.extract_cmd_version", mock.MagicMock(return_value=False))
    def test_check_installed__failure_unavailable(self):
        # When
        SnykTool._version_cache = None
        expected_output = False
        output = SnykTool.check_installed()
        # Then
        assert output == expected_output

    def test_parse_report__node_snapshot(self, snapshot):
        # Test container fixture and snapshot
        self.assert_parse_report_snapshot_test(
            snapshot, {}, "__fixtures__/plugins_tools/raw-snyk-node-report.json", "plugins_tools/snyk-node-output.json"
        )

    def test_parse_report__python_snapshot(self, snapshot):
        # Test container fixture and snapshot
        self.assert_parse_report_snapshot_test(
            snapshot,
            {},
            "__fixtures__/plugins_tools/raw-snyk-python-report.json",
            "plugins_tools/snyk-python-output.json",
        )


class TestSnykContainerTool(ToolMetaTestBase):
    ToolMetaClass = SnykContainerTool
    SNAPSHOT_PREFIX = "snyk-container"

    def test_creation__no_config(self):
        # Given
        input_config = {"DOCKER_TAG": "debian"}
        expected_config = {
            "DOCKERFILE": None,
            "PLATFORM": None,
            "DOCKER_TAG": "debian",
            "REPORT_FILE": create_tempfile_path("tmp-snyk-container-report.json"),
            #
            "ADDITIONAL_ARGUMENTS": "",
            "IGNORED_FILES": None,
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = SnykContainerTool(input_config)
        # Then
        assert testee.config == expected_config

    def test_creation__with_config(self):
        # Given
        input_config = {
            "DOCKER_TAG": "debian:stable",
            "ADDITIONAL_ARGUMENTS": "--something foo",
            "DOCKERFILE": "some-dockerfile/dockerfile",
            "PLATFORM": "linux",
        }
        expected_config = {
            "DOCKER_TAG": "debian:stable",
            "DOCKERFILE": "some-dockerfile/dockerfile",
            "PLATFORM": "linux",
            "REPORT_FILE": create_tempfile_path("tmp-snyk-container-report.json"),
            #
            "ADDITIONAL_ARGUMENTS": "--something foo",
            "IGNORED_FILES": None,
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = SnykContainerTool(input_config)
        # Then
        assert testee.config == expected_config

    def test_parse_report__snapshot(self, snapshot):
        # Given
        input_config = {"DOCKER_TAG": "debian"}

        # Test container fixture and snapshot
        self.assert_parse_report_snapshot_test(snapshot, input_config)


class TestSnykIacTool(ToolMetaTestBase):
    ToolMetaClass = SnykIacTool
    SNAPSHOT_PREFIX = "snyk-iac"

    def test_creation__no_config(self):
        # Given
        input_config = {
            "SOURCE": "goat-owasp-kubernettes/batch-check",
        }
        expected_config = {
            "SOURCE": "goat-owasp-kubernettes/batch-check",
            "REPORT_FILE": create_tempfile_path("tmp-snyk-iac-report.json"),
            #
            "ADDITIONAL_ARGUMENTS": "",
            "IGNORED_FILES": None,
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = SnykIacTool(input_config)
        # Then
        assert testee.config == expected_config

    def test_creation__with_config(self):
        # Given
        input_config = {"SOURCE": "goat-owasp-kubernettes/batch-check", "ADDITIONAL_ARGUMENTS": "--something foo"}
        expected_config = {
            "SOURCE": "goat-owasp-kubernettes/batch-check",
            "REPORT_FILE": create_tempfile_path("tmp-snyk-iac-report.json"),
            #
            "ADDITIONAL_ARGUMENTS": "--something foo",
            "IGNORED_FILES": None,
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = SnykIacTool(input_config)
        # Then
        assert testee.config == expected_config

    def test_parse_report__snapshot(self, snapshot):
        # Given
        input_config = {
            "SOURCE": "goat-owasp-kubernettes/batch-check",
        }

        # Test container fixture and snapshot
        self.assert_parse_report_snapshot_test(snapshot, input_config)
