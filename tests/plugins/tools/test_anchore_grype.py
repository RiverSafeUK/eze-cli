# pylint: disable=missing-module-docstring,missing-class-docstring
from unittest import mock

import pytest

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
            "EXCLUDE": [],
            "IGNORED_VULNERABILITIES": None,
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
            "EXCLUDE": [],
            "IGNORED_VULNERABILITIES": None,
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

    @mock.patch("eze.utils.cli.subprocess.run")
    @mock.patch("eze.utils.cli.is_windows_os", mock.MagicMock(return_value=True))
    @pytest.mark.asyncio
    async def test_run_scan_command__std(self, mock_subprocess_run):
        # Given
        input_config = {
            "SOURCE": "python",
            "CONFIG_FILE": "something.json",
            "ADDITIONAL_ARGUMENTS": "--something foo",
            "REPORT_FILE": "foo-report.json",
        }

        expected_cmd = "grype -o=json -c=something.json python --something foo"

        # Test run calls correct program
        await self.assert_run_scan_command(input_config, expected_cmd, mock_subprocess_run)
