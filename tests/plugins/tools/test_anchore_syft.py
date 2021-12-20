# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long
from unittest import mock

import pytest

from eze.plugins.tools.anchore_syft import SyftTool
from eze.utils.io import create_tempfile_path
from tests.plugins.tools.tool_helper import ToolMetaTestBase


class TestSyftTool(ToolMetaTestBase):
    ToolMetaClass = SyftTool
    SNAPSHOT_PREFIX = "anchore-syft"

    def test_creation__no_config(self):
        # Given
        input_config = {}
        expected_config = {
            "CONFIG_FILE": None,
            "INTERMEDIATE_FILE": create_tempfile_path("tmp-syft-bom.xml"),
            "REPORT_FILE": create_tempfile_path("tmp-syft-bom.json"),
            "SOURCE": ".",
            #
            "ADDITIONAL_ARGUMENTS": "",
            "IGNORED_FILES": None,
            "EXCLUDE": [],
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = SyftTool(input_config)
        # Then
        assert testee.config == expected_config

    def test_creation__with_config(self):
        # Given
        input_config = {
            "SOURCE": "python:3.8-slim",
            "CONFIG_FILE": "something.json",
            "INTERMEDIATE_FILE": "foo-syft-bom.xml",
            "REPORT_FILE": "foo-syft-bom.json",
            "ADDITIONAL_ARGUMENTS": "--something foo",
        }
        expected_config = {
            "CONFIG_FILE": "something.json",
            "INTERMEDIATE_FILE": "foo-syft-bom.xml",
            "REPORT_FILE": "foo-syft-bom.json",
            "SOURCE": "python:3.8-slim",
            #
            "ADDITIONAL_ARGUMENTS": "--something foo",
            "IGNORED_FILES": None,
            "EXCLUDE": [],
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = SyftTool(input_config)
        # Then
        assert testee.config == expected_config

    @mock.patch("eze.plugins.tools.anchore_syft.extract_cmd_version", mock.MagicMock(return_value="1.7.0"))
    def test_check_installed__success(self):
        # When
        expected_output = "1.7.0"
        output = SyftTool.check_installed()
        # Then
        assert output == expected_output

    @mock.patch("eze.plugins.tools.anchore_syft.extract_cmd_version", mock.MagicMock(return_value=False))
    def test_check_installed__failure_unavailable(self):
        # When
        expected_output = False
        output = SyftTool.check_installed()
        # Then
        assert output == expected_output

    def test_parse_report__container_mode_snapshot(self, snapshot):
        # Test container fixture and snapshot
        self.assert_parse_report_snapshot_test(snapshot)

    @mock.patch("eze.utils.cli.async_subprocess_run")
    @mock.patch("eze.utils.cli.is_windows_os", mock.MagicMock(return_value=True))
    @pytest.mark.asyncio
    async def test_run_scan__cli_command__std(self, mock_async_subprocess_run):
        # Given
        input_config = {
            "SOURCE": "python:3.8-slim",
            "CONFIG_FILE": "something.json",
            "INTERMEDIATE_FILE": "foo-syft-bom.xml",
            "REPORT_FILE": "foo-syft-bom.json",
            "ADDITIONAL_ARGUMENTS": "--something foo",
        }

        expected_cmd = "syft -o=cyclonedx -c=something.json python:3.8-slim --something foo"

        # Test run calls correct program
        await self.assert_run_scan_command(input_config, expected_cmd, mock_async_subprocess_run)
