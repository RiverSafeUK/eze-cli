# pylint: disable=missing-module-docstring,missing-class-docstring
from unittest import mock

import pytest

from eze.plugins.tools.node_cyclonedx import NodeCyclonedxTool
from eze.utils.io import create_tempfile_path
from tests.plugins.tools.tool_helper import ToolMetaTestBase


class TestNodeCyclonedxTool(ToolMetaTestBase):
    ToolMetaClass = NodeCyclonedxTool
    SNAPSHOT_PREFIX = "node-cyclonedx"

    def test_creation__no_config(self):
        # Given
        input_config = {}
        expected_config = {
            "REPORT_FILE": create_tempfile_path("tmp-node-cyclonedx-bom.json"),
            #
            "ADDITIONAL_ARGUMENTS": "",
            "IGNORED_FILES": None,
            "EXCLUDE": [],
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = NodeCyclonedxTool(input_config)
        # Then
        assert testee.config == expected_config

    def test_creation__with_config(self):
        # Given
        input_config = {"ADDITIONAL_ARGUMENTS": "--foo", "REPORT_FILE": "tmp-node-cyclonedx-bom.json"}
        expected_config = {
            "REPORT_FILE": "tmp-node-cyclonedx-bom.json",
            #
            "ADDITIONAL_ARGUMENTS": "--foo",
            "IGNORED_FILES": None,
            "EXCLUDE": [],
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = NodeCyclonedxTool(input_config)
        # Then
        assert testee.config == expected_config

    @mock.patch("eze.plugins.tools.node_cyclonedx.extract_cmd_version", mock.MagicMock(return_value="6.14.11"))
    def test_check_installed__success(self):
        # When
        expected_output = "6.14.11"
        output = NodeCyclonedxTool.check_installed()
        # Then
        assert output == expected_output

    @mock.patch("eze.plugins.tools.node_cyclonedx.extract_cmd_version", mock.MagicMock(return_value=False))
    def test_check_installed__failure_unavailable(self):
        # When
        expected_output = False
        output = NodeCyclonedxTool.check_installed()
        # Then
        assert output == expected_output

    def test_parse_report_snapshot(self, snapshot):
        # Test container fixture and snapshot
        self.assert_parse_report_snapshot_test(snapshot)

    @mock.patch("eze.utils.cli.subprocess.run")
    @mock.patch("eze.utils.cli.is_windows_os", mock.MagicMock(return_value=True))
    @mock.patch("eze.utils.language.node.install_node_dependencies", mock.MagicMock(return_value=True))
    @pytest.mark.asyncio
    async def test_run_scan_command__std(self, mock_subprocess_run):
        # Given
        input_config = {"REPORT_FILE": "foo_report.json"}

        expected_cmd = "cyclonedx-bom -o foo_report.json"

        # Test run calls correct program
        await self.assert_run_scan_command(input_config, expected_cmd, mock_subprocess_run)
