# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long
import os
from pathlib import Path
from unittest import mock

import pytest

from eze.plugins.tools.node_cyclonedx import NodeCyclonedxTool
from eze.utils.io.file import create_tempfile_path
from eze.utils.error import EzeError
from tests.plugins.tools.tool_helper import ToolMetaTestBase
from tests.__test_helpers__.mock_helper import mock_run_cmd


class TestNodeCyclonedxTool(ToolMetaTestBase):
    ToolMetaClass = NodeCyclonedxTool
    SNAPSHOT_PREFIX = "node-cyclonedx"

    def test_creation__no_config(self):
        # Given
        input_config = {}
        expected_config = {
            "REPORT_FILE": create_tempfile_path("tmp-node-cyclonedx-bom.json"),
            "LICENSE_ALLOWLIST": [],
            "LICENSE_CHECK": "PROPRIETARY",
            "LICENSE_DENYLIST": [],
            #
            "INCLUDE_DEV": False,
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
            "LICENSE_ALLOWLIST": [],
            "LICENSE_CHECK": "PROPRIETARY",
            "LICENSE_DENYLIST": [],
            #
            "INCLUDE_DEV": False,
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

    @mock.patch("eze.core.config.extract_cmd_version", mock.MagicMock(return_value="6.14.11"))
    def test_check_installed__success(self):
        # When
        expected_output = "6.14.11"
        output = NodeCyclonedxTool.check_installed()
        # Then
        assert output == expected_output

    @mock.patch("eze.core.config.extract_cmd_version", mock.MagicMock(return_value=False))
    def test_check_installed__failure_unavailable(self):
        # When
        expected_output = False
        output = NodeCyclonedxTool.check_installed()
        # Then
        assert output == expected_output

    def test_parse_report_snapshot(self, snapshot):
        # Test container fixture and snapshot
        self.assert_parse_report_snapshot_test(snapshot)

    @mock.patch("eze.utils.cli.run.async_subprocess_run")
    @mock.patch("eze.utils.cli.run.is_windows_os", mock.MagicMock(return_value=True))
    @mock.patch("eze.utils.language.node.find_files_by_name", mock.MagicMock(return_value=["package.json"]))
    @mock.patch(
        "eze.plugins.tools.node_cyclonedx.create_absolute_path",
        mock.MagicMock(return_value="OS_NON_SPECIFIC_ABSOLUTE/foo_report.json"),
    )
    @mock.patch("eze.utils.language.node.install_npm_in_path", mock.MagicMock(return_value=True))
    @pytest.mark.asyncio
    async def test_run_scan__cli_command__std(self, mock_async_subprocess_run):
        # Given
        input_config = {"REPORT_FILE": "foo_report.json", "INCLUDE_DEV": False}
        expected_cwd = Path(os.getcwd())
        expected_cmd = "cyclonedx-bom -o OS_NON_SPECIFIC_ABSOLUTE/foo_report.json"

        # Test run calls correct program
        await self.assert_run_scan_command(input_config, expected_cmd, mock_async_subprocess_run, expected_cwd)

    @mock.patch("eze.utils.cli.run.run_async_cmd")
    @mock.patch("eze.utils.cli.run.is_windows_os", mock.MagicMock(return_value=True))
    @mock.patch("eze.utils.language.node.find_files_by_name", mock.MagicMock(return_value=["package.json"]))
    @mock.patch("eze.utils.language.node.install_npm_in_path", mock.MagicMock(return_value=True))
    @pytest.mark.asyncio
    async def test_run_scan__throw_eze_error_on_broken_package(self, mocked_run_cmd):
        # Given
        input_config = {"REPORT_FILE": "foo_report.json"}
        expected_cwd = Path(os.getcwd())
        mock_broken_package_stdout = (
            "There are no components in the BOM. "
            "The project may not contain dependencies or node_modules does not exist. "
            "Executing `npm install` prior to CycloneDX may solve the issue."
        )
        mock_run_cmd(mocked_run_cmd, mock_broken_package_stdout)

        # Test run calls correct program
        with pytest.raises(EzeError) as raised_error:
            testee = self.ToolMetaClass(input_config)
            # When
            await testee.run_scan()
        # Then
        assert raised_error.value.args[0] == mock_broken_package_stdout
