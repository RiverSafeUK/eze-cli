# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long
from unittest import mock

import pytest
import os

from eze.plugins.tools.trufflehog_v3 import TruffleHogv3Tool
from eze.utils.io.file import create_tempfile_path, create_absolute_path
from tests.plugins.tools.tool_helper import ToolMetaTestBase


class TestTruffleHogv3Tool(ToolMetaTestBase):
    ToolMetaClass = TruffleHogv3Tool
    SNAPSHOT_PREFIX = "trufflehog-v3"

    @mock.patch(
        "eze.plugins.tools.trufflehog_v3.get_gitignore_paths", mock.MagicMock(return_value=["some-gitignore-statement"])
    )
    def test_creation__no_config(self):
        # Given
        input_config = {"SOURCE": "eze"}
        expected_config = {
            "SOURCE": ["eze"],
            "DISABLE_DEFAULT_IGNORES": False,
            "CONFIG_FILE": None,
            "REPORT_FILE": create_tempfile_path("tmp-truffleHog-v3-report.json"),
            "INCLUDE_FULL_REASON": True,
            "NO_ENTROPY": False,
            "USE_GIT_IGNORE": True,
            "REGEXES_EXCLUDE_FILE": None,
            #
            "EXCLUDE": [],
            "ADDITIONAL_ARGUMENTS": "",
            "IGNORED_FILES": None,
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
            "USE_SOURCE_COPY": True,
        }
        # When
        testee = TruffleHogv3Tool(input_config)
        # Then
        assert testee.config == expected_config

    @mock.patch("eze.core.config.extract_cmd_version", mock.MagicMock(return_value="3.4.1"))
    def test_check_installed__success(self):
        # When
        expected_output = "3.4.1"
        output = TruffleHogv3Tool.check_installed()
        # Then
        assert output == expected_output

    @mock.patch("eze.core.config.extract_cmd_version", mock.MagicMock(return_value=False))
    def test_check_installed__failure_unavailable(self):
        # When
        expected_output = False
        output = TruffleHogv3Tool.check_installed()
        # Then
        print(output)
        assert output == expected_output

    def test_parse_report(self, snapshot):
        """Trufflehog v3 format parse support"""
        # Given
        input_config = {"SOURCE": "eze"}
        # Test container fixture and snapshot
        self.assert_parse_report_snapshot_test(
            snapshot,
            input_config,
            "__fixtures__/plugins_tools/raw-trufflehogv3-report.json",
            "plugins_tools/trufflehogv3-result-output.json",
        )

    @mock.patch("eze.utils.cli.run.async_subprocess_run")
    @mock.patch("eze.plugins.tools.trufflehog_v3.cache_workspace_into_tmp", mock.MagicMock(return_value=None))
    @pytest.mark.asyncio
    async def test_run_scan__cli_command__init(self, mock_async_subprocess_run: mock.AsyncMock):
        # Given
        input_config = {
            "SOURCE": "eze",
            "REPORT_FILE": "tmp-truffleHog-v3-report.json",
            "DISABLE_DEFAULT_IGNORES": True,
            "USE_GIT_IGNORE": False,
            "USE_SOURCE_COPY": False,
        }
        expected_first_cmd = "git init"
        # Test run calls correct program
        await self.assert_run_scan_command(input_config, expected_first_cmd, mock_async_subprocess_run)
