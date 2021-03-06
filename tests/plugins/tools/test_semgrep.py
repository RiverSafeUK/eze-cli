# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long
from unittest import mock

import pytest

from eze.utils.io.file_scanner import delete_file_cache, populate_file_cache
from eze.plugins.tools.semgrep import SemGrepTool
from eze.utils.error import EzeError
from eze.utils.io.file import create_tempfile_path, create_absolute_path
from tests.plugins.tools.tool_helper import ToolMetaTestBase
from tests.__test_helpers__.mock_helper import mock_run_cmd

mock_discovered_folders = ["src"]
mock_ignored_folders = ["node_modules"]
mock_discovered_files = ["Dockerfile", "src/thing.js"]
mock_discovered_filenames = ["Dockerfile", "thing.js"]
mock_discovered_types = {"Dockerfile": 1, ".js": 1}


class TestSemGrepTool(ToolMetaTestBase):
    ToolMetaClass = SemGrepTool
    SNAPSHOT_PREFIX = "semgrep"

    @classmethod
    def setup_class(cls) -> None:
        """Pre-Test Setup func"""
        populate_file_cache(
            mock_discovered_folders,
            mock_ignored_folders,
            mock_discovered_files,
            mock_discovered_filenames,
            mock_discovered_types,
        )

    @classmethod
    def teardown_class(cls) -> None:
        """Post-Test Tear Down func"""
        delete_file_cache()

    def test_creation__no_config(self):
        # Given
        expected_config = {
            # based off mocked populate_file_cache
            "CONFIGS": ["p/ci", "p/dockerfile", "p/nodejs", "p/javascript"],
            "EXCLUDE": [],
            "INCLUDE": [],
            "PRINT_TIMING_INFO": False,
            "REPORT_FILE": create_tempfile_path("tmp-semgrep-report.json"),
            "SOURCE": None,
            "USE_GIT_IGNORE": True,
            "USE_SOURCE_COPY": True,
            #
            "ADDITIONAL_ARGUMENTS": "",
            "IGNORED_FILES": None,
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = SemGrepTool()
        # Then
        assert testee.config == expected_config

    def test_creation__with_config(self):
        # Given
        input_config = {
            "ADDITIONAL_ARGUMENTS": "--something foo",
        }
        expected_config = {
            "CONFIGS": ["p/ci", "p/dockerfile", "p/nodejs", "p/javascript"],
            "EXCLUDE": [],
            "INCLUDE": [],
            "PRINT_TIMING_INFO": False,
            "REPORT_FILE": create_tempfile_path("tmp-semgrep-report.json"),
            "SOURCE": None,
            "USE_GIT_IGNORE": True,
            "USE_SOURCE_COPY": True,
            #
            "ADDITIONAL_ARGUMENTS": "--something foo",
            "IGNORED_FILES": None,
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = SemGrepTool(input_config)
        # Then
        assert testee.config == expected_config

    @mock.patch("eze.core.config.extract_cmd_version", mock.MagicMock(return_value="1.10.3"))
    def test_check_installed__success(self):
        # When
        expected_output = "1.10.3"
        output = SemGrepTool.check_installed()
        # Then
        assert output == expected_output

    @mock.patch("eze.core.config.extract_cmd_version", mock.MagicMock(return_value=False))
    def test_check_installed__failure_unavailable(self):
        # When
        expected_output = False
        output = SemGrepTool.check_installed()
        # Then
        assert output == expected_output

    @mock.patch(
        "eze.core.config.extract_cmd_version",
        mock.MagicMock(return_value="ModuleNotFoundError: No module named 'resource'"),
    )
    def test_check_installed__semgrep_not_installed(self):
        # Given
        expected_output = "ModuleNotFoundError: No module named 'resource'"
        # When
        output = SemGrepTool.check_installed()
        # Then
        assert expected_output in output

    def test_parse_report__snapshot(self, snapshot):
        # Test container fixture and snapshot
        self.assert_parse_report_snapshot_test(snapshot)

    @mock.patch("eze.utils.cli.run.async_subprocess_run")
    @mock.patch("eze.utils.cli.run.is_windows_os", mock.MagicMock(return_value=True))
    @mock.patch("eze.plugins.tools.semgrep.cache_workspace_into_tmp", mock.MagicMock(return_value=None))
    @pytest.mark.asyncio
    async def test_run_scan__cli_command__std(self, mock_async_subprocess_run):
        # Given
        input_config = {
            "ADDITIONAL_ARGUMENTS": "--something foo",
            "REPORT_FILE": "foo_report.json",
            "USE_SOURCE_COPY": False,
        }
        absolute_report = create_absolute_path(input_config["REPORT_FILE"])

        expected_cmd = f"semgrep --optimizations all --json --time --disable-metrics -q --use-git-ignore -c p/ci -c p/dockerfile -c p/nodejs -c p/javascript -o '{absolute_report}' --exclude 'test_*.py' --exclude '*.test.js' --exclude tests --exclude __tests__ --something foo"

        # Test run calls correct program
        await self.assert_run_scan_command(input_config, expected_cmd, mock_async_subprocess_run)

    @mock.patch("eze.utils.cli.run.run_async_cmd")
    @mock.patch("eze.utils.cli.run.is_windows_os", mock.MagicMock(return_value=True))
    @mock.patch("eze.plugins.tools.semgrep.cache_workspace_into_tmp", mock.MagicMock(return_value=None))
    @pytest.mark.asyncio
    async def test_run_scan_without_semgrep_locally_installed_raise_eze_error(self, mocked_run_async_cmd):
        # Given
        input_config = {}
        input_stdout = "Semgrep ran into an issue"
        # When
        mock_run_cmd(mocked_run_async_cmd, input_stdout, "ModuleNotFoundError: No module named 'resource'")
        expected_error_message = """[semgrep] semgrep crashed while running, this is likely because semgrep doesn't support native windows yet

As of 2021 semgrep support for windows is limited, until support added you can use eze inside wsl2 to run semgrep on windows
https://github.com/returntocorp/semgrep/issues/1330"""
        # Test run calls correct program
        testee = self.ToolMetaClass(input_config)
        # Then
        with pytest.raises(EzeError) as raised_error:
            await testee.run_scan()
        assert raised_error.value.message == expected_error_message
