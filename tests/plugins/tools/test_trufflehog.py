# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long
from unittest import mock

import pytest
import os

from eze.plugins.tools.trufflehog import TruffleHogTool, extract_leading_number
from eze.utils.io.file import create_tempfile_path, create_absolute_path
from tests.plugins.tools.tool_helper import ToolMetaTestBase

DEFAULT_EXCLUDES_WITH_MOCKED_GIT_IGNORE = [
    "*.eot",
    "*.exe",
    "*.ico",
    "*.jpeg",
    "*.jpg",
    "*.lock",
    "*.lock.hcl",
    "*.map",
    "*.min.css",
    "*.min.js",
    "*.png",
    "*.svg",
    "*.ttf",
    "*.webp",
    "*.woff",
    "*.woff2",
    "*.zip",
    ".DS_Store",
    ".aws",
    ".coverage",
    ".env",
    ".eze",
    ".git",
    ".gradle",
    ".idea",
    ".pytest_cache",
    ".terraform",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "errored.tfstate",
    "node_modules",
    "package-lock.json",
    "sdist",
    "some-gitignore-statement",
    "target",
    "vendor",
    "venv",
    "~",
]


def test_extract_leading_number__std():
    expected_output = "1.45434"
    test_input = "1.45434s"
    output = extract_leading_number(test_input)
    assert output == expected_output


class TestTruffleHogTool(ToolMetaTestBase):
    ToolMetaClass = TruffleHogTool
    SNAPSHOT_PREFIX = "trufflehog"

    @mock.patch(
        "eze.plugins.tools.trufflehog.get_gitignore_paths", mock.MagicMock(return_value=["some-gitignore-statement"])
    )
    def test_creation__no_config(self):
        # Given
        input_config = {"SOURCE": "eze"}
        expected_config = {
            "SOURCE": ["eze"],
            "DISABLE_DEFAULT_IGNORES": False,
            "EXCLUDE": DEFAULT_EXCLUDES_WITH_MOCKED_GIT_IGNORE,
            "CONFIG_FILE": None,
            "REPORT_FILE": create_tempfile_path("tmp-truffleHog-report.json"),
            "INCLUDE_FULL_REASON": True,
            "NO_ENTROPY": False,
            "USE_GIT_IGNORE": True,
            #
            "ADDITIONAL_ARGUMENTS": "",
            "IGNORED_FILES": None,
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
            "USE_SOURCE_COPY": True,
        }
        # When
        testee = TruffleHogTool(input_config)
        # Then
        assert testee.config == expected_config

    @mock.patch(
        "eze.plugins.tools.trufflehog.get_gitignore_paths", mock.MagicMock(return_value=["some-gitignore-statement"])
    )
    def test_creation__with_config(self):
        # Given
        input_config = {
            "SOURCE": ["eze"],
            "ADDITIONAL_ARGUMENTS": "--something foo",
            "CONFIG_FILE": "truffle-config.yaml",
            "INCLUDE_FULL_REASON": False,
        }
        expected_config = {
            "SOURCE": ["eze"],
            "DISABLE_DEFAULT_IGNORES": False,
            "EXCLUDE": DEFAULT_EXCLUDES_WITH_MOCKED_GIT_IGNORE,
            "CONFIG_FILE": "truffle-config.yaml",
            "REPORT_FILE": create_tempfile_path("tmp-truffleHog-report.json"),
            "INCLUDE_FULL_REASON": False,
            "NO_ENTROPY": False,
            "USE_GIT_IGNORE": True,
            #
            "ADDITIONAL_ARGUMENTS": "--something foo",
            "IGNORED_FILES": None,
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
            "USE_SOURCE_COPY": True,
        }
        # When
        testee = TruffleHogTool(input_config)
        # Then
        assert testee.config == expected_config

    @mock.patch(
        "eze.plugins.tools.trufflehog.get_gitignore_paths", mock.MagicMock(return_value=["some-gitignore-statement"])
    )
    @mock.patch("eze.plugins.tools.trufflehog.is_windows_os", mock.MagicMock(return_value=True))
    def test_creation__with_windows_exclude_config(self):
        # Given
        EXCLUDES = [
            "PATH-TO-EXCLUDED-FOLDER/.*",
            "PATH-TO-NESTED-FOLDER/SOME_NESTING/.*",
            "PATH-TO-EXCLUDED-FILE.js",
        ]
        # Windows needs different exclude locations
        EXPECTED_NEW_EXCLUDE = [
            "PATH-TO-EXCLUDED-FOLDER\\\\.*",
            "PATH-TO-NESTED-FOLDER\\\\SOME_NESTING\\\\.*",
            "PATH-TO-EXCLUDED-FILE.js",
        ]
        input_config = {
            "SOURCE": ["eze"],
            "EXCLUDE": EXCLUDES,
        }
        EXPECTED_EXCLUDE = DEFAULT_EXCLUDES_WITH_MOCKED_GIT_IGNORE.copy()
        EXPECTED_EXCLUDE.extend(EXPECTED_NEW_EXCLUDE)
        expected_config = {
            "SOURCE": ["eze"],
            "CONFIG_FILE": None,
            "EXCLUDE": sorted(EXPECTED_EXCLUDE),
            "INCLUDE_FULL_REASON": True,
            "REPORT_FILE": create_tempfile_path("tmp-truffleHog-report.json"),
            "NO_ENTROPY": False,
            "DISABLE_DEFAULT_IGNORES": False,
            "USE_GIT_IGNORE": True,
            #
            "ADDITIONAL_ARGUMENTS": "",
            "IGNORED_FILES": None,
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
            "USE_SOURCE_COPY": True,
        }
        # When
        testee = TruffleHogTool(input_config)
        # Then
        assert testee.config == expected_config

    @mock.patch(
        "eze.plugins.tools.trufflehog.get_gitignore_paths", mock.MagicMock(return_value=["some-gitignore-statement"])
    )
    @mock.patch("eze.plugins.tools.trufflehog.is_windows_os", mock.MagicMock(return_value=False))
    def test_creation__with_linux_exclude_config(self):
        # Given
        # Given
        EXCLUDES = [
            "PATH-TO-EXCLUDED-FOLDER/.*",
            "PATH-TO-NESTED-FOLDER/SOME_NESTING/.*",
            "PATH-TO-EXCLUDED-FILE.js",
        ]
        EXPECTED_NEW_EXCLUDE = EXCLUDES
        input_config = {
            "SOURCE": ["eze"],
            "EXCLUDE": EXCLUDES,
        }
        EXPECTED_EXCLUDE = DEFAULT_EXCLUDES_WITH_MOCKED_GIT_IGNORE.copy()
        EXPECTED_EXCLUDE.extend(EXPECTED_NEW_EXCLUDE)
        expected_config = {
            "SOURCE": ["eze"],
            "CONFIG_FILE": None,
            "EXCLUDE": sorted(EXPECTED_EXCLUDE),
            "INCLUDE_FULL_REASON": True,
            "REPORT_FILE": create_tempfile_path("tmp-truffleHog-report.json"),
            "NO_ENTROPY": False,
            "DISABLE_DEFAULT_IGNORES": False,
            "USE_GIT_IGNORE": True,
            #
            "ADDITIONAL_ARGUMENTS": "",
            "IGNORED_FILES": None,
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
            "USE_SOURCE_COPY": True,
        }
        # When
        testee = TruffleHogTool(input_config)
        # Then
        assert testee.config == expected_config

    @mock.patch("eze.core.config.detect_pip_executable_version", mock.MagicMock(return_value="2.0.5"))
    def test_check_installed__success(self):
        # When
        expected_output = "2.0.5"
        output = TruffleHogTool.check_installed()
        # Then
        assert output == expected_output

    @mock.patch("eze.core.config.detect_pip_executable_version", mock.MagicMock(return_value=False))
    def test_check_installed__failure_unavailable(self):
        # When
        expected_output = False
        output = TruffleHogTool.check_installed()
        # Then
        assert output == expected_output

    def test_parse_report__version2_snapshot(self, snapshot):
        """ab-712: Pre Aug 2021 - Trufflehog3 v2 format parse support"""
        # Given
        input_config = {"SOURCE": "eze"}
        # Test container fixture and snapshot
        self.assert_parse_report_snapshot_test(
            snapshot,
            input_config,
            "__fixtures__/plugins_tools/raw-trufflehog-v2-report.json",
            "plugins_tools/trufflehog-result-v2-output.json",
        )

    def test_parse_report__version3_snapshot(self, snapshot):
        """ab-712: Post Aug 2021 - Trufflehog3 v3 format parse support"""
        # Given
        input_config = {"SOURCE": "eze"}
        # Test container fixture and snapshot
        self.assert_parse_report_snapshot_test(
            snapshot,
            input_config,
            "__fixtures__/plugins_tools/raw-trufflehog-v3-report.json",
            "plugins_tools/trufflehog-result-v3-output.json",
        )

    @mock.patch("eze.utils.cli.run.async_subprocess_run")
    @mock.patch(
        "eze.plugins.tools.trufflehog.get_gitignore_paths", mock.MagicMock(return_value=["some-gitignore-statement"])
    )
    @mock.patch("eze.plugins.tools.trufflehog.cache_workspace_into_tmp", mock.MagicMock(return_value=None))
    @pytest.mark.asyncio
    async def test_run_scan__cli_command(self, mock_async_subprocess_run):
        # Given
        input_config = {
            "SOURCE": "eze",
            "REPORT_FILE": "tmp-truffleHog-report.json",
            "DISABLE_DEFAULT_IGNORES": True,
            "USE_GIT_IGNORE": False,
            "USE_SOURCE_COPY": False,
        }
        absolute_report = create_absolute_path(input_config["REPORT_FILE"])
        rules_path = os.path.normpath(
            os.path.dirname(os.path.abspath(__file__)) + "/../../../eze/data/trufflehog_rules.yml"
        )
        expected_cmd = f"trufflehog3 --no-history -f json -r '{rules_path}' eze -o '{absolute_report}'"
        # Test run calls correct program
        await self.assert_run_scan_command(input_config, expected_cmd, mock_async_subprocess_run)

    @mock.patch("eze.utils.cli.run.async_subprocess_run")
    @mock.patch("eze.utils.cli.run.is_windows_os", mock.MagicMock(return_value=True))
    @mock.patch("eze.plugins.tools.trufflehog.is_windows_os", mock.MagicMock(return_value=True))
    @mock.patch(
        "eze.plugins.tools.trufflehog.get_gitignore_paths", mock.MagicMock(return_value=["some-gitignore-statement"])
    )
    @mock.patch("eze.plugins.tools.trufflehog.cache_workspace_into_tmp", mock.MagicMock(return_value=None))
    @mock.patch(
        "eze.plugins.tools.trufflehog.create_absolute_path",
        mock.MagicMock(return_value="OS_NON_SPECIFIC_ABSOLUTE/tmp-truffleHog-report.json"),
    )
    @pytest.mark.asyncio
    async def test_run_scan__cli_command__windows_ab_699_multi_value_flag_with_windows_path_escaping(
        self, mock_async_subprocess_run
    ):
        # Given
        input_config = {
            "SOURCE": "eze",
            "REPORT_FILE": "tmp-truffleHog-report.json",
            "EXCLUDE": [
                "PATH-TO-EXCLUDED-FOLDER/.*",
                "PATH-TO-NESTED-FOLDER/SOME_NESTING/.*",
                "PATH-TO-EXCLUDED-FILE.js",
            ],
            "DISABLE_DEFAULT_IGNORES": True,
            "USE_GIT_IGNORE": False,
            "USE_SOURCE_COPY": False,
        }

        rules_path = os.path.normpath(
            os.path.dirname(os.path.abspath(__file__)) + "/../../../eze/data/trufflehog_rules.yml"
        )
        expected_cmd = f"trufflehog3 --no-history -f json -r '{rules_path}' eze -o OS_NON_SPECIFIC_ABSOLUTE/tmp-truffleHog-report.json --exclude PATH-TO-EXCLUDED-FILE.js 'PATH-TO-EXCLUDED-FOLDER\\\\.*' 'PATH-TO-NESTED-FOLDER\\\\SOME_NESTING\\\\.*'"

        # Test run calls correct program
        await self.assert_run_scan_command(input_config, expected_cmd, mock_async_subprocess_run)

    @mock.patch("eze.utils.cli.run.async_subprocess_run")
    @mock.patch("eze.utils.cli.run.is_windows_os", mock.MagicMock(return_value=False))
    @mock.patch("eze.plugins.tools.trufflehog.is_windows_os", mock.MagicMock(return_value=False))
    @mock.patch(
        "eze.plugins.tools.trufflehog.get_gitignore_paths", mock.MagicMock(return_value=["some-gitignore-statement"])
    )
    @mock.patch("eze.plugins.tools.trufflehog.cache_workspace_into_tmp", mock.MagicMock(return_value=None))
    @mock.patch(
        "eze.plugins.tools.trufflehog.create_absolute_path",
        mock.MagicMock(return_value="OS_NON_SPECIFIC_ABSOLUTE/tmp-truffleHog-report.json"),
    )
    @pytest.mark.asyncio
    async def test_run_scan__cli_command__ab_699_multi_value_flag_with_linux(self, mock_async_subprocess_run):
        # Given
        input_config = {
            "SOURCE": "eze",
            "REPORT_FILE": "tmp-truffleHog-report.json",
            "EXCLUDE": [
                "PATH-TO-EXCLUDED-FOLDER/.*",
                "PATH-TO-NESTED-FOLDER/SOME_NESTING/.*",
                "PATH-TO-EXCLUDED-FILE.js",
                "FILE WITH SPACES.js",
            ],
            "DISABLE_DEFAULT_IGNORES": True,
            "USE_GIT_IGNORE": False,
            "USE_SOURCE_COPY": False,
        }

        rules_path = os.path.normpath(
            os.path.dirname(os.path.abspath(__file__)) + "/../../../eze/data/trufflehog_rules.yml"
        )
        expected_cmd = f"trufflehog3 --no-history -f json -r '{rules_path}' eze -o OS_NON_SPECIFIC_ABSOLUTE/tmp-truffleHog-report.json --exclude 'FILE WITH SPACES.js' PATH-TO-EXCLUDED-FILE.js 'PATH-TO-EXCLUDED-FOLDER/.*' 'PATH-TO-NESTED-FOLDER/SOME_NESTING/.*'"
        # Test run calls correct program
        await self.assert_run_scan_command(input_config, expected_cmd, mock_async_subprocess_run)

    @mock.patch("eze.utils.cli.run.async_subprocess_run")
    @mock.patch("eze.utils.cli.run.is_windows_os", mock.MagicMock(return_value=False))
    @mock.patch("eze.plugins.tools.trufflehog.is_windows_os", mock.MagicMock(return_value=False))
    @mock.patch(
        "eze.plugins.tools.trufflehog.get_gitignore_paths", mock.MagicMock(return_value=["some-gitignore-statement"])
    )
    @mock.patch("eze.plugins.tools.trufflehog.cache_workspace_into_tmp", mock.MagicMock(return_value=None))
    @mock.patch(
        "eze.plugins.tools.trufflehog.create_absolute_path",
        mock.MagicMock(return_value="OS_NON_SPECIFIC_ABSOLUTE/tmp-truffleHog-report.json"),
    )
    @pytest.mark.asyncio
    async def test_run_scan__cli_command__ab_699_short_flag(self, mock_async_subprocess_run):
        # Given
        input_config = {
            "SOURCE": "eze",
            "REPORT_FILE": "tmp-truffleHog-report.json",
            "NO_ENTROPY": True,
            "DISABLE_DEFAULT_IGNORES": True,
            "USE_GIT_IGNORE": False,
            "USE_SOURCE_COPY": False,
        }

        rules_path = os.path.normpath(
            os.path.dirname(os.path.abspath(__file__)) + "/../../../eze/data/trufflehog_rules.yml"
        )
        expected_cmd = f"trufflehog3 --no-history -f json -r '{rules_path}' eze --no-entropy -o OS_NON_SPECIFIC_ABSOLUTE/tmp-truffleHog-report.json"
        # Test run calls correct program
        await self.assert_run_scan_command(input_config, expected_cmd, mock_async_subprocess_run)
