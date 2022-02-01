# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long
import os
from pathlib import Path
from unittest import mock

import pytest

from eze.plugins.tools.node_npmaudit import NpmAuditTool
from eze.utils.io import create_tempfile_path
from tests.plugins.tools.tool_helper import ToolMetaTestBase


class TestNpmAuditTool(ToolMetaTestBase):
    ToolMetaClass = NpmAuditTool
    SNAPSHOT_PREFIX = "node-npmaudit"

    def test_creation__no_config(self):
        # Given
        input_config = {}
        expected_config = {
            "REPORT_FILE": create_tempfile_path("tmp-npmaudit-report.json"),
            "ONLY_PROD": True,
            #
            "ADDITIONAL_ARGUMENTS": "",
            "IGNORED_FILES": None,
            "EXCLUDE": [],
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = NpmAuditTool(input_config)
        # Then
        assert testee.config == expected_config

    def test_creation__with_config(self):
        # Given
        input_config = {}
        expected_config = {
            "REPORT_FILE": create_tempfile_path("tmp-npmaudit-report.json"),
            "ONLY_PROD": True,
            #
            "ADDITIONAL_ARGUMENTS": "",
            "IGNORED_FILES": None,
            "EXCLUDE": [],
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = NpmAuditTool(input_config)
        # Then
        assert testee.config == expected_config

    @mock.patch("eze.plugins.tools.node_npmaudit.extract_cmd_version", mock.MagicMock(return_value="6.14.11"))
    def test_check_installed__success(self):
        # When
        expected_output = "6.14.11"
        output = NpmAuditTool.check_installed()
        # Then
        assert output == expected_output

    @mock.patch("eze.plugins.tools.node_npmaudit.extract_cmd_version", mock.MagicMock(return_value="5.12.11"))
    def test_check_installed__failure_version_low(self):
        # When
        expected_output = ""
        output = NpmAuditTool.check_installed()
        # Then
        assert output == expected_output

    @mock.patch("eze.plugins.tools.node_npmaudit.extract_cmd_version", mock.MagicMock(return_value=False))
    def test_check_installed__failure_unavailable(self):
        # When
        expected_output = False
        output = NpmAuditTool.check_installed()
        # Then
        assert output == expected_output

    def test_parse_report__npm6_snapshot(self, snapshot):
        # Test container fixture and snapshot
        self.assert_parse_report_snapshot_test(
            snapshot,
            {},
            "__fixtures__/plugins_tools/raw-node-npmaudit-v6-report.json",
            "plugins_tools/node-npmaudit-result-v6-output.json",
        )

    def test_parse_report__npm7_snapshot(self, snapshot):
        # Test container fixture and snapshot
        self.assert_parse_report_snapshot_test(
            snapshot,
            {},
            "__fixtures__/plugins_tools/raw-node-npmaudit-v7-report.json",
            "plugins_tools/node-npmaudit-result-v7-output.json",
        )

    def test_parse_report__npm_was_breaking_snapshot(self, snapshot):
        # Test container fixture and snapshot
        self.assert_parse_report_snapshot_test(
            snapshot,
            {},
            "__fixtures__/plugins_tools/raw-node-npmaudit-breaking-report.json",
            "plugins_tools/node-npmaudit-result-breaking-output.json",
        )

    # new v7 tests

    def test_create_recommendation_v7__major_fix(self):
        # Given
        expected_output = """fix available via `npm audit fix --force`
Will install mocha@8.4.0, which is a breaking change"""
        input_vulnerability = {"fixAvailable": {"name": "mocha", "version": "8.4.0", "isSemVerMajor": True}}
        testee = NpmAuditTool()
        # When
        output = testee.create_recommendation_v7(input_vulnerability)
        # Then
        assert output == expected_output

    def test_create_recommendation_v7__minor_fix(self):
        # Given
        expected_output = """fix available via `npm audit fix --force`
Will install mocha@8.4.0"""
        input_vulnerability = {"fixAvailable": {"name": "mocha", "version": "8.4.0", "isSemVerMajor": False}}
        testee = NpmAuditTool()
        # When
        output = testee.create_recommendation_v7(input_vulnerability)
        # Then
        assert output == expected_output

    def test_create_recommendation_v7__no_details(self):
        # Given
        expected_output = """fix available via `npm audit fix --force`"""
        input_vulnerability = {"fixAvailable": True}
        testee = NpmAuditTool()
        # When
        output = testee.create_recommendation_v7(input_vulnerability)
        # Then
        assert output == expected_output

    def test_create_recommendation_v7__no_fix_available(self):
        # Given
        expected_output = "no fix available"
        input_vulnerability = {"fixAvailable": False}
        testee = NpmAuditTool()
        # When
        output = testee.create_recommendation_v7(input_vulnerability)
        # Then
        assert output == expected_output

    def test_create_path_v7__nested_vul(self):
        # Given
        expected_output = """helmet>connect(2.11.1 - 3.6.4): has insecure dependency finalhandler>debug"""
        input_vulnerability = {
            "name": "connect",
            "severity": "low",
            "via": ["debug", "finalhandler"],
            "effects": ["helmet"],
            "range": "2.11.1 - 3.6.4",
            "nodes": ["node_modules/connect"],
            "fixAvailable": True,
        }
        testee = NpmAuditTool()
        # When
        output = testee.create_path_v7(input_vulnerability)
        # Then
        assert output == expected_output

    def test_create_path_v7__edge_vul(self):
        # Given
        expected_output = (
            """connect>finalhandler>mocha>debug(<= 2.6.8 || >= 3.0.0 <= 3.0.1): Regular Expression Denial of Service"""
        )
        input_vulnerability = {
            "name": "debug",
            "severity": "low",
            "via": [
                {
                    "source": 534,
                    "name": "debug",
                    "dependency": "debug",
                    "title": "Regular Expression Denial of Service",
                    "url": "https://npmjs.com/advisories/534",
                    "severity": "low",
                    "range": "<= 2.6.8 || >= 3.0.0 <= 3.0.1",
                }
            ],
            "effects": ["connect", "finalhandler", "mocha"],
            "range": "<=2.6.8 || 3.0.0 - 3.0.1",
            "nodes": ["node_modules/debug"],
            "fixAvailable": {"name": "mocha", "version": "8.4.0", "isSemVerMajor": True},
        }
        testee = NpmAuditTool()
        # When
        output = testee.create_path_v7(input_vulnerability)
        # Then
        assert output == expected_output

    @mock.patch("eze.utils.cli.async_subprocess_run")
    @mock.patch("eze.plugins.tools.node_npmaudit.find_files_by_name", mock.MagicMock(return_value=["package.json"]))
    @mock.patch("eze.utils.cli.is_windows_os", mock.MagicMock(return_value=True))
    @mock.patch("eze.utils.language.node.install_npm_in_path", mock.MagicMock(return_value=True))
    @pytest.mark.asyncio
    async def test_run_scan__cli_command__std(self, mock_async_subprocess_run):
        # Given
        input_config = {"REPORT_FILE": "foo_report.json"}
        expected_cwd = Path(os.getcwd())
        expected_cmd = "npm audit --json --only=prod"

        # Test run calls correct program
        await self.assert_run_scan_command(input_config, expected_cmd, mock_async_subprocess_run, expected_cwd)

    @mock.patch("eze.utils.cli.async_subprocess_run")
    @mock.patch("eze.plugins.tools.node_npmaudit.find_files_by_name", mock.MagicMock(return_value=["package.json"]))
    @mock.patch("eze.utils.cli.is_windows_os", mock.MagicMock(return_value=True))
    @mock.patch("eze.utils.language.node.install_npm_in_path", mock.MagicMock(return_value=True))
    @pytest.mark.asyncio
    async def test_run_scan__cli_command__non_prod(self, mock_async_subprocess_run):
        # Given
        input_config = {"REPORT_FILE": "foo_report.json", "ONLY_PROD": False}
        expected_cwd = Path(os.getcwd())
        expected_cmd = "npm audit --json"

        # Test run calls correct program
        await self.assert_run_scan_command(input_config, expected_cmd, mock_async_subprocess_run, expected_cwd)
