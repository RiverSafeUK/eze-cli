# pylint: disable=missing-module-docstring,missing-class-docstring
import json

from unittest.mock import patch
import pytest
from click import ClickException
from eze.utils.io import pretty_print_json

from eze.core.enums import VulnerabilityType, VulnerabilitySeverityEnum
from eze.core.tool import ToolManager, ToolMeta, Vulnerability, ScanResult
from tests.__fixtures__.fixture_helper import assert_deep_equal, get_snapshot_directory
from tests.__test_helpers__.mock_helper import (
    setup_mock,
    teardown_mock,
    DummySuccessTool,
    DummyFailureTool,
    unmock_print,
    mock_print,
)


class DummyPlugin1:
    def get_tools(self) -> dict:
        return {"success-tool": DummySuccessTool}


class DummyPlugin2:
    def get_tools(self) -> dict:
        return {"failure-tool": DummyFailureTool}


class DummyPlugin3(ToolMeta):
    EZE_CONFIG: dict = {
        "REPORT_FILE": {
            "type": str,
            "default": "/dummy-path/tmp-path-report.json",
        },
    }

    def get_tools(self) -> dict:
        return {"success-tool": DummySuccessTool}

    def check_installed(self) -> str:
        return True

    def run_scan(self):
        report = ScanResult(
            {
                "tool": "DummyPlugin3",
                "vulnerabilities": [],
                "warnings": [],
            }
        )
        return report


class MockGitBranch:
    def __init__(self):
        self.name = "feature/helloworld"
        self.repo = {"remotes": {"origin": {"url": "https://some-repo.some-domain.com"}}}


class MockSuccessGitRepo:
    def __init__(self):
        self.active_branch = MockGitBranch()


class TestToolManager:
    def setUp(self) -> None:
        """Pre-Test Setup func"""
        teardown_mock()

    def tearDown(self) -> None:
        """Post-Test Tear Down func"""
        teardown_mock()
        unmock_print()

    def test_plugin_inject(self):
        # Given
        expected_tools = {"success-tool": DummySuccessTool, "failure-tool": DummyFailureTool}
        input_plugin = {
            "broken_plugin_with_no_get_tools": {},
            "test_plugin_1": DummyPlugin1(),
            "test_plugin_2": DummyPlugin2(),
        }
        # When
        tool_manager_instance = ToolManager(input_plugin)
        # Then
        assert tool_manager_instance.tools == expected_tools

    def test_get_tool__simple(self):
        # Given
        eze_config = {"success-tool": {"some-thing-for-tool": 123}, "scan": {"tools": [], "reporters": []}}
        setup_mock(eze_config)
        expected_tool_config = {
            "some-thing-for-tool": 123,
            "DEFAULT_SEVERITY": "na",
            "IGNORED_VULNERABILITIES": [],
            "IGNORED_FILES": [],
            "EXCLUDE": [],
            "IGNORE_BELOW_SEVERITY_INT": 5,
        }
        expected_tools = {"success-tool": DummySuccessTool, "failure-tool": DummyFailureTool}
        input_plugin = {
            "broken_plugin_with_no_get_tools": {},
            "test_plugin_1": DummyPlugin1(),
            "test_plugin_2": DummyPlugin2(),
        }
        tool_manager_instance = ToolManager(input_plugin)
        # When
        tool_instance = tool_manager_instance.get_tool("success-tool")
        # Then
        assert type(tool_instance) is DummySuccessTool
        assert tool_instance.config == expected_tool_config

    def test_get_tool__with_nested_run_type(self):
        # Given
        eze_config = {
            "success-tool": {"some-thing-for-tool": 123},
            "success-tool_dev-mode": {"some-thing-for-dev-mode": 456},
            "scan": {"tools": [], "reporters": []},
        }
        setup_mock(eze_config)
        expected_tool_config = {
            "some-thing-for-tool": 123,
            "some-thing-for-dev-mode": 456,
            "DEFAULT_SEVERITY": "na",
            "IGNORED_VULNERABILITIES": [],
            "IGNORED_FILES": [],
            "EXCLUDE": [],
            "IGNORE_BELOW_SEVERITY_INT": 5,
        }
        input_plugin = {
            "broken_plugin_with_no_get_tools": {},
            "test_plugin_1": DummyPlugin1(),
            "test_plugin_2": DummyPlugin2(),
        }
        tool_manager_instance = ToolManager(input_plugin)
        # When
        tool_instance = tool_manager_instance.get_tool("success-tool:dev-mode")
        # Then
        assert type(tool_instance) is DummySuccessTool
        assert tool_instance.config == expected_tool_config

    def test_get_tool__failure_invalid_reporter(self):
        # Given
        setup_mock()
        expected_error_message = """The ./ezerc config references unknown tool plugin 'non-existant-tool', run 'eze tools list' to see available tools"""
        input_plugin = {
            "broken_plugin_with_no_get_tools": {},
            "test_plugin_1": DummyPlugin1(),
            "test_plugin_2": DummyPlugin2(),
        }
        testee = ToolManager(input_plugin)
        # When
        with pytest.raises(ClickException) as thrown_exception:
            testee.get_tool("non-existant-tool")
        # Then
        assert thrown_exception.value.message == expected_error_message

    @patch("git.Repo")
    @pytest.mark.asyncio
    async def test_run_tool__simple(self, mock_repo, snapshot):
        # Given
        mock_repo.return_value = MockSuccessGitRepo()
        eze_config = {"success-tool": {"some-thing-for-tool": 123}, "scan": {"tools": [], "reporters": []}}
        setup_mock(eze_config)
        expected_tool_config = {
            "some-thing-for-tool": 123,
            "DEFAULT_SEVERITY": "na",
            "IGNORED_VULNERABILITIES": [],
            "IGNORED_FILES": [],
            "EXCLUDE": [],
            "IGNORE_BELOW_SEVERITY_INT": 5,
        }
        expected_tools = {"success-tool": DummySuccessTool, "failure-tool": DummyFailureTool}
        input_plugin = {
            "broken_plugin_with_no_get_tools": {},
            "test_plugin_1": DummyPlugin1(),
            "test_plugin_2": DummyPlugin2(),
        }
        tool_manager_instance = ToolManager(input_plugin)
        # When
        output: ScanResult = await tool_manager_instance.run_tool("success-tool")
        # Then
        output.run_details["duration_sec"] = ["NOT UNDER TEST (TIME IS DYNAMIC)"]
        output.run_details["date"] = ["NOT UNDER TEST (TIME IS DYNAMIC)"]
        output.vulnerabilities = ["NOT UNDER TEST (FROM FIXTURE)"]
        output_snapshot = pretty_print_json(output)
        # Then
        # WARNING: this is a snapshot test, any changes to format will edit this and the snapshot will need to be updated
        snapshot.snapshot_dir = get_snapshot_directory()
        snapshot.assert_match(output_snapshot, f"core/tool__run_tool-result-output.json")

    @pytest.mark.asyncio
    @patch("eze.core.tool.create_folder")
    async def test_prepare_folder(self, create_folder_mock):
        # Given
        input_config = {
            "REPORT_FILE": "reports/test_report.json",
        }
        tool_manager_instance = DummyPlugin3(input_config)
        # When
        tool_manager_instance.prepare_folder()
        # Then
        create_folder_mock.assert_called_with("reports/test_report.json")

    def test_print_tool_help__simple(self, snapshot):
        # Given
        mocked_print_output = mock_print()
        input_plugin = {
            "broken_plugin_with_no_get_tools": {},
            "test_plugin_1": DummyPlugin1(),
            "test_plugin_2": DummyPlugin2(),
        }
        tool_manager_instance = ToolManager(input_plugin)
        # When
        tool_manager_instance.print_tool_help("success-tool")
        # Then
        unmock_print()
        output = mocked_print_output.getvalue()
        snapshot.snapshot_dir = get_snapshot_directory()
        snapshot.assert_match(output, "core/tool__print_tool_help.txt")

    def test_print_tools_help__simple(self, snapshot):
        # Given
        mocked_print_output = mock_print()
        input_plugin = {
            "broken_plugin_with_no_get_tools": {},
            "test_plugin_1": DummyPlugin1(),
            "test_plugin_2": DummyPlugin2(),
        }
        tool_manager_instance = ToolManager(input_plugin)
        # When
        tool_manager_instance.print_tools_help()
        # Then
        unmock_print()
        output = mocked_print_output.getvalue()
        snapshot.snapshot_dir = get_snapshot_directory()
        snapshot.assert_match(output, "core/tool__print_tools_help.txt")

    def test_private__normalise_vulnerabilities(self):
        # Given
        fixed_low_vulnerability = Vulnerability(
            {"severity": "low", "is_ignored": False, "name": "corrupted_low_vulnerability"}
        )
        fixed_high_vulnerability = Vulnerability(
            {"severity": "high", "is_ignored": False, "name": "corrupted_high_vulnerability"}
        )
        fixed_missing_severity_vulnerability = Vulnerability(
            {
                "severity": "medium",
                "is_ignored": False,
                "name": "corrupted_missing_severity_vulnerability",
            }
        )
        fixed_ignored_high_vulnerability = Vulnerability(
            {
                "severity": "high",
                "is_ignored": True,
                "name": "corrupted_ignored_high_vulnerability",
            }
        )

        corrupted_low_vulnerability = Vulnerability(
            {
                "severity": "low",
                "is_ignored": "Not a Ignored Bool Value",
                "name": "corrupted_low_vulnerability",
            }
        )
        corrupted_low_vulnerability.severity = "LoW"
        corrupted_missing_severity_vulnerability = Vulnerability(
            {"is_ignored": False, "name": "corrupted_missing_severity_vulnerability"}
        )
        corrupted_high_vulnerability = Vulnerability(
            {"severity": "high", "is_ignored": False, "name": "corrupted_high_vulnerability"}
        )
        corrupted_ignored_high_vulnerability = Vulnerability(
            {
                "severity": "high",
                "is_ignored": True,
                "name": "corrupted_ignored_high_vulnerability",
            }
        )

        expected_output = [
            fixed_high_vulnerability,
            fixed_missing_severity_vulnerability,
            fixed_low_vulnerability,
            fixed_ignored_high_vulnerability,
        ]
        input_vulnerabilities = [
            corrupted_low_vulnerability,
            corrupted_ignored_high_vulnerability,
            corrupted_high_vulnerability,
            corrupted_missing_severity_vulnerability,
        ]
        input_config = {"DEFAULT_SEVERITY": "medium", "IGNORED_VULNERABILITIES": [], "IGNORE_BELOW_SEVERITY_INT": 9999}
        # When
        tool_manager_instance = ToolManager()
        # Then
        output = tool_manager_instance._normalise_vulnerabilities(input_vulnerabilities, input_config)

        output_object = json.loads(json.dumps(output, default=vars))
        expected_output_object = json.loads(json.dumps(expected_output, default=vars))
        assert output_object == expected_output_object

    def test_private__normalise_vulnerabilities_excluded_files(self):
        # Given
        not_excluded_no_file = Vulnerability(
            {
                "severity": "medium",
                "is_excluded": False,
                "name": "not_excluded_no_file",
            }
        )
        excluded_no_file = Vulnerability(
            {
                "severity": "medium",
                "is_excluded": True,
                "name": "excluded_no_file",
            }
        )
        not_excluded_and_file_loc_excluded = Vulnerability(
            {
                "severity": "medium",
                "is_excluded": False,
                "file_location": {"path": "excluded/report1.txt"},
                "name": "not_excluded_and_file_loc_excluded",
            }
        )
        not_excluded_and_file_loc_not_excluded = Vulnerability(
            {
                "severity": "low",
                "is_excluded": False,
                "file_location": {"path": "included/report2.txt"},
                "name": "not_excluded_and_file_loc_not_excluded",
            }
        )
        excluded_and_file_location_excluded = Vulnerability(
            {
                "severity": "low",
                "is_excluded": True,
                "file_location": {"path": "excluded/report3.txt"},
                "name": "excluded_and_file_loc_excluded",
            }
        )

        expected_output = [
            not_excluded_no_file,
            not_excluded_and_file_loc_not_excluded,
        ]
        input_vulnerabilities = [
            not_excluded_no_file,
            excluded_no_file,
            not_excluded_and_file_loc_excluded,
            not_excluded_and_file_loc_not_excluded,
            excluded_and_file_location_excluded,
        ]
        input_config = {
            "DEFAULT_SEVERITY": "medium",
            "IGNORED_VULNERABILITIES": [],
            "IGNORED_FILES": [],
            "EXCLUDE": ["excluded/"],
            "IGNORE_BELOW_SEVERITY_INT": 9999,
        }
        # When
        tool_manager_instance = ToolManager()
        # Then
        output = tool_manager_instance._normalise_vulnerabilities(input_vulnerabilities, input_config)

        output_object = json.loads(json.dumps(output, default=vars))
        expected_output_object = json.loads(json.dumps(expected_output, default=vars))
        assert output_object == expected_output_object

    def test_private__sort_vulnerabilities(self):
        # Given
        low_vulnerability = Vulnerability({"severity": "low", "is_ignored": False, "name": "foo"})
        med_vulnerability = Vulnerability({"severity": "medium", "is_ignored": False, "name": "foo"})
        high_vulnerability = Vulnerability({"severity": "high", "is_ignored": False, "name": "foo"})
        ignored_high_vulnerability = Vulnerability({"severity": "high", "is_ignored": True, "name": "foo"})

        expected_output = [high_vulnerability, med_vulnerability, low_vulnerability, ignored_high_vulnerability]
        input = [low_vulnerability, ignored_high_vulnerability, high_vulnerability, med_vulnerability]
        # When
        tool_manager_instance = ToolManager()
        # Then
        output = tool_manager_instance._sort_vulnerabilities(input)
        assert output == expected_output


class TestVulnerability:
    def test_seralisation_test(self):
        old_vulnerability = Vulnerability(
            {
                "vulnerability_type": VulnerabilityType.dependancy.name,
                "severity": "low",
                "is_ignored": False,
                "name": "foo",
                "identifiers": {"CVE": "cve-something"},
            }
        )
        dehydrated_vulnerability_json = json.loads(json.dumps(old_vulnerability, default=vars))
        new_rehyrdated_vulnerability = Vulnerability(dehydrated_vulnerability_json)

        assert_deep_equal(old_vulnerability, new_rehyrdated_vulnerability)

    def test_update_ignored__false(self):
        # Given
        expected_ignored_status = False
        input_vulnerability = Vulnerability(
            {
                "name": "foo",
                "identifiers": {"CVE": "cve-xxxx"},
                "severity": VulnerabilitySeverityEnum.medium.name,
                "is_ignored": False,
            }
        )

        input_config = {
            "DEFAULT_SEVERITY": "medium",
            "IGNORED_VULNERABILITIES": [],
            "IGNORE_BELOW_SEVERITY_INT": VulnerabilitySeverityEnum.na.value,
        }

        # When
        input_vulnerability.update_ignored(input_config)
        # Then
        assert input_vulnerability.is_ignored == expected_ignored_status

    def test_update_ignored__by_severity(self):
        # Given
        expected_ignored_status = True
        input_vulnerability = Vulnerability(
            {
                "name": "foo",
                "identifiers": {"CVE": "cve-xxxx"},
                "severity": VulnerabilitySeverityEnum.medium.name,
                "is_ignored": False,
            }
        )

        input_config = {
            "DEFAULT_SEVERITY": "medium",
            "IGNORED_VULNERABILITIES": [],
            "IGNORE_BELOW_SEVERITY_INT": VulnerabilitySeverityEnum.high.value,
        }

        # When
        input_vulnerability.update_ignored(input_config)
        # Then
        assert input_vulnerability.is_ignored == expected_ignored_status

    def test_update_ignored__by_name(self):
        # Given
        expected_ignored_status = True
        input_vulnerability = Vulnerability(
            {
                "name": "foo",
                "identifiers": {"CVE": "cve-xxxx"},
                "severity": VulnerabilitySeverityEnum.medium.name,
                "is_ignored": False,
            }
        )

        input_config = {
            "DEFAULT_SEVERITY": "medium",
            "IGNORED_VULNERABILITIES": ["foo"],
            "IGNORE_BELOW_SEVERITY_INT": VulnerabilitySeverityEnum.na.value,
        }

        # When
        input_vulnerability.update_ignored(input_config)
        # Then
        assert input_vulnerability.is_ignored == expected_ignored_status

    def test_update_ignored__by_cve(self):
        # Given
        expected_ignored_status = True
        input_vulnerability = Vulnerability(
            {
                "name": "foo",
                "identifiers": {"CVE": "cve-xxxx"},
                "severity": VulnerabilitySeverityEnum.medium.name,
                "is_ignored": False,
            }
        )

        input_config = {
            "DEFAULT_SEVERITY": "medium",
            "IGNORED_VULNERABILITIES": ["cve-xxxx"],
            "IGNORE_BELOW_SEVERITY_INT": VulnerabilitySeverityEnum.na.value,
        }

        # When
        input_vulnerability.update_ignored(input_config)
        # Then
        assert input_vulnerability.is_ignored == expected_ignored_status
