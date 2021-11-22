# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long

import os
import re
import shutil
import tempfile

import pytest

from eze.core.tool import ScanResult
from eze.plugins.reporters.console import ConsoleReporter
from tests.__fixtures__.fixture_helper import load_json_fixture, get_snapshot_directory
from tests.__test_helpers__.mock_helper import mock_print, unmock_print
from tests.plugins.reporters.reporter_helper import ReporterMetaTestBase


class TestConsoleReporter(ReporterMetaTestBase):
    ReporterMetaClass = ConsoleReporter
    SNAPSHOT_PREFIX = "console"

    def setup_method(self):
        eze_temp_folder = os.path.join(tempfile.gettempdir(), ".eze-temp")
        shutil.rmtree(eze_temp_folder, ignore_errors=True)
        self.console_output = ""

    def test_check_installed__sanity(self):
        # When
        output = ConsoleReporter.check_installed()
        # Then
        assert isinstance(output, str)
        assert len(output) > 0

    def test_creation__no_config(self):
        # Given
        expected_config = {"PRINT_IGNORED": False, "PRINT_SUMMARY_ONLY": False}
        # When
        testee = ConsoleReporter()
        # Then
        assert testee.config == expected_config

    def append_console_output(self, text):
        self.console_output += text + "\n"

    @pytest.mark.asyncio
    async def test_run_report__snapshot(self, snapshot):
        # Given
        input_config = {"PRINT_IGNORED": False}
        expected_config = {"PRINT_IGNORED": False, "PRINT_SUMMARY_ONLY": False}
        input_scan_result = ScanResult(
            load_json_fixture("__fixtures__/plugins_reporters/eze_sample_report_json.json")[0]
        )
        snapshot_location = "plugins_reporters/console-output.txt"

        # Then
        await self.assert_run_report_snapshot(
            snapshot, input_config, expected_config, input_scan_result, snapshot_location
        )

    @pytest.mark.asyncio
    async def test_run_report__print_ignored_snapshot(self, snapshot):
        # Given
        input_config = {"PRINT_IGNORED": True}
        expected_config = {"PRINT_IGNORED": True, "PRINT_SUMMARY_ONLY": False}
        input_scan_result = ScanResult(
            load_json_fixture("__fixtures__/plugins_reporters/eze_sample_report_json.json")[0]
        )
        snapshot_location = "plugins_reporters/console-print_ignored-output.txt"

        # Then
        await self.assert_run_report_snapshot(
            snapshot, input_config, expected_config, input_scan_result, snapshot_location
        )

    @pytest.mark.asyncio
    async def test_run_report__print_summary_only_snapshot(self, snapshot):
        # Given
        input_config = {"PRINT_SUMMARY_ONLY": True}
        expected_config = {"PRINT_IGNORED": False, "PRINT_SUMMARY_ONLY": True}
        input_scan_result = ScanResult(
            load_json_fixture("__fixtures__/plugins_reporters/eze_sample_report_json.json")[0]
        )
        snapshot_location = "plugins_reporters/console-summary_only-output.txt"

        # Then
        await self.assert_run_report_snapshot(
            snapshot, input_config, expected_config, input_scan_result, snapshot_location
        )

    @pytest.mark.asyncio
    async def test_run_report__print_sbom(self, snapshot):
        # Given
        input_config = {"PRINT_IGNORED": True}
        expected_config = {"PRINT_IGNORED": True, "PRINT_SUMMARY_ONLY": False}
        input_scan_result = ScanResult(load_json_fixture("__fixtures__/plugins_reporters/eze_sample_sbom.json")[0])
        snapshot_location = "plugins_reporters/console-sbom-output.txt"

        # Then
        await self.assert_run_report_snapshot(
            snapshot, input_config, expected_config, input_scan_result, snapshot_location
        )

    async def assert_run_report_snapshot(
        self,
        snapshot,
        input_config: dict,
        expected_config: dict,
        input_scan_result: ScanResult,
        snapshot_location: str,
    ):
        # Given
        mocked_print_output = mock_print()

        # When
        testee = ConsoleReporter(input_config)
        # hijack print command to test output
        await testee.run_report([input_scan_result])
        output = mocked_print_output.getvalue()
        unmock_print()

        # Then
        assert testee.config == expected_config
        # WORKAROUND: intellij uses extremely poor regex to do "Click to see difference", normalise ==
        output = output.replace("=", "_")

        # normalise date data
        output = re.sub("scan duration: [^ ]+ seconds", "scan duration: xxx seconds", output)

        # WARNING: this is a snapshot test, any changes to format will edit this and the snapshot will need to be updated
        snapshot.snapshot_dir = get_snapshot_directory()
        snapshot.assert_match(output, snapshot_location)
