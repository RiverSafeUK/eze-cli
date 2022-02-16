# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long

import os
import pathlib
import shutil
import tempfile

import pytest

from unittest import mock
from pytest_snapshot.plugin import Snapshot
from eze.core.tool import ScanResult
from eze.plugins.reporters.sarif import SarifReporter
from eze.utils.io.file import load_text
from tests.plugins.reporters.reporter_helper import ReporterMetaTestBase
from tests.__fixtures__.fixture_helper import get_snapshot_directory, load_json_fixture


class TestSarifReporter(ReporterMetaTestBase):
    ReporterMetaClass = SarifReporter
    SNAPSHOT_PREFIX = "sarif"

    def setup_method(self):
        eze_temp_folder = os.path.join(tempfile.gettempdir(), ".eze-temp")
        shutil.rmtree(eze_temp_folder, ignore_errors=True)

    def test_check_installed__sanity(self):
        # When
        output = SarifReporter.check_installed()
        # Then
        assert isinstance(output, str)
        assert len(output) > 0

    def test_creation__no_config(self):
        # Given
        expected_config = {"REPORT_FILE": ".eze/eze_report.sarif"}
        # When
        testee = SarifReporter()
        # Then
        assert testee.config == expected_config

    def test_creation__simple_config_parsing(self):
        # Given
        input_config = {"REPORT_FILE": "custom_report.sarif"}
        expected_config = {"REPORT_FILE": "custom_report.sarif"}
        # When
        testee = SarifReporter(input_config)
        # Then
        assert testee.config == expected_config

    @pytest.mark.asyncio
    @mock.patch(
        "eze.plugins.reporters.sarif.uuid.uuid4", mock.MagicMock(return_value="d45662fb-577e-4fd8-9950-f5cfd7923450")
    )
    async def test_run_report__snapshot(self, snapshot: Snapshot):
        # Given
        input_report_location = pathlib.Path(tempfile.gettempdir()) / ".eze-temp" / "tmp-local-testfile"
        input_config = {"REPORT_FILE": str(input_report_location)}

        scan_result_fixture = load_json_fixture("__fixtures__/plugins_reporters/eze_sample_report_sarif.json")
        input_scan_results = [ScanResult(e) for e in scan_result_fixture]
        expected_config = {"REPORT_FILE": str(input_report_location)}
        # When
        testee = SarifReporter(input_config)
        print(testee)
        await testee.run_report(input_scan_results)
        output = load_text(input_report_location)
        # Then
        assert testee.config == expected_config
        snapshot.snapshot_dir = get_snapshot_directory()
        snapshot.assert_match(output, "plugins_reporters/sarif-output.txt")
