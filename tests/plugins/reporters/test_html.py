# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long

import os
import pathlib
import shutil
import tempfile
from eze.core.tool import ScanResult
from pytest_snapshot.plugin import Snapshot

import pytest

from eze.plugins.reporters.html import HtmlReporter
from tests.__fixtures__.fixture_helper import get_snapshot_directory, load_json_fixture
from tests.plugins.reporters.reporter_helper import ReporterMetaTestBase

from eze.utils.io import load_text


class TestHtmlReporter(ReporterMetaTestBase):
    ReporterMetaClass = HtmlReporter
    SNAPSHOT_PREFIX = "html"

    def setup_method(self):
        eze_temp_folder = os.path.join(tempfile.gettempdir(), ".eze-temp")
        shutil.rmtree(eze_temp_folder, ignore_errors=True)

    def test_check_installed_sanity(self):
        # When
        output = HtmlReporter.check_installed()
        # Then
        assert isinstance(output, str)
        assert len(output) > 0

    def test_creation__no_config(self):
        # Given
        expected_config = {"REPORT_FILE": ".eze/eze_report.html"}
        # When
        testee = HtmlReporter()
        # Then
        assert testee.config == expected_config

    def test_creation__simple_config(self):
        # Given
        input_config = {"REPORT_FILE": ".eze/eze_report_1.html"}
        expected_config = {"REPORT_FILE": ".eze/eze_report_1.html"}
        # When
        testee = HtmlReporter(input_config)
        # Then
        assert testee.config == expected_config

    @pytest.mark.asyncio
    async def test_run_report__snapshot(self, snapshot: Snapshot):
        """Test that given fixture scan output matches expectations"""

        # Given
        input_report_location = pathlib.Path(tempfile.gettempdir()) / ".eze-temp" / "tmp-local-testfile"
        input_config = {"REPORT_FILE": str(input_report_location)}

        scan_result_fixture = load_json_fixture("__fixtures__/plugins_reporters/eze_sample_report_json.json")
        input_scan_result = ScanResult(scan_result_fixture[0])
        expected_scan_result_fixture = load_json_fixture("__fixtures__/plugins_reporters/eze_sample_report_json.json")
        expected_json = [expected_scan_result_fixture[0]]
        expected_config = {"REPORT_FILE": str(input_report_location)}

        # When
        testee = HtmlReporter(input_config)
        await testee.run_report([input_scan_result])
        output = load_text(input_report_location)
        # Then
        assert testee.config == expected_config
        snapshot.snapshot_dir = get_snapshot_directory()
        snapshot.assert_match(output, "plugins_reporters/html-output.html")
