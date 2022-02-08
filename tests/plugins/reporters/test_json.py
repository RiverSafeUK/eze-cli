# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long

import os
import pathlib
import shutil
import tempfile

import pytest

from eze.core.tool import ScanResult
from eze.plugins.reporters.json import JsonReporter
from eze.utils.io import load_json
from tests.__fixtures__.fixture_helper import load_json_fixture
from tests.plugins.reporters.reporter_helper import ReporterMetaTestBase


class TestJsonReporter(ReporterMetaTestBase):
    ReporterMetaClass = JsonReporter
    SNAPSHOT_PREFIX = "json"

    def setup_method(self):
        eze_temp_folder = os.path.join(tempfile.gettempdir(), ".eze-temp")
        shutil.rmtree(eze_temp_folder, ignore_errors=True)

    def test_check_installed__sanity(self):
        # When
        output = JsonReporter.check_installed()
        # Then
        assert isinstance(output, str)
        assert len(output) > 0

    def test_creation__no_config(self):
        # Given
        expected_config = {"REPORT_FILE": ".eze/eze_report.json"}
        # When
        testee = JsonReporter()
        # Then
        assert testee.config == expected_config

    def test_creation__simple_config_parsing(self):
        # Given
        input_config = {"REPORT_FILE": "helloworld.json"}
        expected_config = {"REPORT_FILE": "helloworld.json"}
        # When
        testee = JsonReporter(input_config)
        # Then
        assert testee.config == expected_config

    @pytest.mark.asyncio
    async def test_run_report__snapshot(self):
        # Given
        input_report_location = pathlib.Path(tempfile.gettempdir()) / ".eze-temp" / "tmp-local-testfile"
        input_config = {"REPORT_FILE": str(input_report_location)}

        scan_result_fixture = load_json_fixture("__fixtures__/plugins_reporters/eze_sample_report_json.json")
        input_scan_result = ScanResult(scan_result_fixture[0])
        expected_scan_result_fixture = load_json_fixture("__fixtures__/plugins_reporters/eze_sample_report_json.json")
        expected_json = [expected_scan_result_fixture[0]]
        expected_config = {"REPORT_FILE": str(input_report_location)}
        # When
        testee = JsonReporter(input_config)
        await testee.run_report([input_scan_result])
        output = load_json(input_report_location)
        # Then
        assert testee.config == expected_config

        # WARNING: this is a snapshot test, any changes to format will edit this and the snapshot will need to be updated
        assert output == expected_json
