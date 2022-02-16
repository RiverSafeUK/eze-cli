# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long

import os
import pathlib
import re
import shutil
import tempfile

import pytest

from eze.core.tool import ScanResult
from eze.plugins.reporters.junit import JunitReporter
from eze.utils.io.file import load_text
from tests.__fixtures__.fixture_helper import load_json_fixture, get_snapshot_directory
from tests.plugins.reporters.reporter_helper import ReporterMetaTestBase


class TestJunitReporter(ReporterMetaTestBase):
    ReporterMetaClass = JunitReporter
    SNAPSHOT_PREFIX = "junit"

    def setup_method(self):
        eze_temp_folder = os.path.join(tempfile.gettempdir(), ".eze-temp")
        shutil.rmtree(eze_temp_folder, ignore_errors=True)

    def test_check_installed__sanity(self):
        # When
        output = JunitReporter.check_installed()
        # Then
        assert isinstance(output, str)
        assert len(output) > 0

    def test_creation__no_config(self):
        # Given
        expected_config = {"REPORT_FILE": ".eze/eze_junit_report.xml"}
        # When
        testee = JunitReporter()
        # Then
        assert testee.config == expected_config

    def test_creation__simple_config_parsing(self):
        # Given
        input_config = {"REPORT_FILE": "helloworld.xml"}
        expected_config = {"REPORT_FILE": "helloworld.xml"}
        # When
        testee = JunitReporter(input_config)
        # Then
        assert testee.config == expected_config

    @pytest.mark.asyncio
    async def test_run_report__snapshot(self, monkeypatch, snapshot):
        # Given
        input_report_location = pathlib.Path(tempfile.gettempdir()) / ".eze-temp" / "tmp-local-testfile"
        input_config = {"REPORT_FILE": str(input_report_location)}

        scan_result_fixture = load_json_fixture("__fixtures__/plugins_reporters/eze_sample_report_json.json")
        input_scan_result = ScanResult(scan_result_fixture[0])
        expected_config = {"REPORT_FILE": str(input_report_location)}

        # When
        testee = JunitReporter(input_config)
        await testee.run_report([input_scan_result])
        output = load_text(input_report_location)

        # Then
        assert testee.config == expected_config
        # WORKAROUND: intellij uses extremely poor regex to do "Click to see difference", normalise ==
        output = output.replace("==", "__")
        # normalise date data
        output = re.sub('timestamp="[^"]+"', 'timestamp="xxx"', output)
        output = re.sub('time="[^"]+"', 'time="xxx"', output)

        # WARNING: this is a snapshot test, any changes to format will edit this and the snapshot will need to be updated
        snapshot.snapshot_dir = get_snapshot_directory()
        snapshot.assert_match(output, "plugins_reporters/junit-output.xml")
