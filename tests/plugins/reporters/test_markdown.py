# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long

import os
import pathlib
import shutil
import tempfile
from unittest import mock
from pytest_snapshot.plugin import Snapshot
from unittest.mock import patch

import pytest

from eze.core.tool import ScanResult
from eze.plugins.reporters.markdown import MarkdownReporter
from eze.utils.io import load_text
from tests.plugins.reporters.reporter_helper import ReporterMetaTestBase
from tests.__fixtures__.fixture_helper import get_snapshot_directory, load_json_fixture


class TestMarkdownReporter(ReporterMetaTestBase):
    ReporterMetaClass = MarkdownReporter
    SNAPSHOT_PREFIX = "markdown"

    def setup_method(self):
        eze_temp_folder = os.path.join(tempfile.gettempdir(), ".eze-temp")
        shutil.rmtree(eze_temp_folder, ignore_errors=True)

    def test_check_installed_sanity(self):
        # When
        output = MarkdownReporter.check_installed()
        # Then
        assert isinstance(output, str)
        assert len(output) > 0

    def test_creation__no_config(self):
        # Given
        expected_config = {"REPORT_FILE": "eze_report.md"}
        # When
        testee = MarkdownReporter()
        # Then
        assert testee.config == expected_config

    def test_creation__simple_config_parsing(self):
        # Given
        input_config = {"REPORT_FILE": "helloworld.md"}
        expected_config = {"REPORT_FILE": "helloworld.md"}
        # When
        testee = MarkdownReporter(input_config)
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
        testee = MarkdownReporter(input_config)
        await testee.run_report([input_scan_result])
        output = load_text(input_report_location)
        # Then
        assert testee.config == expected_config
        snapshot.snapshot_dir = get_snapshot_directory()
        snapshot.assert_match(output, "plugins_reporters/markdown-output.md")
