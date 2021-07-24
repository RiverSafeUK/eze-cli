# pylint: disable=missing-module-docstring,missing-class-docstring

import os
import shutil
import tempfile

import pytest

from eze.plugins.reporters.bom import BomReporter
from tests.plugins.reporters.reporter_helper import ReporterMetaTestBase


class TestBomReporter(ReporterMetaTestBase):
    ReporterMetaClass = BomReporter
    SNAPSHOT_PREFIX = "bom"

    def setup_method(self):
        eze_temp_folder = os.path.join(tempfile.gettempdir(), ".eze-temp")
        shutil.rmtree(eze_temp_folder, ignore_errors=True)
        self.mock_pass_fail = ""

    def mock_fail_report(self, text):
        self.mock_pass_fail += text

    def test_check_installed__sanity(self):
        # When
        expected_output = "1.7.0"
        output = BomReporter.check_installed()
        # Then
        assert isinstance(output, str)
        assert len(output) > 0

    def test_creation__no_config(self):
        # Given
        expected_config = {
            "REPORT_FILE": "eze_bom.json",
        }
        # When
        testee = BomReporter()
        # Then
        assert testee.config == expected_config

    def test_creation__simple_config_parsing(self):
        # Given
        input_config = {
            "REPORT_FILE": "eze_bom_special.json",
        }
        expected_config = {
            "REPORT_FILE": "eze_bom_special.json",
        }
        # When
        testee = BomReporter(input_config)
        # Then
        assert testee.config == expected_config

    @pytest.mark.skip(reason="Mocking of report files not implemented")
    def test_run_report(self, monkeypatch):
        pass
