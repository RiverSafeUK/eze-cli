# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long

import os
import shutil
import tempfile
from unittest import mock

import pytest

from eze.plugins.reporters.bom_formatted import BomFormattedReporter
from eze.utils.io import create_tempfile_path
from tests.plugins.reporters.reporter_helper import ReporterMetaTestBase


class TestBomFormattedReporter(ReporterMetaTestBase):
    ReporterMetaClass = BomFormattedReporter
    SNAPSHOT_PREFIX = "bom_formatted"

    def setup_method(self):
        eze_temp_folder = os.path.join(tempfile.gettempdir(), ".eze-temp")
        shutil.rmtree(eze_temp_folder, ignore_errors=True)
        self.mock_pass_fail = ""

    def mock_fail_report(self, text):
        self.mock_pass_fail += text

    @mock.patch("eze.plugins.reporters.bom_formatted.extract_cmd_version", mock.MagicMock(return_value="1.7.0"))
    def test_check_installed__success(self):
        # When
        expected_output = "1.7.0"
        output = BomFormattedReporter.check_installed()
        # Then
        assert output == expected_output

    @mock.patch("eze.plugins.reporters.bom_formatted.extract_cmd_version", mock.MagicMock(return_value=False))
    def test_check_installed__failure_unavailable(self):
        # When
        expected_output = False
        output = BomFormattedReporter.check_installed()
        # Then
        assert output == expected_output

    def test_creation__no_config(self):
        # Given
        expected_config = {
            "INTERMEDIATE_FILE": create_tempfile_path("tmp-eze_bom.json"),
            "OUTPUT_FORMAT": "json",
            "REPORT_FILE": "eze_bom.json",
        }
        # When
        testee = BomFormattedReporter()
        # Then
        assert testee.config == expected_config

    def test_creation__simple_config_parsing(self):
        # Given
        input_config = {
            "INTERMEDIATE_FILE": "tmp-eze_cyclonedx_bom.json",
            "OUTPUT_FORMAT": "spdxtag",
            "REPORT_FILE": "eze_bom.spdx",
        }
        expected_config = {
            "INTERMEDIATE_FILE": "tmp-eze_cyclonedx_bom.json",
            "OUTPUT_FORMAT": "spdxtag",
            "REPORT_FILE": "eze_bom.spdx",
        }
        # When
        testee = BomFormattedReporter(input_config)
        # Then
        assert testee.config == expected_config

    @pytest.mark.skip(reason="Mocking of report files not implemented")
    def test_run_report(self, monkeypatch):
        pass
