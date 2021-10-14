# pylint: disable=missing-module-docstring,missing-class-docstring

import os
import pathlib
import shutil
import tempfile

import pytest

from eze.core.tool import ScanResult
from eze.plugins.reporters.sarif import SarifReporter
from tests.plugins.reporters.reporter_helper import ReporterMetaTestBase


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
        expected_config = {"REPORT_FILE": "eze_report.sarif"}
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
