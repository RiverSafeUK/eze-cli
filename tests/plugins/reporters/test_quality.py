# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long

import os
import shutil
import tempfile

import pytest

from eze.core.tool import ScanResult
from eze.plugins.reporters.quality import QualityReporter
from tests.plugins.reporters.reporter_helper import ReporterMetaTestBase


class TestQualityReporter(ReporterMetaTestBase):
    ReporterMetaClass = QualityReporter
    SNAPSHOT_PREFIX = "quality"

    def setup_method(self):
        eze_temp_folder = os.path.join(tempfile.gettempdir(), ".eze-temp")
        shutil.rmtree(eze_temp_folder, ignore_errors=True)
        self.mock_pass_fail = ""

    def mock_fail_report(self, text):
        self.mock_pass_fail += text

    def test_check_installed__sanity(self):
        # When
        output = QualityReporter.check_installed()
        # Then
        assert isinstance(output, str)
        assert len(output) > 0

    def test_creation__no_config(self):
        # Given
        expected_config = {
            "VULNERABILITY_COUNT_THRESHOLD": 0,
            "VULNERABILITY_CRITICAL_SEVERITY_LIMIT": None,
            "VULNERABILITY_HIGH_SEVERITY_LIMIT": None,
            "VULNERABILITY_LOW_SEVERITY_LIMIT": None,
            "VULNERABILITY_MEDIUM_SEVERITY_LIMIT": None,
            "VULNERABILITY_NA_SEVERITY_LIMIT": None,
            "VULNERABILITY_NONE_SEVERITY_LIMIT": None,
            "VULNERABILITY_SEVERITY_THRESHOLD": "medium",
        }
        # When
        testee = QualityReporter()
        # Then
        assert testee.config == expected_config

    def test_creation__simple_config_parsing(self):
        # Given
        input_config = {
            "VULNERABILITY_COUNT_THRESHOLD": 6,
            "VULNERABILITY_CRITICAL_SEVERITY_LIMIT": 9,
            "VULNERABILITY_HIGH_SEVERITY_LIMIT": 8,
            "VULNERABILITY_LOW_SEVERITY_LIMIT": 7,
            "VULNERABILITY_MEDIUM_SEVERITY_LIMIT": 6,
            "VULNERABILITY_NA_SEVERITY_LIMIT": 5,
            "VULNERABILITY_NONE_SEVERITY_LIMIT": 4,
            "VULNERABILITY_SEVERITY_THRESHOLD": "medium",
        }
        expected_config = {
            "VULNERABILITY_COUNT_THRESHOLD": 6,
            "VULNERABILITY_CRITICAL_SEVERITY_LIMIT": 9,
            "VULNERABILITY_HIGH_SEVERITY_LIMIT": 8,
            "VULNERABILITY_LOW_SEVERITY_LIMIT": 7,
            "VULNERABILITY_MEDIUM_SEVERITY_LIMIT": 6,
            "VULNERABILITY_NA_SEVERITY_LIMIT": 5,
            "VULNERABILITY_NONE_SEVERITY_LIMIT": 4,
            "VULNERABILITY_SEVERITY_THRESHOLD": "medium",
        }
        # When
        testee = QualityReporter(input_config)
        # Then
        assert testee.config == expected_config

    @pytest.mark.asyncio
    async def test_run_report__pass(self, monkeypatch):
        # Given
        expected_error_message = ""
        input_config = {}
        input_scan_result = ScanResult(
            {
                "summary": {
                    "ignored": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0, "na": 0},
                    "totals": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0, "na": 0},
                }
            }
        )

        # When
        testee = QualityReporter(input_config)

        # hijack print command to test output
        monkeypatch.setattr(testee, "fail_report", self.mock_fail_report)

        await testee.run_report([input_scan_result])
        output_error_message = self.mock_pass_fail

        # Then
        assert output_error_message == expected_error_message

    @pytest.mark.asyncio
    async def test_run_report__failure(self, monkeypatch):
        # Given
        expected_error_message = "5 medium+ vulnerabilities exceeded threshold 0 medium+"

        input_config = {}

        input_scan_result = ScanResult(
            {
                "summary": {
                    "ignored": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0, "na": 0},
                    "totals": {"total": 9, "critical": 1, "high": 2, "medium": 2, "low": 2, "none": 2, "na": 0},
                }
            }
        )

        # When
        testee = QualityReporter(input_config)

        # hijack print command to test output
        monkeypatch.setattr(testee, "fail_report", self.mock_fail_report)

        await testee.run_report([input_scan_result])
        output_error_message = self.mock_pass_fail

        # Then
        assert output_error_message == expected_error_message

    @pytest.mark.asyncio
    async def test_run_report__failure_explicit_config(self, monkeypatch):
        # Given
        expected_error_message = "3 high+ vulnerabilities exceeded threshold 2 high+"

        input_config = {"VULNERABILITY_COUNT_THRESHOLD": 2, "VULNERABILITY_SEVERITY_THRESHOLD": "high"}

        input_scan_result = ScanResult(
            {
                "summary": {
                    "ignored": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0, "na": 0},
                    "totals": {"total": 5, "critical": 1, "high": 2, "medium": 2, "low": 0, "none": 0, "na": 0},
                }
            }
        )

        # When
        testee = QualityReporter(input_config)

        # hijack print command to test output
        monkeypatch.setattr(testee, "fail_report", self.mock_fail_report)

        await testee.run_report([input_scan_result])
        output_error_message = self.mock_pass_fail

        # Then
        assert output_error_message == expected_error_message

    @pytest.mark.asyncio
    async def test_run_report__failure_indivdual_threshold(self, monkeypatch):
        # Given
        expected_error_message = "2 medium vulnerabilities exceeded medium threshold of 1"

        input_config = {
            "VULNERABILITY_COUNT_THRESHOLD": 99,
            "VULNERABILITY_SEVERITY_THRESHOLD": "high",
            "VULNERABILITY_MEDIUM_SEVERITY_LIMIT": 1,
        }

        input_scan_result = ScanResult(
            {
                "summary": {
                    "ignored": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0, "na": 0},
                    "totals": {"total": 5, "critical": 1, "high": 2, "medium": 2, "low": 0, "none": 0, "na": 0},
                }
            }
        )

        # When
        testee = QualityReporter(input_config)

        # hijack print command to test output
        monkeypatch.setattr(testee, "fail_report", self.mock_fail_report)

        await testee.run_report([input_scan_result])
        output_error_message = self.mock_pass_fail

        # Then
        assert output_error_message == expected_error_message
