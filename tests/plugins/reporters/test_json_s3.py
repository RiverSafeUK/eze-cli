# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long

import os
import pathlib
import shutil
import tempfile
from unittest import mock
from botocore.exceptions import ClientError
from click.testing import CliRunner

import pytest

from eze.core.tool import ScanResult
from eze.plugins.reporters.json_s3 import JsonS3Reporter
from eze.utils.io import load_json
from tests.__fixtures__.fixture_helper import load_json_fixture
from tests.plugins.reporters.reporter_helper import ReporterMetaTestBase


class FakeClientError(ClientError):
    def __init__(self):
        pass


class FakeBoto3Client:
    def __init__(self, error=None) -> None:
        self.error = error

    def put_object(self, Body, Bucket, Key):
        if self.error:
            raise self.error


class TestJsonS3Reporter(ReporterMetaTestBase):
    ReporterMetaClass = JsonS3Reporter
    SNAPSHOT_PREFIX = "jsons3"

    def setup_method(self):
        eze_temp_folder = os.path.join(tempfile.gettempdir(), ".eze-temp")
        shutil.rmtree(eze_temp_folder, ignore_errors=True)

    def test_check_installed__sanity(self):
        # When
        output = JsonS3Reporter.check_installed()
        # Then
        assert isinstance(output, str)
        assert len(output) > 0

    def test_creation__no_config(self):
        # Given
        expected_config = {"REPORT_FILE": "eze_report.json", "AWS_ACCESS_KEY": "", "AWS_SECRET_KEY": ""}
        # When
        testee = JsonS3Reporter()
        # Then
        assert testee.config == expected_config

    def test_creation__simple_config_parsing(self):
        # Given
        input_config = {"REPORT_FILE": "helloworld.json", "AWS_ACCESS_KEY": "", "AWS_SECRET_KEY": ""}
        expected_config = {"REPORT_FILE": "helloworld.json", "AWS_ACCESS_KEY": "", "AWS_SECRET_KEY": ""}
        # When
        testee = JsonS3Reporter(input_config)
        # Then
        assert testee.config == expected_config

    @pytest.mark.asyncio
    @mock.patch("boto3.client", mock.MagicMock(return_value=FakeBoto3Client(error=FakeClientError())))
    async def test_run_report__snapshot_client_error(self, snapshot):
        # Given
        input_report_location = pathlib.Path(tempfile.gettempdir()) / ".eze-temp" / "tmp-local-testfile"
        input_config = {
            "REPORT_FILE": str(input_report_location),
            "AWS_ACCESS_KEY": "awsaccess",
            "AWS_SECRET_KEY": "awssecret",
        }

        scan_result_fixture = load_json_fixture("__fixtures__/plugins_reporters/eze_sample_report_json.json")
        input_scan_result = ScanResult(scan_result_fixture[0])
        expected_scan_result_fixture = load_json_fixture("__fixtures__/plugins_reporters/eze_sample_report_json.json")
        expected_json = [expected_scan_result_fixture[0]]
        expected_config = {
            "REPORT_FILE": str(input_report_location),
            "AWS_ACCESS_KEY": "awsaccess",
            "AWS_SECRET_KEY": "awssecret",
        }
        # When
        testee = JsonS3Reporter(input_config)
        await testee.run_report([input_scan_result])
        output = load_json(input_report_location)
        # Then
        assert testee.config == expected_config

        # WARNING: this is a snapshot test, any changes to format will edit this and the snapshot will need to be updated
        assert output == expected_json

    @pytest.mark.asyncio
    async def test_run_report__no_credentials(self, snapshot):
        # Given
        input_report_location = pathlib.Path(tempfile.gettempdir()) / ".eze-temp" / "tmp-local-testfile"
        input_config = {
            "REPORT_FILE": str(input_report_location),
            "AWS_ACCESS_KEY": "",
            "AWS_SECRET_KEY": "",
        }

        scan_result_fixture = load_json_fixture("__fixtures__/plugins_reporters/eze_sample_report_json.json")
        input_scan_result = ScanResult(scan_result_fixture[0])
        expected_scan_result_fixture = load_json_fixture("__fixtures__/plugins_reporters/eze_sample_report_json.json")
        expected_json = [expected_scan_result_fixture[0]]
        expected_config = {"REPORT_FILE": str(input_report_location), "AWS_ACCESS_KEY": "", "AWS_SECRET_KEY": ""}
        # When
        testee = JsonS3Reporter(input_config)
        await testee.run_report([input_scan_result])
        output = load_json(input_report_location)
        # Then
        assert testee.config == expected_config

        # WARNING: this is a snapshot test, any changes to format will edit this and the snapshot will need to be updated
        assert output == expected_json
