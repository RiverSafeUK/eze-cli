# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long

import os
import pathlib
import shutil
import tempfile
from unittest import mock
from botocore.exceptions import ClientError
from click.testing import CliRunner
from eze.utils.error import EzeConfigError

import pytest

from eze.core.tool import ScanResult
from eze.plugins.reporters.json_s3 import JsonS3Reporter
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
        expected_error = "required param 'OBJECT_KEY' missing from configuration"
        # When
        try:
            testee = JsonS3Reporter()
        except EzeConfigError as error:
            raised_error = error
        # Then
        assert expected_error in str(raised_error)

    def test_creation__simple_config_parsing(self):
        # Given
        input_config = {
            "OBJECT_KEY": "dummy_object",
            "BUCKET_NAME": "dummy_bucket",
            "AWS_ACCESS_KEY": "",
            "AWS_SECRET_KEY": "",
        }
        expected_config = {
            "OBJECT_KEY": "dummy_object",
            "BUCKET_NAME": "dummy_bucket",
            "AWS_ACCESS_KEY": "",
            "AWS_SECRET_KEY": "",
        }
        # When
        testee = JsonS3Reporter(input_config)
        # Then
        assert testee.config == expected_config

    @pytest.mark.asyncio
    @mock.patch("boto3.client", mock.MagicMock(return_value=FakeBoto3Client(error=FakeClientError())))
    @mock.patch("click.echo")
    async def test_run_report__snapshot_client_error(self, click_echo):
        # Given
        input_config = {
            "OBJECT_KEY": "dummy_object",
            "BUCKET_NAME": "dummy_bucket",
            "AWS_ACCESS_KEY": "awsaccess",
            "AWS_SECRET_KEY": "awssecret",
        }

        scan_result_fixture = load_json_fixture("__fixtures__/plugins_reporters/eze_sample_report_json.json")
        input_scan_result = ScanResult(scan_result_fixture[0])

        # When
        testee = JsonS3Reporter(input_config)
        await testee.run_report([input_scan_result])
        # Then
        click_echo.assert_called_with("    Error trying to upload in S3: ", err=True)

    @pytest.mark.asyncio
    @mock.patch("click.echo")
    async def test_run_report__no_credentials(self, click_echo):
        # Given
        input_config = {
            "OBJECT_KEY": "dummy_object",
            "BUCKET_NAME": "dummy_bucket",
            "AWS_ACCESS_KEY": "",
            "AWS_SECRET_KEY": "",
        }
        scan_result_fixture = load_json_fixture("__fixtures__/plugins_reporters/eze_sample_report_json.json")
        input_scan_result = ScanResult(scan_result_fixture[0])

        # When
        testee = JsonS3Reporter(input_config)
        await testee.run_report([input_scan_result])
        # Then
        click_echo.assert_called_with("    No aws credentials provided to upload file into S3 bucket")

    @pytest.mark.asyncio
    @mock.patch("boto3.client", mock.MagicMock(return_value=FakeBoto3Client()))
    @mock.patch("click.echo")
    async def test_run_report__ok(self, click_echo, snapshot):
        # Given
        input_config = {
            "OBJECT_KEY": "dummy_object",
            "BUCKET_NAME": "dummy_bucket",
            "AWS_ACCESS_KEY": "awsaccess",
            "AWS_SECRET_KEY": "awssecret",
        }

        scan_result_fixture = load_json_fixture("__fixtures__/plugins_reporters/eze_sample_report_json.json")
        input_scan_result = ScanResult(scan_result_fixture[0])
        expected_config = {
            "OBJECT_KEY": "dummy_object",
            "BUCKET_NAME": "dummy_bucket",
            "AWS_ACCESS_KEY": "awsaccess",
            "AWS_SECRET_KEY": "awssecret",
        }
        # When
        testee = JsonS3Reporter(input_config)
        await testee.run_report([input_scan_result])
        # Then
        assert testee.config == expected_config

        # WARNING: this is a snapshot test, any changes to format will edit this and the snapshot will need to be updated
        click_echo.assert_called_with("    Json Report file was uploaded successfully")
