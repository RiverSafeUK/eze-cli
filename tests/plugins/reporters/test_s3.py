# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long

import os
import shutil
import tempfile
import pytest
from unittest import mock
from botocore.exceptions import ClientError
from eze.utils.error import EzeConfigError

from eze.core.tool import ScanResult
from eze.plugins.reporters.s3 import S3Reporter
from eze.utils.log import LogLevel
from tests.__test_helpers__.mock_helper import unmock_print, mock_print, mock_print_stderr
from tests.__fixtures__.fixture_helper import load_json_fixture
from tests.plugins.reporters.reporter_helper import ReporterMetaTestBase


class FakeClientError(ClientError):
    def __init__(self):
        meta = {"region_name": "eu-mock"}
        pass


class FakeBoto3Client:
    def __init__(self, error=None) -> None:
        meta = {"region_name": "eu-mock"}
        self.error = error

    def put_object(self, Body, Bucket, Key):
        if self.error:
            raise self.error

    def get_caller_identity(self):
        return {"Account": "fake-aws-account"}


class TestJsonS3Reporter(ReporterMetaTestBase):
    ReporterMetaClass = S3Reporter
    SNAPSHOT_PREFIX = "jsons3"

    def setup_method(self):
        eze_temp_folder = os.path.join(tempfile.gettempdir(), ".eze-temp")
        shutil.rmtree(eze_temp_folder, ignore_errors=True)

    def teardown_method(self):
        unmock_print()
        LogLevel.reset_instance()

    def test_check_installed__sanity(self):
        # When
        output = S3Reporter.check_installed()
        # Then
        assert isinstance(output, str)
        assert len(output) > 0

    def test_creation__no_config(self):
        # Given
        expected_error = "required param 'BUCKET_NAME' missing from configuration"
        # When
        with pytest.raises(EzeConfigError) as raised_error:
            S3Reporter()
        # Then
        assert expected_error in str(raised_error.value)

    def test_creation__simple_config_parsing(self):
        # Given
        input_config = {
            "OBJECT_KEY": "dummy_object",
            "BUCKET_NAME": "dummy_bucket",
        }
        expected_config = {
            "OBJECT_KEY": "dummy_object",
            "BUCKET_NAME": "dummy_bucket",
        }
        # When
        testee = S3Reporter(input_config)
        # Then
        assert testee.config == expected_config

    @pytest.mark.asyncio
    @mock.patch("boto3.client", mock.MagicMock(return_value=FakeBoto3Client(error=FakeClientError())))
    async def test_run_report__snapshot_client_error(self):
        # Given
        input_config = {
            "OBJECT_KEY": "dummy_object",
            "BUCKET_NAME": "dummy_bucket",
        }

        scan_result_fixture = load_json_fixture("__fixtures__/plugins_reporters/eze_sample_report_json.json")
        input_scan_result = ScanResult(scan_result_fixture[0])
        mocked_print_output = mock_print()
        mocked_print_output_stderr = mock_print_stderr()
        expected_output = ""
        expected_output_stderr = "Error trying to upload '(None:fake-aws-account)dummy_bucket:dummy_object' into S3: \n"

        # When
        testee = S3Reporter(input_config)
        await testee.run_report([input_scan_result])
        # Then
        assert mocked_print_output.getvalue() == expected_output
        assert mocked_print_output_stderr.getvalue() == expected_output_stderr

    @pytest.mark.asyncio
    @mock.patch("boto3.client", mock.MagicMock(return_value=FakeBoto3Client()))
    async def test_run_report__ok(self):
        # Given
        input_config = {
            "OBJECT_KEY": "dummy_object",
            "BUCKET_NAME": "dummy_bucket",
        }
        scan_result_fixture = load_json_fixture("__fixtures__/plugins_reporters/eze_sample_report_json.json")
        input_scan_result = ScanResult(scan_result_fixture[0])
        expected_config = {
            "OBJECT_KEY": "dummy_object",
            "BUCKET_NAME": "dummy_bucket",
        }
        mocked_print_output = mock_print()
        mocked_print_output_stderr = mock_print_stderr()
        expected_output = "Json Report file was uploaded successfully\n"
        expected_output_stderr = ""
        # When
        testee = S3Reporter(input_config)
        await testee.run_report([input_scan_result])
        # Then
        assert testee.config == expected_config
        assert mocked_print_output.getvalue() == expected_output
        assert mocked_print_output_stderr.getvalue() == expected_output_stderr
