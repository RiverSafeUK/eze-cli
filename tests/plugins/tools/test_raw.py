# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long

import pytest
from click import ClickException

from eze import __version__
from eze.plugins.tools.raw import RawTool
from eze.utils.io.file import load_json
from eze.utils.error import EzeConfigError
from tests.__fixtures__.fixture_helper import (
    convert_to_std_object,
    get_path_fixture,
)
from tests.plugins.tools.tool_helper import ToolMetaTestBase


class TestRawTool(ToolMetaTestBase):
    ToolMetaClass = RawTool
    SNAPSHOT_PREFIX = "raw"

    def test_creation__no_config_with_custom_error_message(self):
        # Given
        expected_error_message = """required param 'REPORT_FILE' missing from configuration
Eze report file to ingest
normally REPORT_FILE: eze_report.json"""
        # When
        with pytest.raises(EzeConfigError) as raised_error:
            RawTool()
        # Then
        assert raised_error.value.message == expected_error_message

    def test_creation__with_config(self):
        # Given
        input_config = {
            "REPORT_FILE": "some-eze-report.json",
        }
        expected_config = {
            "REPORT_FILE": "some-eze-report.json",
            #
            "ADDITIONAL_ARGUMENTS": "",
            "IGNORED_FILES": None,
            "EXCLUDE": [],
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = RawTool(input_config)
        # Then
        assert testee.config == expected_config

    def test_check_installed__success(self):
        # When
        expected_output = __version__
        output = RawTool.check_installed()
        # Then
        assert output == expected_output

    @pytest.mark.asyncio
    async def test_run_scan__snapshot(self):
        # Given
        input_report = str(get_path_fixture("__fixtures__/plugins_tools/raw-raw-eze_sample_report_json.json"))
        input_config = {"REPORT_FILE": input_report}
        expected_scan_result = load_json(input_report)
        testee = RawTool(input_config)
        # When
        output_scan_result = await testee.run_scan()
        # Then
        assert convert_to_std_object(output_scan_result) == expected_scan_result[0]

    @pytest.mark.asyncio
    async def test_run_scan__report_missing_snapshot(self):
        # Given
        input_config = {
            "REPORT_FILE": "non-existant-eze-report.json",
        }
        expected_error_message = "Eze Raw tool can not find 'REPORT_FILE' non-existant-eze-report.json"
        # When
        with pytest.raises(ClickException) as raised_error:
            testee = RawTool(input_config)
            await testee.run_scan()
        # Then
        assert raised_error.value.message == expected_error_message
