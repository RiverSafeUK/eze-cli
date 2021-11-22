# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long
import pytest
from click import ClickException

from eze.core.config import EzeConfig
from eze.core.reporter import ReporterManager
from tests.__test_helpers__.mock_helper import get_dummy_plugin, DummyReporter, mock_print, unmock_print


class TestReport:
    @pytest.mark.asyncio
    async def test_create_report_basic(self):
        # Given
        mocked_print_output = mock_print()
        expected_output = """DummyReporter received 0 scans
"""
        input_scan_results = []
        testee = DummyReporter()
        # When
        await testee.run_report(input_scan_results)
        # Then
        unmock_print()
        output = mocked_print_output.getvalue()
        assert output == expected_output


class TestReporterManager:
    def setup_method(self):
        """Clean up ReporterManager"""
        ReporterManager.reset_instance()
        EzeConfig.reset_instance()
        EzeConfig.set_instance([])

    def teardown_module(self):
        """teardown any state that was previously setup with a setup_module
        method.
        """
        ReporterManager.reset_instance()
        EzeConfig.reset_instance()
        EzeConfig.set_instance([])

    def test_get_reporter__success(self):
        # Given
        testee = ReporterManager({"dummy-plugin": get_dummy_plugin()})
        # When
        output = testee.get_reporter("testee-reporter")
        # Then
        assert isinstance(output, DummyReporter)

    def test_get_reporter__failure_invalid_reporter(self):
        # Given
        expected_error_message = """[non-existant-reporter] The ./ezerc config references unknown reporter plugin 'non-existant-reporter', run 'eze reporters list' to see available reporters"""
        testee = ReporterManager({"dummy-plugin": get_dummy_plugin()})
        # When
        with pytest.raises(ClickException) as thrown_exception:
            testee.get_reporter("non-existant-reporter")
        # Then
        assert thrown_exception.value.message == expected_error_message
