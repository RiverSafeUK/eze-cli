# pylint: disable=missing-module-docstring,missing-class-docstring
import pytest
from click import ClickException

from eze.core.config import EzeConfig
from eze.core.reporter import ReporterManager
from tests.__test_helpers__.mock_helper import get_dummy_plugin, DummyReporter


class TestReport:
    @pytest.mark.asyncio
    async def test_create_report_basic(self):
        expected_output = {"title": "test report wip"}
        input_scan_results = []
        testee = DummyReporter()
        result = await testee.run_report(input_scan_results)
        assert result == expected_output


class TestReporterManager:
    def setup_method(self):
        """Clean up ReporterManager"""
        ReporterManager.reset_instance()
        EzeConfig.reset_instance()
        EzeConfig.set_instance([])

    def teardown_module(module):
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
        expected_error_message = """The ./ezerc config references unknown reporter plugin 'non-existant-reporter', run 'eze reporters list' to see available reporters"""
        testee = ReporterManager({"dummy-plugin": get_dummy_plugin()})
        # When
        with pytest.raises(ClickException) as thrown_exception:
            testee.get_reporter("non-existant-reporter")
        # Then
        assert thrown_exception.value.message == expected_error_message
