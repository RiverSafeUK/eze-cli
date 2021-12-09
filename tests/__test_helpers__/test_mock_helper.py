# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring,line-too-long,invalid-name
import sys

from tests.__test_helpers__.mock_helper import (
    DummyFailureTool,
    DummySuccessTool,
    DummyReporter,
    unmock_print,
    unmock_print_stderr,
    mock_print_stderr,
    mock_print,
)
from tests.plugins.reporters.reporter_helper import ReporterMetaTestBase
from tests.plugins.tools.tool_helper import ToolMetaTestBase


def teardown_function(function):
    """Teardown function"""
    unmock_print()
    unmock_print_stderr()


class TestDummyFailureTool(ToolMetaTestBase):
    ToolMetaClass = DummyFailureTool
    SNAPSHOT_PREFIX = "dummy-failure-tool"


class TestDummySuccessTool(ToolMetaTestBase):
    ToolMetaClass = DummySuccessTool
    SNAPSHOT_PREFIX = "dummy-success-tool"


class TestDummyReporter(ReporterMetaTestBase):
    ReporterMetaClass = DummyReporter
    SNAPSHOT_PREFIX = "dummy-reporter"


def test_mock_print():
    """Test log_error output to stderr"""

    # Given
    mocked_print_output = mock_print()
    expected_output = "123\n"

    # When
    print("123")

    # Then
    output = mocked_print_output.getvalue()
    assert output == expected_output


def test_mock_print_stderr():
    """Test log_error output to stderr"""

    # Given
    mocked_print_output = mock_print_stderr()
    expected_output = "123\n"

    # When
    print("123", file=sys.stderr)

    # Then
    output = mocked_print_output.getvalue()
    assert output == expected_output
