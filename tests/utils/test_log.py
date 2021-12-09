"""Unit test for tests/utils/test_log.py"""
from eze.utils.log import log, log_debug, log_error, LogLevel
from tests.__test_helpers__.mock_helper import mock_print, unmock_print, mock_print_stderr, unmock_print_stderr


def teardown_function(function):
    """Teardown function"""
    unmock_print()
    unmock_print_stderr()
    LogLevel.reset_instance()


def test_log():
    """Test log output to stdout"""

    # Given
    mocked_print_output = mock_print()
    mocked_print_output_stderr = mock_print_stderr()
    expected_output = "Echo 123\n"
    expected_output_stderr = ""

    # When
    test_input = "Echo 123"
    log(test_input)

    # Then
    output = mocked_print_output.getvalue()
    assert output == expected_output
    output_stderr = mocked_print_output_stderr.getvalue()
    assert output_stderr == expected_output_stderr


def test_log_debug__in_debug_mode():
    """Test log_debug output to stdout in debug mode"""

    # Given
    LogLevel.set_level(LogLevel.DEBUG)
    mocked_print_output = mock_print()
    mocked_print_output_stderr = mock_print_stderr()
    expected_output = "Echo 123\n"
    expected_output_stderr = ""

    # When
    test_input = "Echo 123"
    log_debug(test_input)

    # Then
    output = mocked_print_output.getvalue()
    assert output == expected_output
    output_stderr = mocked_print_output_stderr.getvalue()
    assert output_stderr == expected_output_stderr


def test_log_debug__not_in_debug_mode():
    """Test log_debug output to stdout when its not in debug mode"""

    # Given
    mocked_print_output = mock_print()
    mocked_print_output_stderr = mock_print_stderr()
    expected_output = ""
    expected_output_stderr = ""

    # When
    test_input = "Echo 123"
    log_debug(test_input)

    # Then
    output = mocked_print_output.getvalue()
    assert output == expected_output
    output_stderr = mocked_print_output_stderr.getvalue()
    assert output_stderr == expected_output_stderr


def test_log_error():
    """Test log_error output to stderr"""

    # Given
    mocked_print_output = mock_print()
    mocked_print_output_stderr = mock_print_stderr()
    expected_output = ""
    expected_output_stderr = "Echo 123\n"

    # When
    test_input = "Echo 123"
    log_error(test_input)

    # Then
    output = mocked_print_output.getvalue()
    assert output == expected_output
    output_stderr = mocked_print_output_stderr.getvalue()
    assert output_stderr == expected_output_stderr
