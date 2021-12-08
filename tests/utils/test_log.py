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

    # When
    test_input = "Echo 123"
    log(test_input)

    # Then
    output = mocked_print_output.getvalue()
    expected_output = "Echo 123\n"
    assert output == expected_output


def test_log_does_print_to_stderr():
    """Test log output to stderr"""

    # Given
    mocked_print_output_stderr = mock_print_stderr()

    # When
    test_input = "Echo 123"
    log(test_input)

    # Then
    output_stderr = mocked_print_output_stderr.getvalue()
    expected_output_stderr = ""
    assert output_stderr == expected_output_stderr


# Not sure how to run test in --debug mode to get it to print to stdout
def test_log_debug__in_debug_mode():
    """Test log_debug output to stdout in debug mode"""

    # Given
    LogLevel.set_level(LogLevel.DEBUG)
    mocked_print_output = mock_print()

    # When
    test_input = "Echo 123"
    log_debug(test_input)

    # Then
    output = mocked_print_output.getvalue()
    expected_output = "Echo 123\n"
    assert output == expected_output


def test_log_debug_not_in_debug_mode():
    """Test log_debug output to stdout when its not in debug mode"""

    # Given
    mocked_print_output = mock_print()

    # When
    test_input = "Echo 123"
    log_debug(test_input)

    # Then
    output = mocked_print_output.getvalue()
    expected_output = ""
    assert output == expected_output


def test_log_error():
    """Test log_error output to stderr"""

    # Given
    mocked_print_output_stderr = mock_print_stderr()

    # When
    test_input = "Echo 123"
    log_error(test_input)

    # Then
    output_stderr = mocked_print_output_stderr.getvalue()
    expected_output_stderr = "Echo 123\n"
    assert output_stderr == expected_output_stderr


def test_log_error_does_not_print_to_stdout():
    """Test log_error output to stdout"""

    # Given
    mocked_print_output_stdout = mock_print()

    # When
    test_input = "Echo 123"
    log_error(test_input)

    # Then
    output_stdout = mocked_print_output_stdout.getvalue()
    expected_output_stdout = ""
    assert output_stdout == expected_output_stdout
